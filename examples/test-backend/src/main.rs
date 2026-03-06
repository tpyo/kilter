use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use opentelemetry::propagation::Extractor;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

struct HeaderExtractor<'a>(&'a hyper::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0
            .keys()
            .map(hyper::header::HeaderName::as_str)
            .collect()
    }
}

async fn handle(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if path == "/healthz" {
        return Ok(Response::new(Full::new(Bytes::from("OK"))));
    }

    // Extract parent trace context and create a span
    let parent_cx = opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(req.headers()))
    });

    let span = tracing::info_span!(
        "handle",
        http.method = %method,
        http.target = %path,
        http.status_code = tracing::field::Empty,
    );
    let _ = span.set_parent(parent_cx);
    let _guard = span.enter();

    // Collect headers
    let mut header_lines = String::new();
    header_lines.push_str("Request Headers:\n");
    header_lines.push_str(&"-".repeat(50));
    header_lines.push('\n');

    for (name, value) in req.headers() {
        let line = format!("{}: {}\n", name, value.to_str().unwrap_or("<binary>"));
        header_lines.push_str(&line);
    }

    header_lines.push_str(&"-".repeat(50));
    header_lines.push('\n');

    span.record("http.status_code", 200u16);

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(header_lines)))
}

fn init_tracing() -> opentelemetry_sdk::trace::SdkTracerProvider {
    let endpoint =
        std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").unwrap_or("http://alloy:4317".to_string());

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
        .expect("Failed to create OTLP span exporter");

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name("test-backend")
                .build(),
        )
        .build();

    let tracer = provider.tracer("test-backend");

    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .with(otel_layer)
        .init();

    provider
}

#[tokio::main]
async fn main() {
    let _provider = init_tracing();

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    let listener = TcpListener::bind(addr).await.expect("failed to bind");
    tracing::info!("test-backend listening on {addr}");

    loop {
        let (stream, _) = listener.accept().await.expect("failed to accept");
        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service_fn(handle))
                .await
            {
                tracing::error!("connection error: {e}");
            }
        });
    }
}

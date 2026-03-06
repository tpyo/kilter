use crate::config::{Config, LogFormat, OtlpProtocol};
use anyhow::{Context, Result};
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::Subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

pub struct TracingGuard {
    _provider: Option<SdkTracerProvider>,
    // Dedicated runtime for the tonic gRPC transport's background connection task
    _runtime: Option<tokio::runtime::Runtime>,
}

fn build_exporter(
    protocol: OtlpProtocol,
    endpoint: &str,
) -> Result<opentelemetry_otlp::SpanExporter> {
    match protocol {
        OtlpProtocol::Grpc => opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .context("failed to create OTLP gRPC span exporter"),
        OtlpProtocol::Http => opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .build()
            .context("failed to create OTLP HTTP span exporter"),
    }
}

fn build_fmt_layer<S>(format: LogFormat) -> Box<dyn Layer<S> + Send + Sync>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    match format {
        LogFormat::Default => Box::new(tracing_subscriber::fmt::layer()),
        LogFormat::Logfmt => Box::new(tracing_logfmt::layer()),
        LogFormat::Json => Box::new(tracing_subscriber::fmt::layer().json()),
    }
}

pub fn init_tracing(config: &Config) -> Result<TracingGuard> {
    let env_filter = EnvFilter::from_default_env();
    let fmt_layer = build_fmt_layer(config.log_format);

    if let Some(ref endpoint) = config.telemetry.otlp_endpoint {
        // Pingora creates its own runtime later, so we provide a dedicated one here.
        let otel_runtime =
            tokio::runtime::Runtime::new().context("failed to create OTEL tokio runtime")?;
        let _guard = otel_runtime.enter();

        let exporter = build_exporter(config.telemetry.otlp_protocol, endpoint)?;

        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(
                opentelemetry_sdk::Resource::builder()
                    .with_service_name("kilter")
                    .build(),
            )
            .build();

        let tracer = provider.tracer("kilter");

        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );

        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .init();

        let protocol_label = match config.telemetry.otlp_protocol {
            OtlpProtocol::Grpc => "gRPC",
            OtlpProtocol::Http => "HTTP",
        };
        tracing::info!(
            "OpenTelemetry tracing initialised (endpoint: {}, protocol: {})",
            endpoint,
            protocol_label
        );

        Ok(TracingGuard {
            _provider: Some(provider),
            _runtime: Some(otel_runtime),
        })
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();

        Ok(TracingGuard {
            _provider: None,
            _runtime: None,
        })
    }
}

use crate::cidr::Cidr;
use crate::limiter::RateLimiter;
use crate::metrics;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::LoadBalancer;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

type BoxBody = Full<Bytes>;

/// A single CIDR block entry with an associated TTL in seconds
#[derive(Debug, Deserialize, Serialize)]
pub struct BlockEntry {
    pub cidr: Cidr,
    pub ttl: Option<u64>,
}

fn response(
    status: StatusCode,
    content_type: &str,
    body: impl Into<Bytes>,
) -> Result<Response<BoxBody>, hyper::http::Error> {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .body(Full::new(body.into()))
}

fn json_ok() -> Result<Response<BoxBody>, hyper::http::Error> {
    response(StatusCode::OK, "application/json", r#"{"ok":true}"#)
}

fn json_err(status: StatusCode, error: &str) -> Result<Response<BoxBody>, hyper::http::Error> {
    let body = format!(r#"{{"ok":false,"error":{}}}"#, serde_json::json!(error));
    response(status, "application/json", body)
}

fn handle_metrics() -> Result<Response<BoxBody>, hyper::http::Error> {
    match metrics::gather_metrics() {
        Ok(metrics_text) => response(StatusCode::OK, "text/plain; version=0.0.4", metrics_text),
        Err(e) => response(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", e),
    }
}

fn handle_healthz(lb: &LoadBalancer<RoundRobin>) -> Result<Response<BoxBody>, hyper::http::Error> {
    let all_backends = lb.backends().get_backend();
    let (_healthy, unhealthy): (Vec<_>, Vec<_>) = all_backends
        .iter()
        .partition(|backend| lb.backends().ready(backend));

    if unhealthy.is_empty() {
        response(StatusCode::OK, "text/plain", "OK")
    } else {
        response(StatusCode::SERVICE_UNAVAILABLE, "text/plain", "unavailable")
    }
}

// curl -s -X POST http://localhost:8081/api/block -H 'Content-Type: application/json' -d '[{"cidr": "192.168.1.0/24", "ttl": 3600}]'
async fn handle_block(
    req: Request<hyper::body::Incoming>,
    rate_limiter: &RateLimiter,
) -> Result<Response<BoxBody>, hyper::http::Error> {
    let body_bytes = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "bad request"),
    };
    let entries: Vec<BlockEntry> = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("invalid json: {e}")),
    };
    for entry in &entries {
        if let Err(e) = rate_limiter
            .add_to_blocklist(&entry.cidr.to_string(), entry.ttl.unwrap_or(0))
            .await
        {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
    }
    json_ok()
}

// curl -s -X POST http://localhost:8081/api/unblock -H 'Content-Type: application/json' -d '["192.168.1.0/24"]'
async fn handle_unblock(
    req: Request<hyper::body::Incoming>,
    rate_limiter: &RateLimiter,
) -> Result<Response<BoxBody>, hyper::http::Error> {
    let body_bytes = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "bad request"),
    };
    let cidrs: Vec<Cidr> = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("invalid json: {e}")),
    };
    match rate_limiter.remove_from_blocklist(&cidrs).await {
        Ok(()) => json_ok(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn handle_list(rate_limiter: &RateLimiter) -> Result<Response<BoxBody>, hyper::http::Error> {
    match rate_limiter.list_blocklist().await {
        Ok(raw_entries) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let entries: Vec<BlockEntry> = raw_entries
                .into_iter()
                .map(|(cidr, expires_at)| BlockEntry {
                    cidr,
                    ttl: (expires_at != 0).then(|| expires_at.saturating_sub(now)),
                })
                .collect();
            match serde_json::to_string(&entries) {
                Ok(json) => response(StatusCode::OK, "application/json", json),
                Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
            }
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    lb: Arc<LoadBalancer<RoundRobin>>,
    rate_limiter: Arc<RateLimiter>,
) -> Result<Response<BoxBody>, hyper::http::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => handle_metrics(),
        (&Method::GET, "/healthz") => handle_healthz(&lb),
        (&Method::POST, "/api/block") => handle_block(req, &rate_limiter).await,
        (&Method::POST, "/api/unblock") => handle_unblock(req, &rate_limiter).await,
        (&Method::GET, "/api/list") => handle_list(&rate_limiter).await,
        _ => response(StatusCode::NOT_FOUND, "text/plain", "Not Found"),
    }
}

pub async fn run_management_server(
    addr: SocketAddr,
    lb: Arc<LoadBalancer<RoundRobin>>,
    rate_limiter: Arc<RateLimiter>,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("failed to bind management server to {:?}: {}", addr, e);
            return;
        }
    };

    if let Ok(local_addr) = listener.local_addr() {
        tracing::info!("management server listening on {}", local_addr);
    }

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("failed to accept connection: {}", e);
                continue;
            }
        };

        let io = TokioIo::new(stream);
        let lb_clone = lb.clone();
        let rate_limiter_clone = rate_limiter.clone();

        tokio::spawn(async move {
            let service =
                service_fn(|req| handle_request(req, lb_clone.clone(), rate_limiter_clone.clone()));

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                tracing::debug!("connection error: {}", e);
            }
        });
    }
}

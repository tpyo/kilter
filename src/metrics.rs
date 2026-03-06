use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec, Encoder, HistogramVec,
    IntCounter, IntCounterVec, TextEncoder,
};
use std::sync::LazyLock;

/// HTTP requests total by status code, method, and path
pub static HTTP_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kilter_http_requests_total",
        "Total number of HTTP requests",
        &["status", "method", "path"]
    )
    .expect("failed to register kilter_http_requests_total metric")
});

/// HTTP requests by rate limit status
pub static RATE_LIMIT_REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kilter_rate_limit_requests_total",
        "Total number of requests by rate limit status",
        &["rule", "limited"]
    )
    .expect("failed to register kilter_rate_limit_requests_total metric")
});

/// Requests blocked by the IP blocklist
pub static BLOCKLIST_BLOCKED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "kilter_blocklist_blocked_total",
        "Total number of requests blocked by the IP blocklist"
    )
    .expect("failed to register kilter_blocklist_blocked_total metric")
});

/// Request duration histogram
pub static HTTP_REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "kilter_http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["status", "method"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 7.5, 10.0]
    )
    .expect("failed to register kilter_http_request_duration_seconds metric")
});

/// Record an HTTP request metric
pub fn record_http_request(status: u16, method: &str, path: &str) {
    let labels: [&str; 3] = [&*status.to_string(), method, path];
    HTTP_REQUESTS_TOTAL.with_label_values(&labels).inc();
}

/// Record rate limit decision
pub fn record_rate_limit(rule: &str, limited: bool) {
    RATE_LIMIT_REQUESTS
        .with_label_values(&[rule, if limited { "true" } else { "false" }])
        .inc();
}

/// Record a request blocked by the IP blocklist
pub fn record_ip_blocked() {
    BLOCKLIST_BLOCKED_TOTAL.inc();
}

/// Record request duration
pub fn record_request_duration(status: u16, method: &str, duration_secs: f64) {
    let status_str = &*status.to_string();
    HTTP_REQUEST_DURATION
        .with_label_values(&[status_str, method])
        .observe(duration_secs);
}

/// Get metrics in Prometheus text format
pub fn gather_metrics() -> Result<String, String> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|e| format!("failed to encode metrics: {e}"))?;
    String::from_utf8(buffer).map_err(|e| format!("invalid UTF-8 in metrics: {e}"))
}

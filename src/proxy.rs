use crate::cidr::CidrSet;
use crate::limiter::{RateLimitResult, RateLimiter};
use crate::matcher::CompiledRule;
use crate::metrics;
use crate::xff::{extract_xff_info, format_xff_header};

use async_trait::async_trait;
use opentelemetry::propagation::{Extractor, Injector};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora_load_balancing::{selection::RoundRobin, LoadBalancer};
use pingora_proxy::{ProxyHttp, Session};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

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

struct HeaderInjector(HashMap<String, String>);

impl Injector for HeaderInjector {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }
}

pub struct RateLimitProxy {
    pub upstream: Arc<LoadBalancer<RoundRobin>>,
    pub tls: bool,
    pub sni: String,
    pub rules: Arc<Vec<CompiledRule>>,
    pub rate_limiter: Arc<RateLimiter>,
    pub trusted_proxies: Arc<CidrSet>,
}

pub struct ProxyContext {
    pub client_ip: Option<IpAddr>,
    pub xff_chain: Vec<IpAddr>,
    pub rate_limit_rule: Option<String>,
    pub rate_limit_key: Option<String>,
    pub rate_limit_remaining: Option<i64>,
    pub rate_limit_limit: Option<i64>,
    pub rate_limited: bool,
    pub request_start_time: Instant,
    pub otel_context: opentelemetry::Context,
    pub request_span: tracing::Span,
    pub user_agent: Option<String>,
}

fn blocked_headers() -> Result<ResponseHeader> {
    let mut header = ResponseHeader::build(403, None)?;
    header.insert_header("Content-Type", "text/plain")?;
    header.insert_header("Content-Length", "0")?;
    Ok(header)
}

fn limited_headers(
    limit: i64,
    remaining: i64,
    reset_at: u64,
    retry_after: u64,
) -> Result<ResponseHeader> {
    let mut header = ResponseHeader::build(429, None)?;
    header.insert_header("X-Kilter-Limit", limit.to_string())?;
    header.insert_header("X-Kilter-Remaining", remaining.to_string())?;
    header.insert_header("X-Kilter-Reset", reset_at.to_string())?;
    header.insert_header("Retry-After", retry_after.to_string())?;
    header.insert_header("Content-Type", "text/plain")?;
    header.insert_header("Content-Length", "0")?;
    Ok(header)
}

impl RateLimitProxy {
    #[tracing::instrument(skip_all)]
    async fn apply_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<bool> {
        (ctx.client_ip, ctx.xff_chain) = extract_xff_info(session, &self.trusted_proxies);

        ctx.user_agent = session
            .req_header()
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        if let Some(client_addr) = ctx.client_ip {
            tracing::debug!("request from client: {}", client_addr);
        }

        // Check dynamic IP blocklist before evaluating rate limit rules
        if let Some(ip) = ctx.client_ip {
            if self.rate_limiter.is_ip_blocked(ip).await {
                tracing::debug!("request from blocked IP: {ip}");
                metrics::record_ip_blocked();
                let headers = blocked_headers()?;
                session
                    .write_response_header(Box::new(headers), true)
                    .await?;
                return Ok(true);
            }
        }

        // Iterate through all rules
        for rule in self.rules.iter() {
            // Check if request matches this rule
            if !rule.matches_request(session, ctx.client_ip.as_ref()) {
                continue;
            }

            // Check if request is excluded
            if rule.is_excluded(session, ctx.client_ip.as_ref()) {
                tracing::debug!("request excluded from rate limit rule: {}", rule.name);
                continue;
            }

            // Extract rate limit key
            let key = rule.extract_key(session);

            // Check rate limit using configured algorithm
            let result = self
                .rate_limiter
                .check_rate_limit(&rule.name, &key, rule.interval, rule.max, rule.algorithm)
                .await;

            if self
                .handle_rate_limit_result(session, ctx, &rule.name, &key, result)
                .await?
            {
                return Ok(true);
            }
        }

        Ok(false) // Allow request
    }

    #[tracing::instrument(skip_all, fields(rule_name, key))]
    async fn handle_rate_limit_result(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
        rule_name: &str,
        key: &str,
        result: std::result::Result<RateLimitResult, anyhow::Error>,
    ) -> Result<bool> {
        match result {
            Ok(RateLimitResult::Limited {
                limit,
                remaining,
                reset_at,
                retry_after,
            }) => {
                ctx.rate_limit_rule = Some(rule_name.to_string());
                ctx.rate_limit_key = Some(key.to_string());
                ctx.rate_limit_remaining = Some(remaining);
                ctx.rate_limit_limit = Some(limit);
                ctx.rate_limited = true;

                let headers = limited_headers(limit, remaining, reset_at, retry_after)?;
                //session.set_keepalive(Some(60));
                session
                    .write_response_header(Box::new(headers), true)
                    .await?;
                Ok(true)
            }
            Ok(RateLimitResult::Allowed {
                limit,
                remaining,
                reset_at,
            }) => {
                tracing::debug!(
                    "rate limit allowed for rule: {}, key: {}, remaining: {}, reset at: {}",
                    rule_name,
                    key,
                    remaining,
                    reset_at
                );

                ctx.rate_limit_rule = Some(rule_name.to_string());
                ctx.rate_limit_key = Some(key.to_string());
                ctx.rate_limit_remaining = Some(remaining);
                ctx.rate_limit_limit = Some(limit);
                ctx.rate_limited = false;
                Ok(false)
            }
            Ok(RateLimitResult::FailedOpen) => {
                tracing::warn!("redis unavailable, failing open for rule: {}", rule_name);
                Ok(false)
            }
            Ok(RateLimitResult::Blocked) => {
                tracing::debug!("request blocked by rate limit rule: {}", rule_name);
                let headers = blocked_headers()?;
                session.set_keepalive(Some(60));
                session
                    .write_response_header(Box::new(headers), true)
                    .await?;
                Ok(true)
            }
            Err(e) => {
                tracing::error!("rate limit check error for rule {}: {}", rule_name, e);
                Ok(false)
            }
        }
    }
}

#[async_trait]
impl ProxyHttp for RateLimitProxy {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext {
            client_ip: None,
            xff_chain: Vec::new(),
            rate_limit_rule: None,
            rate_limit_key: None,
            rate_limit_remaining: None,
            rate_limit_limit: None,
            rate_limited: false,
            request_start_time: Instant::now(),
            otel_context: opentelemetry::Context::new(),
            request_span: tracing::Span::none(),
            user_agent: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // Extract the upstream OTEL context from incoming headers. This MUST happen before
        // creating the span so that set_parent() is called before the span's first enter —
        // tracing-opentelemetry creates the OTEL span on first enter, so setting the parent
        // after that point has no effect.
        let extractor = HeaderExtractor(&session.req_header().headers);
        let parent_cx = opentelemetry::global::get_text_map_propagator(|p| p.extract(&extractor));

        let method = session.req_header().method.as_str().to_string();
        let path = session.req_header().uri.path().to_string();

        let span = tracing::info_span!(
            parent: tracing::Span::none(),
            "request_filter",
            http.method = %method,
            http.target = %path,
            http.status_code = tracing::field::Empty,
        );
        // Set parent before the span is entered for the first time.
        let _ = span.set_parent(parent_cx.clone());

        ctx.otel_context = parent_cx;
        ctx.request_span = span.clone();

        // Run all filter logic inside the span. The span is entered here for the first time,
        // after set_parent(), so the OTEL parent is correctly captured at span creation.
        self.apply_request_filter(session, ctx)
            .instrument(span)
            .await
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let _guard =
            tracing::debug_span!(parent: &ctx.request_span, "upstream_request_filter").entered();

        // Inject trace context with the proxy's span as parent
        let trace_headers = {
            let cx = opentelemetry::Context::current();
            let mut injector = HeaderInjector(HashMap::new());
            opentelemetry::global::get_text_map_propagator(|propagator| {
                propagator.inject_context(&cx, &mut injector);
            });
            injector.0
        };
        for (key, value) in trace_headers {
            upstream_request.insert_header(key, value).map_err(|e| {
                pingora::Error::because(
                    pingora::ErrorType::InternalError,
                    "failed to insert trace header",
                    e,
                )
            })?;
        }

        // Add X-Request-ID for request correlation
        if let Some(request_id) = session.req_header().headers.get("x-request-id") {
            upstream_request
                .insert_header("x-request-id", request_id)
                .map_err(|e| {
                    pingora::Error::because(
                        pingora::ErrorType::InternalError,
                        "failed to insert x-request-id header",
                        e,
                    )
                })?;
        }

        // Add client IP for upstream visibility
        if let Some(client_ip) = ctx.client_ip.as_ref() {
            upstream_request
                .insert_header("x-kilter-ip", client_ip.to_string())
                .map_err(|e| {
                    pingora::Error::because(
                        pingora::ErrorType::InternalError,
                        "failed to insert x-kilter-ip header",
                        e,
                    )
                })?;
        }

        // Add X-Forwarded-For header with the client IP and existing chain
        if !ctx.xff_chain.is_empty() {
            upstream_request
                .insert_header("x-forwarded-for", format_xff_header(&ctx.xff_chain))
                .map_err(|e| {
                    pingora::Error::because(
                        pingora::ErrorType::InternalError,
                        "failed to insert x-forwarded-for header",
                        e,
                    )
                })?;
        }

        // Add X-Forwarded-Host for upstream visibility of original host
        // Only set if not already present from a downstream proxy
        if session
            .req_header()
            .headers
            .get("x-forwarded-host")
            .is_none()
        {
            if let Some(host) = session.req_header().headers.get("host") {
                upstream_request
                    .insert_header("x-forwarded-host", host)
                    .map_err(|e| {
                        pingora::Error::because(
                            pingora::ErrorType::InternalError,
                            "failed to insert x-forwarded-host header",
                            e,
                        )
                    })?;
            }
        }

        // Add X-Forwarded-Proto for upstream visibility of original protocol
        // Only set if not already present from a downstream proxy
        if session
            .req_header()
            .headers
            .get("x-forwarded-proto")
            .is_none()
        {
            let proto = if session
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .is_some()
            {
                "https"
            } else {
                "http"
            };
            upstream_request
                .insert_header("x-forwarded-proto", proto)
                .map_err(|e| {
                    pingora::Error::because(
                        pingora::ErrorType::InternalError,
                        "failed to insert x-forwarded-proto header",
                        e,
                    )
                })?;
        }

        Ok(())
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let _guard = tracing::debug_span!(parent: &ctx.request_span, "upstream_peer").entered();

        // Use LoadBalancer to select upstream with connection pooling
        let Some(upstream) = self.upstream.select(b"", 256) else {
            return Err("no upstream available").map_err(|e| {
                pingora::Error::because(
                    pingora::ErrorType::InternalError,
                    "failed to select upstream",
                    e,
                )
            });
        };

        let peer = Box::new(HttpPeer::new(upstream, self.tls, self.sni.clone()));
        Ok(peer)
    }

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let method = session.req_header().method.as_str();
        let uri = session.req_header().uri.path();
        let query = session.req_header().uri.query().unwrap_or("");
        let request_uri = if query.is_empty() {
            uri.to_string()
        } else {
            format!("{uri}?{query}")
        };

        let client_ip = ctx
            .client_ip
            .map_or_else(|| "-".to_string(), |ip| ip.to_string());

        let status = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());

        // Record status on the OTEL span
        ctx.request_span.record("http.status_code", status);

        // Get user agent (cached from request processing to avoid repeated extraction)
        let user_agent = ctx.user_agent.as_deref().unwrap_or("-");

        // Calculate request duration
        let duration = ctx.request_start_time.elapsed();
        let duration_secs = duration.as_secs_f64();

        // Record Prometheus metrics
        metrics::record_http_request(status, method, uri);
        metrics::record_request_duration(status, method, duration_secs);

        // Record rate limit metrics if applicable
        if let Some(ref rule_name) = ctx.rate_limit_rule {
            metrics::record_rate_limit(rule_name, ctx.rate_limited);
        }

        // Log in a structured format with rate limit information
        if ctx.rate_limited {
            tracing::info!(
                client_ip = %client_ip,
                method = %method,
                request_uri = %request_uri,
                status = %status,
                user_agent = %user_agent,
                duration_ms = duration.as_millis(),
                rate_limited = %ctx.rate_limited,
                rate_limit_rule = ctx.rate_limit_rule.clone().unwrap_or_else(|| "unknown".to_string()),
                rate_limit_remaining = ?ctx.rate_limit_remaining.unwrap_or(0),
                rate_limit_limit = ?ctx.rate_limit_limit.unwrap_or(0),
                "request completed"
            );
        } else {
            tracing::info!(
                client_ip = %client_ip,
                method = %method,
                request_uri = %request_uri,
                status = %status,
                user_agent = %user_agent,
                duration_ms = duration.as_millis(),
                rate_limited = %ctx.rate_limited,
                "request completed"
            );
        }
    }
}

pub mod cidr;
mod config;
mod ip_sets;
mod limiter;
mod management;
mod matcher;
mod metrics;
mod proxy;
mod telemetry;
mod xff;

use anyhow::{Context, Result};
use cidr::CidrSet;
use config::load_config;
use ip_sets::load_external_ip_sets;
use limiter::RateLimiter;
use matcher::compile_rules;
use pingora::prelude::*;
use pingora::server::configuration::{Opt, ServerConf};
use pingora_load_balancing::prelude::RoundRobin;
use pingora_load_balancing::{health_check::HttpHealthCheck, LoadBalancer};
use pingora_proxy::http_proxy_service;
use proxy::RateLimitProxy;
use std::sync::Arc;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn resolve_trusted_proxies(
    names: &[String],
    ip_sets: &std::collections::HashMap<String, Arc<CidrSet>>,
) -> CidrSet {
    let mut trusted_proxies = CidrSet::new();
    for set_name in names {
        if let Some(cidr_set) = ip_sets.get(set_name) {
            for cidr in cidr_set.iter() {
                trusted_proxies.insert(cidr);
            }
        } else {
            tracing::warn!(
                "trusted_proxies references unknown ip_set '{}', ignoring",
                set_name
            );
        }
    }
    trusted_proxies
}

fn get_upstreams(config: &config::Config) -> Result<LoadBalancer<RoundRobin>, anyhow::Error> {
    let upstream_refs: Vec<&str> = config
        .proxy
        .upstreams
        .iter()
        .map(std::string::String::as_str)
        .collect();
    tracing::debug!("creating LoadBalancer with upstreams: {:?}", upstream_refs);
    LoadBalancer::try_from_iter(upstream_refs).context("failed to create load balancer")
}

fn main() -> Result<()> {
    let config = load_config("config.ron").context("failed to load config")?;

    // Initialise tracing
    let _tracing_guard =
        telemetry::init_tracing(&config).context("failed to initialise tracing")?;

    tracing::debug!(
        "configured {} upstream(s): {:?}",
        config.proxy.upstreams.len(),
        config.proxy.upstreams
    );

    // Determine TLS settings (for now, assuming all upstreams use same protocol)
    // You can make this more sophisticated later by parsing each upstream
    let use_tls = config.proxy.tls; // Set to true if using HTTPS upstreams
    let sni = config.proxy.upstreams[0]
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string();

    // Initialise redis client (non-blocking - will connect in background)
    let rate_limiter = Arc::new(
        RateLimiter::new(
            &config.redis.url,
            config.redis.fail_open,
            config.redis.timeout_seconds,
            config.redis.reconnect_interval_seconds,
        )
        .context("failed to create redis client")?,
    );

    // Start background connection manager (retries if redis is unavailable)
    rate_limiter.start_connection_manager();

    // Start background blocklist refresh task
    rate_limiter.start_blocklist_refresh(std::time::Duration::from_secs(
        config.redis.block_list_refresh_seconds,
    ));

    // Load external IP sets (blocking call since main is not async)
    let ip_sets = {
        let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;
        rt.block_on(load_external_ip_sets(config.ip_sets.as_ref()))
            .context("failed to load external IP sets")?
    };

    tracing::debug!("loaded {} IP sets", ip_sets.len());

    // Validate configuration
    config
        .validate(&ip_sets)
        .context("configuration validation failed")?;

    // Compile regex patterns and resolve IP sets
    let compiled_rules = Arc::new(
        compile_rules(config.limits.clone(), &ip_sets).context("failed to compile rules")?,
    );

    let trusted_proxies = Arc::new(resolve_trusted_proxies(
        &config.proxy.trusted_proxies,
        &ip_sets,
    ));

    tracing::debug!("compiled {} rate limit rules", compiled_rules.len());

    let server_conf = ServerConf {
        threads: num_cpus::get(),
        grace_period_seconds: Some(config.proxy.grace_period_seconds),
        graceful_shutdown_timeout_seconds: Some(config.proxy.graceful_shutdown_timeout_seconds),
        work_stealing: true,
        upstream_keepalive_pool_size: config.proxy.upstream_keepalive_pool_size,
        ..ServerConf::default()
    };

    let opt = Opt::default();
    let mut server = Server::new_with_opt_and_conf(opt, server_conf);
    server.bootstrap();

    // Create LoadBalancer with health checks from configured upstreams
    let mut upstreams = get_upstreams(&config).context("failed to create load balancer")?;

    if let Some(health_check) = config.proxy.health_check {
        let frequency = health_check.frequency_seconds;
        let hc = HttpHealthCheck::try_from(health_check).context("failed to build health check")?;
        upstreams.set_health_check(Box::new(hc));
        upstreams.health_check_frequency = Some(std::time::Duration::from_secs_f64(frequency));
    }

    // Create background service for health checks
    let background = background_service("health check", upstreams);
    let upstreams = background.task();
    tracing::info!(
        "initialised LoadBalancer with health checks for {} upstream(s)",
        config.proxy.upstreams.len()
    );

    let upstreams_for_management = upstreams.clone();
    let rate_limiter_for_management = rate_limiter.clone();

    let proxy = RateLimitProxy {
        upstream: upstreams,
        tls: use_tls,
        sni,
        rules: compiled_rules,
        rate_limiter: rate_limiter.clone(),
        trusted_proxies,
    };

    let mut proxy_service = http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&config.proxy.listen.to_string());

    server.add_service(background);
    server.add_service(proxy_service);

    // Start management server if enabled
    if config.management.enabled {
        std::thread::spawn(move || {
            let rt =
                tokio::runtime::Runtime::new().expect("failed to create management server runtime");
            rt.block_on(async move {
                management::run_management_server(
                    config.management.listen,
                    upstreams_for_management,
                    rate_limiter_for_management,
                )
                .await;
            });
        });
    }

    server.run_forever();
}

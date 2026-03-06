use crate::cidr::{Cidr, CidrSet};
use anyhow::{bail, Result};
use pingora::http::RequestHeader;
use pingora_load_balancing::health_check::HttpHealthCheck;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub redis: RedisConfig,
    pub management: ManagementConfig,
    pub limits: HashMap<String, LimitRule>,
    pub ip_sets: Option<HashMap<String, IpSetSource>>,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub log_format: LogFormat,
}

impl Config {
    pub fn validate(&self, ip_sets: &HashMap<String, Arc<CidrSet>>) -> Result<()> {
        if self.proxy.upstreams.is_empty() {
            bail!("at least one upstream must be configured");
        }

        let known_sets: HashSet<&str> = ip_sets.keys().map(String::as_str).collect();

        for (name, rule) in &self.limits {
            if rule.interval == 0 {
                bail!("rule '{name}': interval must be greater than 0");
            }
            if let Some(ref sets) = rule.matches.ip_sets {
                for set_name in sets {
                    if !known_sets.contains(set_name.as_str()) {
                        bail!("rule '{name}': references unknown ip_set '{set_name}'");
                    }
                }
            }
            if let Some(ref excludes) = rule.excludes {
                if let Some(ref sets) = excludes.ip_sets {
                    for set_name in sets {
                        if !known_sets.contains(set_name.as_str()) {
                            bail!("rule '{name}': excludes references unknown ip_set '{set_name}'");
                        }
                    }
                }
            }
        }

        for set_name in &self.proxy.trusted_proxies {
            if !known_sets.contains(set_name.as_str()) {
                bail!("trusted_proxies references unknown ip_set '{set_name}'");
            }
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub enum IpSetSource {
    External(Vec<IPSource>),
    Inline(Vec<Cidr>),
}

#[derive(Debug, Clone, Deserialize)]
pub enum IPSource {
    Google,
    Bing,
    OpenAISearchBot,
    OpenAIGPTBot,
    OpenAIGPTUser,
    CloudFront,
    Cloudflare,
    Fastly,
}

#[derive(Debug, Deserialize)]
pub struct ProxyConfig {
    pub upstreams: Vec<String>,
    pub tls: bool,
    pub listen: SocketAddr,
    pub grace_period_seconds: u64,
    pub graceful_shutdown_timeout_seconds: u64,
    pub upstream_keepalive_pool_size: usize,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub health_check: Option<HealthCheck>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            upstreams: vec![],
            tls: false,
            listen: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 8080),
            grace_period_seconds: 10,
            graceful_shutdown_timeout_seconds: 5,
            upstream_keepalive_pool_size: 256,
            trusted_proxies: vec![],
            health_check: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct HealthCheck {
    pub addr: String,
    /// HTTP method to use for health checks (e.g., "GET", "HEAD")
    pub method: String,
    /// URI path for health check requests (e.g., "/health")
    pub path: String,
    /// Port to use for health checks (overrides upstream port if set)
    pub port: Option<u16>,
    /// Host header value for the health check request
    pub host: Option<String>,
    /// Whether to use TLS for the health check request
    pub tls: bool,
    /// Additional headers to send with health check requests
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Number of consecutive failures before marking upstream unhealthy
    pub failure_threshold: usize,
    /// Number of consecutive successes before marking upstream healthy
    pub success_threshold: usize,
    /// Connection timeout in seconds for health check requests
    pub connection_timeout_seconds: u64,
    /// Read timeout in seconds for health check requests
    pub read_timeout_seconds: u64,
    /// Frequency in seconds to perform health checks
    pub frequency_seconds: f64,
    /// Whether to reuse TCP connections for health checks
    #[serde(default)]
    pub reuse_connection: bool,
}

impl Default for HealthCheck {
    fn default() -> Self {
        HealthCheck {
            addr: String::new(),
            method: "GET".to_string(),
            path: "/".to_string(),
            port: None,
            host: None,
            tls: false,
            headers: HashMap::new(),
            failure_threshold: 3,
            success_threshold: 1,
            connection_timeout_seconds: 1,
            read_timeout_seconds: 1,
            frequency_seconds: 5.0,
            reuse_connection: false,
        }
    }
}

impl TryFrom<HealthCheck> for HttpHealthCheck {
    type Error = anyhow::Error;

    fn try_from(val: HealthCheck) -> Result<Self> {
        let mut hc = HttpHealthCheck::new(&val.addr, val.tls);

        // Build the request header with the configured method and path
        let mut req = RequestHeader::build(val.method.as_bytes(), val.path.as_bytes(), None)?;

        // Set Host header if configured
        if let Some(host) = val.host.as_deref() {
            req.insert_header("Host", host)?;
        }

        // Add custom headers
        for (name, value) in val.headers {
            req.insert_header(name, &value)?;
        }

        hc.req = req;
        hc.consecutive_failure = val.failure_threshold;
        hc.consecutive_success = val.success_threshold;
        hc.reuse_connection = val.reuse_connection;

        hc.peer_template.options.connection_timeout =
            Some(Duration::from_secs(val.connection_timeout_seconds));
        hc.peer_template.options.read_timeout = Some(Duration::from_secs(val.read_timeout_seconds));

        if let Some(port) = val.port {
            hc.port_override = Some(port);
        }

        Ok(hc)
    }
}

#[derive(Debug, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL (e.g., `redis://localhost/1`)
    pub url: String,
    /// Whether to allow requests when Redis is unavailable (fail-open)
    pub fail_open: bool,
    /// Connection timeout for Redis operations
    pub timeout_seconds: f64,
    /// Interval between reconnection attempts
    pub reconnect_interval_seconds: u64,
    /// Interval between IP blocklist refreshes from Redis (seconds)
    pub block_list_refresh_seconds: u64,
}

impl Default for RedisConfig {
    fn default() -> Self {
        RedisConfig {
            url: "redis://127.0.0.1:6379".to_string(),
            fail_open: true,
            timeout_seconds: 0.1,
            reconnect_interval_seconds: 1,
            block_list_refresh_seconds: 2,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ManagementConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        ManagementConfig {
            enabled: true,
            listen: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 8081),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, Default)]
pub enum OtlpProtocol {
    #[default]
    Grpc,
    Http,
}

#[derive(Debug, Deserialize, Clone, Copy, Default)]
pub enum LogFormat {
    #[default]
    Default,
    Logfmt,
    Json,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct TelemetryConfig {
    pub otlp_endpoint: Option<String>,
    #[serde(default)]
    pub otlp_protocol: OtlpProtocol,
}

#[derive(Debug, Deserialize, Clone, Copy, Default)]
pub enum AlgorithmConfig {
    SlidingWindow,
    FixedWindow,
    TokenBucket,
    #[default]
    Gcra,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LimitRule {
    pub interval: u64,
    pub max: i64,
    pub keys: KeyExtraction,
    pub matches: MatchRules,
    pub excludes: Option<ExcludeRules>,
    #[serde(default)]
    pub algorithm: AlgorithmConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KeyExtraction {
    pub headers: HeaderNames,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HeaderNames {
    pub names: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MatchRules {
    pub paths: Option<PathMatch>,
    pub headers: Option<HeaderMatch>,
    pub ip_sets: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PathMatch {
    pub match_any: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HeaderMatch {
    pub match_any: Vec<HeaderPattern>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HeaderPattern {
    pub name: String,
    pub pattern: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ExcludeRules {
    pub paths: Option<PathMatch>,
    pub headers: Option<HeaderMatch>,
    pub ip_sets: Option<Vec<String>>,
}

pub fn load_config(path: &str) -> Result<Config> {
    let contents = fs::read_to_string(path)?;
    let config: Config = ron::from_str(&contents)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config(limits: HashMap<String, LimitRule>) -> Config {
        Config {
            proxy: ProxyConfig {
                upstreams: vec!["127.0.0.1:8000".to_string()],
                ..ProxyConfig::default()
            },
            redis: RedisConfig::default(),
            management: ManagementConfig {
                enabled: false,
                ..ManagementConfig::default()
            },
            limits,
            ip_sets: None,
            telemetry: TelemetryConfig::default(),
            log_format: LogFormat::default(),
        }
    }

    fn simple_rule(interval: u64, max: i64) -> LimitRule {
        LimitRule {
            interval,
            max,
            keys: KeyExtraction {
                headers: HeaderNames {
                    names: vec!["X-Forwarded-For".to_string()],
                },
            },
            matches: MatchRules {
                paths: Some(PathMatch {
                    match_any: vec!["/.*".to_string()],
                }),
                headers: None,
                ip_sets: None,
            },
            excludes: None,
            algorithm: AlgorithmConfig::default(),
        }
    }

    #[test]
    fn test_valid_config_parses() {
        let ron = r#"(
            proxy: (
                upstreams: ["127.0.0.1:8080"],
                tls: false,
                listen: "0.0.0.0:8080",
                grace_period_seconds: 10,
                graceful_shutdown_timeout_seconds: 5,
                upstream_keepalive_pool_size: 256,
            ),
            redis: (
                url: "redis://127.0.0.1:6379",
                fail_open: true,
                timeout_seconds: 0.1,
                reconnect_interval_seconds: 1,
                block_list_refresh_seconds: 5,
            ),
            management: (enabled: false, listen: "0.0.0.0:8081"),
            limits: {
                "test": (
                    interval: 60,
                    max: 100,
                    keys: (headers: (names: ["X-Forwarded-For"])),
                    matches: (
                        paths: Some((match_any: ["/.*"])),
                        headers: None,
                        ip_sets: None,
                    ),
                    excludes: None,
                ),
            },
        )"#;
        let config: Config = ron::from_str(ron).unwrap();
        assert_eq!(config.proxy.upstreams.len(), 1);
        assert_eq!(config.limits.len(), 1);
    }

    #[test]
    fn test_validate_empty_upstreams() {
        let mut config = minimal_config(HashMap::new());
        config.proxy.upstreams.clear();
        let ip_sets = HashMap::new();
        let result = config.validate(&ip_sets);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("upstream"));
    }

    #[test]
    fn test_validate_interval_zero() {
        let mut limits = HashMap::new();
        limits.insert("bad".to_string(), simple_rule(0, 100));
        let config = minimal_config(limits);
        let ip_sets = HashMap::new();
        let result = config.validate(&ip_sets);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("interval"));
    }

    #[test]
    fn test_validate_unknown_ip_set_reference() {
        let mut limits = HashMap::new();
        let mut rule = simple_rule(60, 100);
        rule.matches.ip_sets = Some(vec!["nonexistent".to_string()]);
        limits.insert("bad".to_string(), rule);
        let config = minimal_config(limits);
        let ip_sets = HashMap::new();
        let result = config.validate(&ip_sets);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonexistent"));
    }

    #[test]
    fn test_validate_unknown_trusted_proxy() {
        let mut config = minimal_config(HashMap::new());
        config.proxy.trusted_proxies = vec!["nonexistent".to_string()];
        let ip_sets = HashMap::new();
        let result = config.validate(&ip_sets);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonexistent"));
    }

    #[test]
    fn test_validate_valid_config() {
        let mut limits = HashMap::new();
        limits.insert("ok".to_string(), simple_rule(60, 100));
        let config = minimal_config(limits);
        let ip_sets = HashMap::new();
        assert!(config.validate(&ip_sets).is_ok());
    }
}

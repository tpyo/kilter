use crate::cidr::{Cidr, CidrSet};
use crate::config::{IPSource, IpSetSource};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

/// JSON response structure for IP range endpoints
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpRangeResponse {
    #[allow(dead_code)]
    creation_time: String,
    prefixes: Vec<IpPrefix>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpPrefix {
    ipv4_prefix: Option<String>,
    ipv6_prefix: Option<String>,
}

/// JSON response structure for AWS IP ranges
#[derive(Debug, Deserialize)]
struct AwsIpRangesResponse {
    prefixes: Vec<AwsIpv4Prefix>,
    #[serde(default)]
    ipv6_prefixes: Vec<AwsIpv6Prefix>,
}

#[derive(Debug, Deserialize)]
struct AwsIpv4Prefix {
    ip_prefix: String,
    service: String,
}

#[derive(Debug, Deserialize)]
struct AwsIpv6Prefix {
    ipv6_prefix: String,
    service: String,
}

impl IPSource {
    /// Returns the URL for fetching IP ranges for this source
    pub fn url(&self) -> &'static str {
        match self {
            // Crawlers
            IPSource::Google => "https://www.gstatic.com/ipranges/goog.json",
            IPSource::Bing => "https://www.bing.com/toolbox/bingbot.json",
            IPSource::OpenAISearchBot => "https://openai.com/searchbot.json",
            IPSource::OpenAIGPTBot => "https://openai.com/gptbot.json",
            IPSource::OpenAIGPTUser => "https://openai.com/chatgpt-user.json",
            // CDNs
            IPSource::CloudFront => "https://ip-ranges.amazonaws.com/ip-ranges.json",
            IPSource::Cloudflare => "https://api.cloudflare.com/client/v4/ips",
            IPSource::Fastly => "https://api.fastly.com/public-ip-list",
        }
    }
}

/// Fetches and parses IP ranges from a URL
async fn fetch_ip_ranges(url: &str) -> Result<Vec<Cidr>> {
    let response = reqwest::get(url)
        .await
        .with_context(|| format!("failed to fetch IP ranges from {url}"))?;

    let ip_range_response: IpRangeResponse = response
        .json()
        .await
        .with_context(|| format!("failed to parse JSON response from {url}"))?;

    let mut cidrs = Vec::new();
    for prefix in ip_range_response.prefixes {
        if let Some(ipv4) = prefix.ipv4_prefix {
            match ipv4.parse::<Cidr>() {
                Ok(cidr) => cidrs.push(cidr),
                Err(e) => tracing::warn!("failed to parse IPv4 CIDR '{}': {}", ipv4, e),
            }
        }
        if let Some(ipv6) = prefix.ipv6_prefix {
            match ipv6.parse::<Cidr>() {
                Ok(cidr) => cidrs.push(cidr),
                Err(e) => tracing::warn!("failed to parse IPv6 CIDR '{}': {}", ipv6, e),
            }
        }
    }

    tracing::debug!("loaded {} CIDRs from {}", cidrs.len(), url);
    Ok(cidrs)
}

/// Fetches and parses AWS `CloudFront` IP ranges from the AWS IP ranges endpoint
async fn fetch_cloudfront_ip_ranges(url: &str) -> Result<Vec<Cidr>> {
    let response = reqwest::get(url)
        .await
        .with_context(|| format!("failed to fetch CloudFront IP ranges from {url}"))?;

    let aws_response: AwsIpRangesResponse = response
        .json()
        .await
        .with_context(|| format!("failed to parse AWS IP ranges JSON from {url}"))?;

    let mut cidrs = Vec::new();

    for prefix in &aws_response.prefixes {
        if prefix.service == "CLOUDFRONT" {
            match prefix.ip_prefix.parse::<Cidr>() {
                Ok(cidr) => cidrs.push(cidr),
                Err(e) => tracing::warn!(
                    "failed to parse CloudFront IPv4 CIDR '{}': {}",
                    prefix.ip_prefix,
                    e
                ),
            }
        }
    }

    for prefix in &aws_response.ipv6_prefixes {
        if prefix.service == "CLOUDFRONT" {
            match prefix.ipv6_prefix.parse::<Cidr>() {
                Ok(cidr) => cidrs.push(cidr),
                Err(e) => tracing::warn!(
                    "failed to parse CloudFront IPv6 CIDR '{}': {}",
                    prefix.ipv6_prefix,
                    e
                ),
            }
        }
    }

    tracing::debug!("loaded {} CloudFront CIDRs from {}", cidrs.len(), url);
    Ok(cidrs)
}

/// JSON response structure for Cloudflare IP ranges
#[derive(Debug, Deserialize)]
struct CloudflareIpRangesResponse {
    result: CloudflareIpRangesResult,
}

#[derive(Debug, Deserialize)]
struct CloudflareIpRangesResult {
    ipv4_cidrs: Vec<String>,
    ipv6_cidrs: Vec<String>,
}

/// Fetches and parses Cloudflare IP ranges
async fn fetch_cloudflare_ip_ranges(url: &str) -> Result<Vec<Cidr>> {
    let response = reqwest::get(url)
        .await
        .with_context(|| format!("failed to fetch Cloudflare IP ranges from {url}"))?;

    let cf_response: CloudflareIpRangesResponse = response
        .json()
        .await
        .with_context(|| format!("failed to parse Cloudflare IP ranges JSON from {url}"))?;

    let mut cidrs = Vec::new();
    for prefix in cf_response
        .result
        .ipv4_cidrs
        .iter()
        .chain(cf_response.result.ipv6_cidrs.iter())
    {
        match prefix.parse::<Cidr>() {
            Ok(cidr) => cidrs.push(cidr),
            Err(e) => tracing::warn!("failed to parse Cloudflare CIDR '{}': {}", prefix, e),
        }
    }

    tracing::debug!("loaded {} Cloudflare CIDRs from {}", cidrs.len(), url);
    Ok(cidrs)
}

/// JSON response structure for Fastly IP ranges
#[derive(Debug, Deserialize)]
struct FastlyIpRangesResponse {
    addresses: Vec<String>,
    ipv6_addresses: Vec<String>,
}

/// Fetches and parses Fastly IP ranges
async fn fetch_fastly_ip_ranges(url: &str) -> Result<Vec<Cidr>> {
    let response = reqwest::get(url)
        .await
        .with_context(|| format!("failed to fetch Fastly IP ranges from {url}"))?;

    let fastly_response: FastlyIpRangesResponse = response
        .json()
        .await
        .with_context(|| format!("failed to parse Fastly IP ranges JSON from {url}"))?;

    let mut cidrs = Vec::new();
    for prefix in fastly_response
        .addresses
        .iter()
        .chain(fastly_response.ipv6_addresses.iter())
    {
        match prefix.parse::<Cidr>() {
            Ok(cidr) => cidrs.push(cidr),
            Err(e) => tracing::warn!("failed to parse Fastly CIDR '{}': {}", prefix, e),
        }
    }

    tracing::debug!("loaded {} Fastly CIDRs from {}", cidrs.len(), url);
    Ok(cidrs)
}

/// Fetches IP ranges for a specific `IPSource`
async fn fetch_ip_source(source: &IPSource) -> Result<Vec<Cidr>> {
    match source {
        IPSource::CloudFront => fetch_cloudfront_ip_ranges(source.url()).await,
        IPSource::Cloudflare => fetch_cloudflare_ip_ranges(source.url()).await,
        IPSource::Fastly => fetch_fastly_ip_ranges(source.url()).await,
        _ => fetch_ip_ranges(source.url()).await,
    }
}

/// Loads all external IP sets and returns a resolved map of set name to `CidrSet`
pub async fn load_external_ip_sets(
    ip_sets: Option<&HashMap<String, IpSetSource>>,
) -> Result<HashMap<String, Arc<CidrSet>>> {
    let mut resolved = HashMap::new();

    let Some(ip_sets) = ip_sets else {
        return Ok(resolved);
    };

    // Spawn all external source fetches concurrently
    let mut tasks = tokio::task::JoinSet::new();

    for (name, source) in ip_sets {
        match source {
            IpSetSource::External(sources) => {
                for ip_source in sources {
                    let name = name.clone();
                    let ip_source = ip_source.clone();
                    tasks.spawn(async move {
                        let result = fetch_ip_source(&ip_source).await;
                        (name, ip_source, result)
                    });
                }
            }
            IpSetSource::Inline(cidrs) => {
                resolved.insert(name.clone(), Arc::new(CidrSet::from_cidrs(cidrs.clone())));
            }
        }
    }

    // Collect results and group by set name
    let mut set_cidrs: HashMap<String, Vec<Cidr>> = HashMap::new();
    while let Some(task_result) = tasks.join_next().await {
        let (name, ip_source, result) = match task_result {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("IP set fetch task failed: {}", e);
                continue;
            }
        };
        match result {
            Ok(cidrs) => {
                set_cidrs.entry(name).or_default().extend(cidrs);
            }
            Err(e) => {
                tracing::error!(
                    "failed to load external IP source {:?} for set '{}': {}",
                    ip_source,
                    name,
                    e
                );
            }
        }
    }

    // Convert grouped CIDRs to CidrSets
    for (name, cidrs) in set_cidrs {
        tracing::debug!(
            "loaded external IP set '{}' with {} CIDRs",
            name,
            cidrs.len()
        );
        resolved.insert(name, Arc::new(CidrSet::from_cidrs(cidrs)));
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_fetch_google_ip_ranges() {
        let cidrs = fetch_ip_source(&IPSource::Google)
            .await
            .expect("failed to fetch Google IP ranges");
        assert!(!cidrs.is_empty(), "Google should have IP ranges");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_fetch_bing_ip_ranges() {
        let cidrs = fetch_ip_source(&IPSource::Bing)
            .await
            .expect("failed to fetch Bing IP ranges");
        assert!(!cidrs.is_empty(), "Bing should have IP ranges");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_fetch_openai_searchbot_ip_ranges() {
        let cidrs = fetch_ip_source(&IPSource::OpenAISearchBot)
            .await
            .expect("failed to fetch OpenAI SearchBot IP ranges");
        assert!(!cidrs.is_empty(), "OpenAI SearchBot should have IP ranges");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_fetch_openai_gptbot_ip_ranges() {
        let cidrs = fetch_ip_source(&IPSource::OpenAIGPTBot)
            .await
            .expect("failed to fetch OpenAI GPTBot IP ranges");
        assert!(!cidrs.is_empty(), "OpenAI GPTBot should have IP ranges");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_fetch_openai_chatgpt_user_ip_ranges() {
        let cidrs = fetch_ip_source(&IPSource::OpenAIGPTUser)
            .await
            .expect("failed to fetch OpenAI ChatGPT User IP ranges");
        assert!(
            !cidrs.is_empty(),
            "OpenAI ChatGPT User should have IP ranges"
        );
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_fetch_cloudfront_ip_ranges() {
        let cidrs = fetch_ip_source(&IPSource::CloudFront)
            .await
            .expect("failed to fetch CloudFront IP ranges");
        assert!(!cidrs.is_empty(), "CloudFront should have IP ranges");
        // CloudFront should have a substantial number of IP ranges
        assert!(cidrs.len() > 50, "CloudFront should have many IP ranges");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_fetch_cloudflare_ip_ranges() {
        let cidrs = fetch_ip_source(&IPSource::Cloudflare)
            .await
            .expect("failed to fetch Cloudflare IP ranges");
        assert!(!cidrs.is_empty(), "Cloudflare should have IP ranges");
        assert!(cidrs.len() > 10, "Cloudflare should have many IP ranges");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_fetch_fastly_ip_ranges() {
        let cidrs = fetch_ip_source(&IPSource::Fastly)
            .await
            .expect("failed to fetch Fastly IP ranges");
        assert!(!cidrs.is_empty(), "Fastly should have IP ranges");
        assert!(cidrs.len() > 10, "Fastly should have many IP ranges");
    }
}

//! X-Forwarded-For header parsing and client IP extraction

use crate::cidr::CidrSet;
use pingora_proxy::Session;
use std::net::IpAddr;

/// Check if an IP is trusted: either loopback (`127.0.0.1`/`::1`) or in the trusted proxies set
fn is_trusted(ip: IpAddr, trusted_proxies: &CidrSet) -> bool {
    ip.is_loopback() || trusted_proxies.contains(ip)
}

/// Parse X-Forwarded-For header value into a list of IPs
///
/// Invalid IP addresses in the header are silently skipped
#[must_use]
fn parse_xff(xff_value: &str) -> Vec<IpAddr> {
    xff_value
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect()
}

/// Extract client IP from an IP chain using trusted proxy rules
#[must_use]
fn extract_client_from_xff(
    xff_ips: &[IpAddr],
    direct_ip: Option<IpAddr>,
    trusted_proxies: &CidrSet,
) -> (Option<IpAddr>, Vec<IpAddr>) {
    // If direct IP is not trusted, ignore XFF entirely
    if !direct_ip.is_some_and(|ip| is_trusted(ip, trusted_proxies)) {
        let chain = direct_ip.map(|ip| vec![ip]).unwrap_or_default();
        return (direct_ip, chain);
    }

    // Empty XFF with trusted direct connection - use direct IP
    if xff_ips.is_empty() {
        let chain = direct_ip.map(|ip| vec![ip]).unwrap_or_default();
        return (direct_ip, chain);
    }

    // Find the rightmost untrusted IP, or use the first if all are trusted
    let client_pos = xff_ips
        .iter()
        .rposition(|ip| !is_trusted(*ip, trusted_proxies))
        .unwrap_or(0);

    let client_ip = xff_ips.get(client_pos).copied();

    // Build the downstream XFF chain: client IP + trusted proxies + direct IP.
    // This strips any spoofed entries to the left of the client and appends
    // the direct connection IP (as a forwarding proxy should per RFC 7239).
    let mut xff_chain = xff_ips[client_pos..].to_vec();
    if let Some(ip) = direct_ip {
        xff_chain.push(ip);
    }

    (client_ip, xff_chain)
}

/// Format an XFF chain as a header value
#[must_use]
pub fn format_xff_header(chain: &[IpAddr]) -> String {
    chain
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Extracts client IP and XFF chain from the session's X-Forwarded-For header
/// using the provided trusted proxy rules
#[must_use]
#[tracing::instrument(skip_all, level = "trace")]
pub fn extract_xff_info(
    session: &Session,
    trusted_proxies: &CidrSet,
) -> (Option<IpAddr>, Vec<IpAddr>) {
    tracing::trace!(
        "Extracting XFF info from session CIDRS: trusted_proxies={:?}",
        trusted_proxies
    );

    // Get the direct connection IP
    let direct_ip = session
        .client_addr()
        .and_then(|addr| addr.as_inet().map(std::net::SocketAddr::ip));

    // Only trust XFF header if the direct client is a trusted proxy
    let direct_is_trusted = direct_ip.is_some_and(|ip| is_trusted(ip, trusted_proxies));

    if direct_is_trusted {
        if let Some(xff) = session.req_header().headers.get("X-Forwarded-For") {
            if let Ok(xff_str) = std::str::from_utf8(xff.as_bytes()) {
                let xff_ips = parse_xff(xff_str);
                return extract_client_from_xff(&xff_ips, direct_ip, trusted_proxies);
            }
        }
    }

    // Direct client not trusted or no valid XFF - use direct IP
    let xff_chain = direct_ip.map(|ip| vec![ip]).unwrap_or_default();
    (direct_ip, xff_chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr_set_from_strs(strs: &[&str]) -> CidrSet {
        let cidrs: Vec<_> = strs.iter().map(|s| s.parse().unwrap()).collect();
        CidrSet::from_cidrs(cidrs)
    }

    #[test]
    fn test_parse_xff_single_ip() {
        let ips = parse_xff("1.2.3.4");
        assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_parse_xff_multiple_ips() {
        let ips = parse_xff("1.2.3.4, 5.6.7.8, 10.0.0.1");
        assert_eq!(
            ips,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "5.6.7.8".parse::<IpAddr>().unwrap(),
                "10.0.0.1".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_parse_xff_with_spaces() {
        let ips = parse_xff("  1.2.3.4  ,  5.6.7.8  ");
        assert_eq!(
            ips,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "5.6.7.8".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_parse_xff_invalid_ips_skipped() {
        let ips = parse_xff("not-ip, 1.2.3.4, also-not-ip, 5.6.7.8");
        assert_eq!(
            ips,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "5.6.7.8".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_parse_xff_empty() {
        let ips = parse_xff("");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_parse_xff_ipv6() {
        let ips = parse_xff("2001:db8::1, 1.2.3.4");
        assert_eq!(
            ips,
            vec![
                "2001:db8::1".parse::<IpAddr>().unwrap(),
                "1.2.3.4".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_no_xff() {
        let trusted = cidr_set_from_strs(&["10.0.0.0/8"]);
        let direct_ip = Some("1.2.3.4".parse().unwrap());

        let (client, chain) = extract_client_from_xff(&[], direct_ip, &trusted);

        assert_eq!(client, Some("1.2.3.4".parse().unwrap()));
        // Untrusted direct: chain is just the direct IP (no trusted proxy to append)
        assert_eq!(chain, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_untrusted_direct_ignores_xff() {
        let trusted = cidr_set_from_strs(&["10.0.0.0/8"]);
        let direct_ip = Some("1.2.3.4".parse().unwrap()); // Not trusted
        let xff_ips: Vec<IpAddr> = vec!["5.6.7.8".parse().unwrap(), "10.0.0.1".parse().unwrap()];

        let (client, chain) = extract_client_from_xff(&xff_ips, direct_ip, &trusted);

        assert_eq!(client, Some("1.2.3.4".parse().unwrap()));
        assert_eq!(chain, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_single_trusted_proxy() {
        let trusted = cidr_set_from_strs(&["10.0.0.0/8"]);
        let direct_ip: Option<IpAddr> = Some("10.0.0.1".parse().unwrap());
        let xff_ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];

        let (client, chain) = extract_client_from_xff(&xff_ips, direct_ip, &trusted);

        assert_eq!(client, Some("1.2.3.4".parse().unwrap()));
        assert_eq!(
            chain,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "10.0.0.1".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_multiple_trusted_proxies() {
        let trusted = cidr_set_from_strs(&["10.0.0.0/8", "172.16.0.0/12"]);
        let direct_ip: Option<IpAddr> = Some("10.0.0.1".parse().unwrap());
        let xff_ips: Vec<IpAddr> = vec![
            "1.2.3.4".parse().unwrap(),
            "172.16.0.5".parse().unwrap(),
            "10.0.0.50".parse().unwrap(),
        ];

        let (client, chain) = extract_client_from_xff(&xff_ips, direct_ip, &trusted);

        assert_eq!(client, Some("1.2.3.4".parse().unwrap()));
        assert_eq!(
            chain,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "172.16.0.5".parse::<IpAddr>().unwrap(),
                "10.0.0.50".parse::<IpAddr>().unwrap(),
                "10.0.0.1".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_untrusted_proxy_in_middle() {
        let trusted = cidr_set_from_strs(&["10.0.0.0/8"]);
        let direct_ip: Option<IpAddr> = Some("10.0.0.1".parse().unwrap());
        let xff_ips: Vec<IpAddr> = vec![
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            "10.0.0.50".parse().unwrap(),
        ];

        let (client, chain) = extract_client_from_xff(&xff_ips, direct_ip, &trusted);

        assert_eq!(client, Some("5.6.7.8".parse().unwrap()));
        assert_eq!(
            chain,
            vec![
                "5.6.7.8".parse::<IpAddr>().unwrap(),
                "10.0.0.50".parse::<IpAddr>().unwrap(),
                "10.0.0.1".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_all_proxies_trusted() {
        let trusted = cidr_set_from_strs(&["10.0.0.0/8", "172.16.0.0/12"]);
        let direct_ip: Option<IpAddr> = Some("10.0.0.1".parse().unwrap());
        let xff_ips: Vec<IpAddr> =
            vec!["172.16.0.5".parse().unwrap(), "10.0.0.50".parse().unwrap()];

        let (client, chain) = extract_client_from_xff(&xff_ips, direct_ip, &trusted);

        assert_eq!(client, Some("172.16.0.5".parse().unwrap()));
        assert_eq!(
            chain,
            vec![
                "172.16.0.5".parse::<IpAddr>().unwrap(),
                "10.0.0.50".parse::<IpAddr>().unwrap(),
                "10.0.0.1".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_spoofed_client_with_untrusted_middle() {
        let trusted = cidr_set_from_strs(&["10.0.0.0/8"]);
        let direct_ip: Option<IpAddr> = Some("10.0.0.1".parse().unwrap());
        let xff_ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap(), "10.0.0.50".parse().unwrap()];

        let (client, chain) = extract_client_from_xff(&xff_ips, direct_ip, &trusted);

        assert_eq!(client, Some("1.2.3.4".parse().unwrap()));
        assert_eq!(
            chain,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "10.0.0.50".parse::<IpAddr>().unwrap(),
                "10.0.0.1".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_empty_xff_with_trusted_direct() {
        let trusted = cidr_set_from_strs(&["10.0.0.0/8"]);
        let direct_ip: Option<IpAddr> = Some("10.0.0.1".parse().unwrap());

        let (client, chain) = extract_client_from_xff(&[], direct_ip, &trusted);

        assert_eq!(client, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(chain, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_format_xff_header_single() {
        let chain: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        assert_eq!(format_xff_header(&chain), "1.2.3.4");
    }

    #[test]
    fn test_format_xff_header_multiple() {
        let chain: Vec<IpAddr> = vec![
            "1.2.3.4".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "172.16.0.5".parse().unwrap(),
        ];
        assert_eq!(format_xff_header(&chain), "1.2.3.4, 10.0.0.1, 172.16.0.5");
    }

    #[test]
    fn test_format_xff_header_empty() {
        let chain: Vec<IpAddr> = vec![];
        assert_eq!(format_xff_header(&chain), "");
    }

    #[test]
    fn test_format_xff_header_ipv6() {
        let chain: Vec<IpAddr> = vec!["2001:db8::1".parse().unwrap(), "1.2.3.4".parse().unwrap()];
        assert_eq!(format_xff_header(&chain), "2001:db8::1, 1.2.3.4");
    }

    #[test]
    fn test_no_direct_ip() {
        let trusted = cidr_set_from_strs(&["10.0.0.0/8"]);
        let xff_ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];

        let (client, chain) = extract_client_from_xff(&xff_ips, None, &trusted);

        // No direct IP means we can't trust anything
        assert_eq!(client, None);
        assert!(chain.is_empty());
    }

    #[test]
    fn test_localhost_always_trusted() {
        let trusted = cidr_set_from_strs(&["10.0.0.0/8"]); // no loopback configured
        let direct_ip: Option<IpAddr> = Some("127.0.0.1".parse().unwrap());
        let xff_ips: Vec<IpAddr> = vec!["203.0.113.50".parse().unwrap()];

        let (client, chain) = extract_client_from_xff(&xff_ips, direct_ip, &trusted);

        assert_eq!(client, Some("203.0.113.50".parse().unwrap()));
        assert_eq!(
            chain,
            vec![
                "203.0.113.50".parse::<IpAddr>().unwrap(),
                "127.0.0.1".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_ipv6_loopback_always_trusted() {
        let trusted = cidr_set_from_strs(&["10.0.0.0/8"]);
        let direct_ip: Option<IpAddr> = Some("::1".parse().unwrap());
        let xff_ips: Vec<IpAddr> = vec!["203.0.113.50".parse().unwrap()];

        let (client, chain) = extract_client_from_xff(&xff_ips, direct_ip, &trusted);

        assert_eq!(client, Some("203.0.113.50".parse().unwrap()));
        assert_eq!(
            chain,
            vec![
                "203.0.113.50".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap(),
            ]
        );
    }
}

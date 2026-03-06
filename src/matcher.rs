use crate::cidr::CidrSet;
use crate::config::{AlgorithmConfig, LimitRule};
use crate::limiter::Algorithm;
use anyhow::Result;
use pingora_proxy::Session;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub name: String,
    pub interval: u64,
    pub max: i64,
    pub key_headers: Vec<String>,
    pub path_patterns: Vec<Regex>,
    pub header_patterns: Vec<(String, Regex)>,
    pub match_ip_sets: Vec<Arc<CidrSet>>,
    pub exclude_path_patterns: Vec<Regex>,
    pub exclude_patterns: Vec<(String, Regex)>,
    pub exclude_ip_sets: Vec<Arc<CidrSet>>,
    pub algorithm: Algorithm,
}

impl From<AlgorithmConfig> for Algorithm {
    fn from(config: AlgorithmConfig) -> Self {
        match config {
            AlgorithmConfig::SlidingWindow => Algorithm::SlidingWindow,
            AlgorithmConfig::FixedWindow => Algorithm::FixedWindow,
            AlgorithmConfig::TokenBucket => Algorithm::TokenBucket,
            AlgorithmConfig::Gcra => Algorithm::Gcra,
        }
    }
}

impl CompiledRule {
    #[tracing::instrument(skip_all, level = "debug", fields(rule = %self.name))]
    #[must_use]
    pub fn matches_request(&self, session: &Session, client_ip: Option<&IpAddr>) -> bool {
        let req_header = session.req_header();

        // Check path patterns (OR logic - match_any)
        let t_path = std::time::Instant::now();
        let path_matches = if self.path_patterns.is_empty() {
            true // No path restrictions means match all paths
        } else {
            self.path_patterns
                .iter()
                .any(|pattern| pattern.is_match(req_header.uri.path()))
        };
        tracing::debug!(rule = %self.name, elapsed_us = t_path.elapsed().as_micros(), "path pattern check");

        if !path_matches {
            return false;
        }

        // Check header patterns (OR logic - match_any)
        let t_headers = std::time::Instant::now();
        let header_matches = if self.header_patterns.is_empty() {
            true // No header restrictions means match all
        } else {
            self.header_patterns.iter().any(|(header_name, pattern)| {
                if let Some(header_value) = req_header.headers.get(header_name) {
                    if let Ok(value_str) = std::str::from_utf8(header_value.as_bytes()) {
                        return pattern.is_match(value_str);
                    }
                }
                false
            })
        };
        tracing::debug!(rule = %self.name, elapsed_us = t_headers.elapsed().as_micros(), "header pattern check");

        if !header_matches {
            return false;
        }

        // Check IP set matches - IP must be in at least one of the configured sets
        let t_ip = std::time::Instant::now();
        let ip_matches = if self.match_ip_sets.is_empty() {
            true // No IP set restrictions means match all IPs
        } else if let Some(client_ip) = client_ip {
            self.match_ip_sets
                .iter()
                .any(|set| set.contains(*client_ip))
        } else {
            false // No client IP available, can't match IP-based rules
        };
        tracing::debug!(rule = %self.name, elapsed_us = t_ip.elapsed().as_micros(), "ip set check");

        if !ip_matches {
            return false;
        }

        true
    }

    #[tracing::instrument(skip_all, level = "debug")]
    #[must_use]
    pub fn is_excluded(&self, session: &Session, client_ip: Option<&IpAddr>) -> bool {
        let req_header = session.req_header();
        let path = req_header.uri.path();

        // Check if any exclude path pattern matches (OR logic)
        if self
            .exclude_path_patterns
            .iter()
            .any(|pattern| pattern.is_match(path))
        {
            return true;
        }

        // Check if any exclude header pattern matches (OR logic)
        let header_excluded = self.exclude_patterns.iter().any(|(header_name, pattern)| {
            if let Some(header_value) = req_header.headers.get(header_name) {
                if let Ok(value_str) = std::str::from_utf8(header_value.as_bytes()) {
                    return pattern.is_match(value_str);
                }
            }
            false
        });

        if header_excluded {
            return true;
        }

        // Check if client IP is in any excluded IP set
        if !self.exclude_ip_sets.is_empty() {
            if let Some(client_ip) = client_ip {
                if self
                    .exclude_ip_sets
                    .iter()
                    .any(|set| set.contains(*client_ip))
                {
                    return true;
                }
            }
        }

        false
    }

    #[tracing::instrument(skip_all, level = "debug")]
    #[must_use]
    pub fn extract_key(&self, session: &Session) -> String {
        let req_header = session.req_header();

        if self.key_headers.is_empty() {
            return format!("{}:default", self.name);
        }

        let parts: Vec<String> = self
            .key_headers
            .iter()
            .map(|header_name| {
                req_header
                    .headers
                    .get(header_name)
                    .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                    .unwrap_or("")
                    .to_string()
            })
            .collect();

        format!("{}:{}", self.name, parts.join(":"))
    }
}

/// Resolve IP set names to Vec<Arc<CidrSet>> from pre-loaded sets
fn resolve_ip_sets(
    set_names: &[String],
    ip_sets: &HashMap<String, Arc<CidrSet>>,
) -> Vec<Arc<CidrSet>> {
    let mut resolved = Vec::new();
    for name in set_names {
        if let Some(cidr_set) = ip_sets.get(name) {
            resolved.push(Arc::clone(cidr_set));
        } else {
            tracing::warn!("IP set '{}' not found in loaded IP sets", name);
        }
    }
    resolved
}

#[allow(clippy::implicit_hasher)]
pub fn compile_rules(
    limits: HashMap<String, LimitRule>,
    ip_sets: &HashMap<String, Arc<CidrSet>>,
) -> Result<Vec<CompiledRule>> {
    let mut compiled_rules = Vec::new();

    for (name, rule) in limits {
        let mut path_patterns = Vec::new();
        if let Some(paths) = &rule.matches.paths {
            for pattern_str in &paths.match_any {
                let pattern = Regex::new(pattern_str)?;
                path_patterns.push(pattern);
            }
        }

        let mut header_patterns = Vec::new();
        if let Some(headers) = &rule.matches.headers {
            for header_pattern in &headers.match_any {
                let pattern = Regex::new(&header_pattern.pattern)?;
                header_patterns.push((header_pattern.name.clone(), pattern));
            }
        }

        // Resolve match IP sets for efficient lookups
        let match_ip_sets = rule
            .matches
            .ip_sets
            .as_ref()
            .map(|names| resolve_ip_sets(names, ip_sets))
            .unwrap_or_default();

        let mut exclude_path_patterns = Vec::new();
        let mut exclude_patterns = Vec::new();
        let mut exclude_ip_sets = Vec::new();
        if let Some(excludes) = &rule.excludes {
            if let Some(paths) = &excludes.paths {
                for pattern_str in &paths.match_any {
                    let pattern = Regex::new(pattern_str)?;
                    exclude_path_patterns.push(pattern);
                }
            }
            if let Some(headers) = &excludes.headers {
                for header_pattern in &headers.match_any {
                    let pattern = Regex::new(&header_pattern.pattern)?;
                    exclude_patterns.push((header_pattern.name.clone(), pattern));
                }
            }
            // Resolve exclude IP sets for efficient lookups
            if let Some(names) = &excludes.ip_sets {
                exclude_ip_sets = resolve_ip_sets(names, ip_sets);
            }
        }

        compiled_rules.push(CompiledRule {
            name,
            interval: rule.interval,
            max: rule.max,
            key_headers: rule.keys.headers.names.clone(),
            path_patterns,
            header_patterns,
            match_ip_sets,
            exclude_path_patterns,
            exclude_patterns,
            exclude_ip_sets,
            algorithm: rule.algorithm.into(),
        });
    }

    Ok(compiled_rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    fn simple_rule() -> LimitRule {
        LimitRule {
            interval: 60,
            max: 100,
            keys: KeyExtraction {
                headers: HeaderNames {
                    names: vec!["X-Forwarded-For".to_string()],
                },
            },
            matches: MatchRules {
                paths: Some(PathMatch {
                    match_any: vec!["/api/.*".to_string()],
                }),
                headers: None,
                ip_sets: None,
            },
            excludes: None,
            algorithm: AlgorithmConfig::default(),
        }
    }

    #[test]
    fn test_compile_basic_rule() {
        let mut limits = HashMap::new();
        limits.insert("test".to_string(), simple_rule());
        let ip_sets = HashMap::new();
        let rules = compile_rules(limits, &ip_sets).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "test");
        assert_eq!(rules[0].interval, 60);
        assert_eq!(rules[0].max, 100);
        assert_eq!(rules[0].path_patterns.len(), 1);
        assert!(rules[0].header_patterns.is_empty());
    }

    #[test]
    fn test_compile_invalid_regex() {
        let mut rule = simple_rule();
        rule.matches.paths = Some(PathMatch {
            match_any: vec!["[invalid".to_string()],
        });
        let mut limits = HashMap::new();
        limits.insert("bad".to_string(), rule);
        let ip_sets = HashMap::new();
        assert!(compile_rules(limits, &ip_sets).is_err());
    }

    #[test]
    fn test_compile_with_header_patterns() {
        let mut rule = simple_rule();
        rule.matches.headers = Some(HeaderMatch {
            match_any: vec![HeaderPattern {
                name: "User-Agent".to_string(),
                pattern: ".*bot.*".to_string(),
            }],
        });
        let mut limits = HashMap::new();
        limits.insert("test".to_string(), rule);
        let ip_sets = HashMap::new();
        let rules = compile_rules(limits, &ip_sets).unwrap();
        assert_eq!(rules[0].header_patterns.len(), 1);
        assert_eq!(rules[0].header_patterns[0].0, "User-Agent");
    }

    #[test]
    fn test_compile_with_excludes() {
        let mut rule = simple_rule();
        rule.excludes = Some(ExcludeRules {
            paths: Some(PathMatch {
                match_any: vec!["/health.*".to_string()],
            }),
            headers: Some(HeaderMatch {
                match_any: vec![HeaderPattern {
                    name: "User-Agent".to_string(),
                    pattern: ".*Googlebot.*".to_string(),
                }],
            }),
            ip_sets: None,
        });
        let mut limits = HashMap::new();
        limits.insert("test".to_string(), rule);
        let ip_sets = HashMap::new();
        let rules = compile_rules(limits, &ip_sets).unwrap();
        assert_eq!(rules[0].exclude_path_patterns.len(), 1);
        assert_eq!(rules[0].exclude_patterns.len(), 1);
    }

    #[test]
    fn test_compile_with_ip_sets() {
        use crate::cidr::CidrSet;

        let mut cidr_set = CidrSet::new();
        cidr_set.insert("10.0.0.0/8".parse().unwrap());

        let mut ip_sets = HashMap::new();
        ip_sets.insert("internal".to_string(), Arc::new(cidr_set));

        let mut rule = simple_rule();
        rule.matches.ip_sets = Some(vec!["internal".to_string()]);
        let mut limits = HashMap::new();
        limits.insert("test".to_string(), rule);
        let rules = compile_rules(limits, &ip_sets).unwrap();
        assert_eq!(rules[0].match_ip_sets.len(), 1);
    }

    #[test]
    fn test_compile_unknown_ip_set_skipped() {
        let mut rule = simple_rule();
        rule.matches.ip_sets = Some(vec!["nonexistent".to_string()]);
        let mut limits = HashMap::new();
        limits.insert("test".to_string(), rule);
        let ip_sets = HashMap::new();
        let rules = compile_rules(limits, &ip_sets).unwrap();
        assert!(rules[0].match_ip_sets.is_empty());
    }
}

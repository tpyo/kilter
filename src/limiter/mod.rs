//! Rate limiter implementation using Redis as a backend for distributed state management

mod lua;

use crate::cidr::{Cidr, CidrSet};
use crate::limiter::lua::{FIXED_WINDOW, GCRA, SLIDING_WINDOW, TOKEN_BUCKET};
use anyhow::{Context, Result};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Rate limiting algorithm to use
#[derive(Debug, Clone, Copy)]
pub enum Algorithm {
    /// Sliding window
    SlidingWindow,
    /// Fixed window
    FixedWindow,
    /// Token bucket
    TokenBucket,
    /// GCRA (Generic Cell Rate Algorithm)
    Gcra,
}

/// Rate limiter with Redis backend
pub struct RateLimiter {
    connection: Arc<RwLock<Option<ConnectionManager>>>,
    client: redis::Client,
    fail_open: bool,
    timeout: Duration,
    reconnect_interval: Duration,
    blocked_ips: Arc<RwLock<CidrSet>>,
}

/// Result of a rate limit check
#[derive(Debug)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed {
        /// Maximum requests allowed in the window
        limit: i64,
        /// Remaining requests in the current window
        remaining: i64,
        /// Timestamp when the window resets (Unix timestamp in seconds)
        reset_at: u64,
    },
    /// Request is rate limited
    Limited {
        /// Maximum requests allowed in the window
        limit: i64,
        /// Remaining requests in the current window (always 0)
        remaining: i64,
        /// Timestamp when the window resets (Unix timestamp in seconds)
        reset_at: u64,
        /// Time to wait before retry in seconds
        retry_after: u64,
    },
    /// Request is immediately blocked due to max <= 0 configuration
    Blocked,
    /// Redis unavailable and fail-open is enabled
    FailedOpen,
}

impl RateLimiter {
    /// Create a new rate limiter with default config
    /// This will attempt to connect but won't fail if Redis is unavailable
    pub fn new(url: &str, fail_open: bool, timeout: f64, reconnect_interval: u64) -> Result<Self> {
        let client = redis::Client::open(url).context("failed to create Redis client")?;

        Ok(Self {
            connection: Arc::new(RwLock::new(None)),
            client,
            fail_open,
            timeout: Duration::from_secs_f64(timeout),
            reconnect_interval: Duration::from_secs(reconnect_interval),
            blocked_ips: Arc::new(RwLock::new(CidrSet::new())),
        })
    }

    /// Start the background connection manager
    /// This spawns a dedicated thread with its own runtime to maintain the Redis connection
    pub fn start_connection_manager(self: &Arc<Self>) {
        let limiter = Arc::clone(self);

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("failed to create tokio runtime: {}", e);
                    return;
                }
            };

            rt.block_on(async move {
                loop {
                    // Check if we need to connect
                    let needs_connect = {
                        let conn = limiter.connection.read().await;
                        conn.is_none()
                    };

                    if needs_connect {
                        match ConnectionManager::new(limiter.client.clone()).await {
                            Ok(manager) => {
                                let mut conn = limiter.connection.write().await;
                                *conn = Some(manager);
                                tracing::info!("established Redis connection");
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "failed to connect to Redis, will retry in {:?}: {}",
                                    limiter.reconnect_interval,
                                    e
                                );
                            }
                        }
                    }

                    tokio::time::sleep(limiter.reconnect_interval).await;

                    // Verify connection is still healthy
                    let conn_healthy = {
                        let conn = limiter.connection.read().await;
                        if let Some(ref manager) = *conn {
                            let mut conn = manager.clone();
                            redis::cmd("PING")
                                .query_async::<String>(&mut conn)
                                .await
                                .is_ok()
                        } else {
                            false
                        }
                    };

                    if !conn_healthy {
                        let mut conn = limiter.connection.write().await;
                        if conn.is_some() {
                            tracing::warn!("lost Redis connection, will attempt to reconnect");
                            *conn = None;
                        }
                    }
                }
            });
        });
    }

    /// Get a connection manager clone if available
    async fn get_connection(&self) -> Option<ConnectionManager> {
        let conn = self.connection.read().await;
        conn.clone()
    }

    /// Add a CIDR to the Redis blocklist with the given TTL
    #[tracing::instrument(skip_all, fields(cidr, ttl))]
    pub async fn add_to_blocklist(&self, cidr: &str, ttl: u64) -> Result<()> {
        let Some(mut conn) = self.get_connection().await else {
            anyhow::bail!("failed to connect to Redis to add blocklist entry");
        };

        if ttl == 0 {
            // Never expires - use +inf score
            tokio::time::timeout(self.timeout, async {
                redis::cmd("ZADD")
                    .arg("bl:cidrs")
                    .arg("+inf")
                    .arg(cidr)
                    .query_async::<i64>(&mut conn)
                    .await
            })
            .await
            .context("operation timed out")?
            .context("ZADD failed")?;
        } else {
            let expires_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + ttl;
            tokio::time::timeout(self.timeout, async {
                redis::cmd("ZADD")
                    .arg("bl:cidrs")
                    .arg(expires_at)
                    .arg(cidr)
                    .query_async::<i64>(&mut conn)
                    .await
            })
            .await
            .context("operation timed out")?
            .context("ZADD failed")?;
        }

        let parsed =
            Cidr::from_str(cidr).map_err(|e| anyhow::anyhow!("invalid CIDR '{cidr}': {e}"))?;
        let mut blocked = self.blocked_ips.write().await;
        blocked.insert(parsed);
        if ttl == 0 {
            tracing::info!("permanently blocked CIDR {cidr}");
        } else {
            tracing::info!("blocked CIDR {cidr} for {ttl}s");
        }
        Ok(())
    }

    /// Remove CIDRs from the Redis blocklist and the local in-memory set
    #[tracing::instrument(skip_all)]
    pub async fn remove_from_blocklist(&self, cidrs: &[Cidr]) -> Result<()> {
        let Some(mut conn) = self.get_connection().await else {
            anyhow::bail!("failed to connect to Redis to remove blocklist entries");
        };

        let mut cmd = redis::cmd("ZREM");
        cmd.arg("bl:cidrs");
        for cidr in cidrs {
            cmd.arg(cidr.to_string());
        }
        tokio::time::timeout(self.timeout, cmd.query_async::<i64>(&mut conn))
            .await
            .context("operation timed out")?
            .context("ZREM failed")?;

        let mut blocked = self.blocked_ips.write().await;
        for cidr in cidrs {
            blocked.remove(*cidr);
        }
        tracing::info!("removed {} CIDR(s) from blocklist", cidrs.len());
        Ok(())
    }

    /// Refresh the in-memory blocklist from Redis
    /// Purges expired entries from the ZSET then rebuilds the local `CidrSet`
    async fn refresh_blocklist(&self) -> Result<()> {
        let Some(mut conn) = self.get_connection().await else {
            tracing::debug!("failed to connect to Redis, skipping blocklist refresh");
            return Ok(());
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Purge expired entries
        redis::cmd("ZREMRANGEBYSCORE")
            .arg("bl:cidrs")
            .arg("-inf")
            .arg(now.saturating_sub(1))
            .query_async::<i64>(&mut conn)
            .await
            .context("ZREMRANGEBYSCORE failed")?;

        // Fetch all active CIDRs (score >= now)
        let active: Vec<String> = redis::cmd("ZRANGEBYSCORE")
            .arg("bl:cidrs")
            .arg(now)
            .arg("+inf")
            .query_async(&mut conn)
            .await
            .context("ZRANGEBYSCORE failed")?;

        let mut new_set = CidrSet::new();
        for cidr_str in &active {
            match Cidr::from_str(cidr_str) {
                Ok(cidr) => new_set.insert(cidr),
                Err(e) => tracing::warn!("skipping invalid CIDR in blocklist '{cidr_str}': {e}"),
            }
        }

        tracing::trace!("blocklist refreshed: {} active CIDR(s)", active.len());
        *self.blocked_ips.write().await = new_set;
        Ok(())
    }

    /// Spawns a dedicated thread with its own runtime to periodically sync from Redis
    pub fn start_blocklist_refresh(self: &Arc<Self>, interval: Duration) {
        let limiter = Arc::clone(self);

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("failed to create tokio runtime for blocklist refresh: {e}");
                    return;
                }
            };

            rt.block_on(async move {
                loop {
                    tokio::time::sleep(interval).await;
                    if let Err(e) = limiter.refresh_blocklist().await {
                        tracing::warn!("blocklist refresh failed: {e}");
                    }
                }
            });
        });
    }

    /// Returns true if the given IP is covered by an entry in the local blocklist
    #[tracing::instrument(skip_all, fields(%ip))]
    pub async fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        self.blocked_ips.read().await.contains(ip)
    }

    /// Returns all active blocklist entries as `(cidr, expires_at)` pairs fetched from Redis
    pub async fn list_blocklist(&self) -> Result<Vec<(Cidr, u64)>> {
        let Some(mut conn) = self.get_connection().await else {
            anyhow::bail!("failed to connect to Redis");
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let raw: Vec<String> = redis::cmd("ZRANGEBYSCORE")
            .arg("bl:cidrs")
            .arg(now)
            .arg("+inf")
            .arg("WITHSCORES")
            .query_async(&mut conn)
            .await
            .context("ZRANGEBYSCORE WITHSCORES failed")?;

        let entries = raw
            .chunks(2)
            .filter_map(|pair| {
                let cidr: Cidr = pair[0].parse().ok()?;
                let expires_at: u64 = if pair[1] == "inf" {
                    0
                } else {
                    pair[1].parse().ok()?
                };
                Some((cidr, expires_at))
            })
            .collect();

        Ok(entries)
    }

    /// Check rate limit using the specified algorithm
    #[tracing::instrument(skip_all, fields(rule_name, key, algorithm = ?algorithm))]
    pub async fn check_rate_limit(
        &self,
        rule_name: &str,
        key: &str,
        interval: u64,
        max: i64,
        algorithm: Algorithm,
    ) -> Result<RateLimitResult> {
        // If the max is 0 or negative, we can short-circuit and block immediately without hitting Redis
        if max <= 0 {
            return Ok(RateLimitResult::Blocked);
        }
        match algorithm {
            Algorithm::SlidingWindow => {
                self.check_sliding_window(rule_name, key, interval, max)
                    .await
            }
            Algorithm::FixedWindow => self.check_fixed_window(rule_name, key, interval, max).await,
            Algorithm::TokenBucket => self.check_token_bucket(rule_name, key, interval, max).await,
            Algorithm::Gcra => self.check_gcra(rule_name, key, interval, max).await,
        }
    }

    /// Sliding window implementation using sorted sets
    #[tracing::instrument(skip_all, fields(rule_name, key))]
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_sign_loss)]
    async fn check_sliding_window(
        &self,
        rule_name: &str,
        key: &str,
        interval: u64,
        max: i64,
    ) -> Result<RateLimitResult> {
        let redis_key = format!("rl:sw:{rule_name}:{key}");

        let Some(mut conn) = self.get_connection().await else {
            if self.fail_open {
                tracing::debug!("failed to connect to Redis, failing open");
                return Ok(RateLimitResult::FailedOpen);
            }
            anyhow::bail!("failed to connect to Redis");
        };

        match tokio::time::timeout(self.timeout, async {
            SLIDING_WINDOW
                .key(&redis_key)
                .arg(max)
                .arg(interval)
                .arg(interval + 60)
                .invoke_async::<Vec<i64>>(&mut conn)
                .await
        })
        .await
        {
            Ok(Ok(result)) => {
                let count = result.first().copied().unwrap_or(0);
                let is_limited = result.get(1).copied().unwrap_or(0) == 1;
                let _now = result.get(2).copied().unwrap_or(0) as u64;
                let reset_at = result.get(3).copied().unwrap_or(0) as u64;

                if is_limited {
                    Ok(RateLimitResult::Limited {
                        limit: max,
                        remaining: 0,
                        reset_at,
                        retry_after: interval,
                    })
                } else {
                    Ok(RateLimitResult::Allowed {
                        limit: max,
                        remaining: max - count,
                        reset_at,
                    })
                }
            }
            Ok(Err(e)) => {
                if self.fail_open {
                    tracing::warn!("Redis operation failed, failing open: {}", e);
                    Ok(RateLimitResult::FailedOpen)
                } else {
                    Err(e.into())
                }
            }
            Err(_) => {
                if self.fail_open {
                    tracing::warn!("Redis operation timed out, failing open");
                    Ok(RateLimitResult::FailedOpen)
                } else {
                    anyhow::bail!("Redis operation timed out")
                }
            }
        }
    }

    /// Fixed window implementation using atomic increments
    #[tracing::instrument(skip_all, fields(rule_name, key))]
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_sign_loss)]
    async fn check_fixed_window(
        &self,
        rule_name: &str,
        key: &str,
        interval: u64,
        max: i64,
    ) -> Result<RateLimitResult> {
        let Some(mut conn) = self.get_connection().await else {
            if self.fail_open {
                tracing::debug!("failed to connect to Redis, failing open");
                return Ok(RateLimitResult::FailedOpen);
            }
            anyhow::bail!("failed to connect to Redis");
        };

        match tokio::time::timeout(self.timeout, async {
            let key_prefix = format!("rl:fw:{rule_name}:{key}:");
            FIXED_WINDOW
                .key(&key_prefix)
                .arg(max)
                .arg(interval)
                .arg(interval + 60)
                .invoke_async::<Vec<i64>>(&mut conn)
                .await
        })
        .await
        {
            Ok(Ok(result)) => {
                let count = result.first().copied().unwrap_or(0);
                let is_limited = result.get(1).copied().unwrap_or(0) == 1;
                let reset_at = result.get(2).copied().unwrap_or(0) as u64;
                let retry_after = result.get(3).copied().unwrap_or(0) as u64;

                if is_limited {
                    Ok(RateLimitResult::Limited {
                        limit: max,
                        remaining: 0,
                        reset_at,
                        retry_after,
                    })
                } else {
                    Ok(RateLimitResult::Allowed {
                        limit: max,
                        remaining: max - count,
                        reset_at,
                    })
                }
            }
            Ok(Err(e)) => {
                if self.fail_open {
                    tracing::warn!("Redis operation failed, failing open: {}", e);
                    Ok(RateLimitResult::FailedOpen)
                } else {
                    Err(e.into())
                }
            }
            Err(_) => {
                if self.fail_open {
                    tracing::warn!("Redis operation timed out, failing open");
                    Ok(RateLimitResult::FailedOpen)
                } else {
                    anyhow::bail!("Redis operation timed out")
                }
            }
        }
    }

    /// Token bucket implementation
    #[tracing::instrument(skip_all, fields(rule_name, key))]
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_sign_loss)]
    async fn check_token_bucket(
        &self,
        rule_name: &str,
        key: &str,
        interval: u64,
        max: i64,
    ) -> Result<RateLimitResult> {
        let Some(mut conn) = self.get_connection().await else {
            if self.fail_open {
                tracing::debug!("failed to connect to Redis, failing open");
                return Ok(RateLimitResult::FailedOpen);
            }
            anyhow::bail!("failed to connect to Redis");
        };

        let redis_key = format!("rl:tb:{rule_name}:{key}");

        // Calculate refill rate: tokens per second
        let refill_rate = max as f64 / interval as f64;

        match tokio::time::timeout(self.timeout, async {
            TOKEN_BUCKET
                .key(&redis_key)
                .arg(max)
                .arg(refill_rate)
                .arg(interval * 2) // Keep bucket data for 2x interval
                .invoke_async::<Vec<i64>>(&mut conn)
                .await
        })
        .await
        {
            Ok(Ok(result)) => {
                let allowed = result.first().copied().unwrap_or(0) == 1;
                let tokens = result.get(1).copied().unwrap_or(0);
                let retry_after = result.get(2).copied().unwrap_or(0) as u64;
                let server_now = result.get(3).copied().unwrap_or(0) as u64;

                let reset_at = server_now.saturating_add(retry_after);

                if allowed {
                    Ok(RateLimitResult::Allowed {
                        limit: max,
                        remaining: tokens,
                        reset_at,
                    })
                } else {
                    Ok(RateLimitResult::Limited {
                        limit: max,
                        remaining: 0,
                        reset_at,
                        retry_after,
                    })
                }
            }
            Ok(Err(e)) => {
                if self.fail_open {
                    tracing::warn!("Redis operation failed, failing open: {}", e);
                    Ok(RateLimitResult::FailedOpen)
                } else {
                    Err(e.into())
                }
            }
            Err(_) => {
                if self.fail_open {
                    tracing::warn!("Redis operation timed out, failing open");
                    Ok(RateLimitResult::FailedOpen)
                } else {
                    anyhow::bail!("Redis operation timed out")
                }
            }
        }
    }

    /// GCRA (Generic Cell Rate Algorithm) implementation
    /// Most precise, based on theoretical arrival time
    /// Adapted from redis-rate
    #[tracing::instrument(skip_all, fields(rule_name, key))]
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_sign_loss)]
    async fn check_gcra(
        &self,
        rule_name: &str,
        key: &str,
        interval: u64,
        max: i64,
    ) -> Result<RateLimitResult> {
        let redis_key = format!("rl:gcra:{rule_name}:{key}");

        // Calculate GCRA parameters
        let emission_interval = interval as f64 / max as f64; // Time between tokens
        let burst_offset = max as f64 * emission_interval; // Burst capacity (allows `max` concurrent requests)
        let tat_increment = emission_interval; // TAT increment per request
        let cost = 1.0; // Cost of this request

        let Some(mut conn) = self.get_connection().await else {
            if self.fail_open {
                tracing::debug!("failed to connect to Redis, failing open");
                return Ok(RateLimitResult::FailedOpen);
            }
            anyhow::bail!("failed to connect to Redis");
        };

        match tokio::time::timeout(self.timeout, async {
            GCRA.key(&redis_key)
                .arg(emission_interval)
                .arg(burst_offset)
                .arg(tat_increment)
                .arg(cost)
                .invoke_async::<Vec<i64>>(&mut conn)
                .await
        })
        .await
        {
            Ok(Ok(result)) => {
                let limited = result.first().copied().unwrap_or(0) == 1;
                let remaining = result.get(1).copied().unwrap_or(0);
                let retry_after = result.get(2).copied().unwrap_or(0) as u64;
                let reset_after = result.get(3).copied().unwrap_or(0) as u64;
                let server_now = result.get(4).copied().unwrap_or(0) as u64;

                let reset_at = server_now + reset_after;

                if limited {
                    Ok(RateLimitResult::Limited {
                        limit: max,
                        remaining: 0,
                        reset_at,
                        retry_after,
                    })
                } else {
                    Ok(RateLimitResult::Allowed {
                        limit: max,
                        remaining,
                        reset_at,
                    })
                }
            }
            Ok(Err(e)) => {
                if self.fail_open {
                    tracing::warn!("Redis operation failed, failing open: {}", e);
                    Ok(RateLimitResult::FailedOpen)
                } else {
                    Err(e.into())
                }
            }
            Err(_) => {
                if self.fail_open {
                    tracing::warn!("Redis operation timed out, failing open");
                    Ok(RateLimitResult::FailedOpen)
                } else {
                    anyhow::bail!("Redis operation timed out")
                }
            }
        }
    }

    /// Get the current count for a key (useful for monitoring)
    #[allow(dead_code)]
    pub async fn get_current_count(
        &self,
        rule_name: &str,
        key: &str,
        algorithm: Algorithm,
    ) -> Result<i64> {
        let Some(mut conn) = self.get_connection().await else {
            anyhow::bail!("failed to connect to Redis");
        };

        let count = match algorithm {
            Algorithm::SlidingWindow => {
                let redis_key = format!("rl:sw:{rule_name}:{key}");
                conn.zcard(&redis_key).await?
            }
            Algorithm::FixedWindow => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                // Note: Fixed window needs interval to calculate current window
                // This is approximate - use 60s window for monitoring
                let window = now / 60;
                let redis_key = format!("rl:fw:{rule_name}:{key}:{window}");
                conn.get(&redis_key).await.unwrap_or(0)
            }
            Algorithm::TokenBucket => {
                let redis_key = format!("rl:tb:{rule_name}:{key}");
                let bucket: Vec<Option<String>> = conn.hget(&redis_key, "tokens").await?;
                bucket
                    .first()
                    .and_then(|v| v.as_ref())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0)
            }
            Algorithm::Gcra => {
                let redis_key = format!("rl:gcra:{rule_name}:{key}");
                // GCRA stores TAT (Theoretical Arrival Time), not a count
                // Return 0 if key doesn't exist, 1 if it does (indicates recent activity)
                let tat: Option<String> = conn.get(&redis_key).await?;
                i64::from(tat.is_some())
            }
        };

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create a test limiter with established connection
    async fn create_test_limiter() -> Arc<RateLimiter> {
        let limiter = Arc::new(RateLimiter::new("redis://localhost:6379", true, 0.5, 1).unwrap());
        limiter.start_connection_manager();
        // Wait for connection to establish
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        assert!(
            !limiter.connection.read().await.is_none(),
            "Failed to connect to Redis after multiple attempts"
        );
        limiter
    }

    /// Helper function to create concurrent requests
    async fn fire_concurrent_requests(
        limiter: &Arc<RateLimiter>,
        rule_name: &str,
        key: &str,
        interval: u64,
        max: i64,
        algorithm: Algorithm,
        num_requests: usize,
    ) -> Vec<RateLimitResult> {
        let mut tasks = tokio::task::JoinSet::new();

        // Clone the Arc for each task to enable true concurrency
        for _ in 0..num_requests {
            let limiter = Arc::clone(limiter);
            let rule_name = rule_name.to_string();
            let key = key.to_string();

            tasks.spawn(async move {
                limiter
                    .check_rate_limit(&rule_name, &key, interval, max, algorithm)
                    .await
                    .unwrap()
            });
        }

        let mut results = Vec::with_capacity(num_requests);
        while let Some(result) = tasks.join_next().await {
            results.push(result.expect("task panicked"));
        }
        results
    }

    #[tokio::test]
    async fn test_sliding_window_burst() {
        let limiter = create_test_limiter().await;
        let rule_name = "test_sliding_burst";
        let key = uuid::Uuid::new_v4().to_string();
        let interval = 10; // 10 second window
        let max = 5; // Allow 5 requests per window
        let num_requests = 10; // Fire 10 concurrent requests

        let results = fire_concurrent_requests(
            &limiter,
            rule_name,
            &key,
            interval,
            max,
            Algorithm::SlidingWindow,
            num_requests,
        )
        .await;

        let allowed_count = results
            .iter()
            .filter(|r| matches!(r, RateLimitResult::Allowed { .. }))
            .count();
        let limited_count = results
            .iter()
            .filter(|r| matches!(r, RateLimitResult::Limited { .. }))
            .count();

        assert_eq!(
            allowed_count,
            usize::try_from(max).unwrap(),
            "Should allow exactly max requests"
        );
        assert_eq!(limited_count, num_requests - usize::try_from(max).unwrap());

        let mut allowed_remaining: Vec<i64> = results
            .iter()
            .filter_map(|r| {
                if let RateLimitResult::Allowed { remaining, .. } = r {
                    Some(*remaining)
                } else {
                    None
                }
            })
            .collect();
        allowed_remaining.sort_unstable();
        assert_eq!(
            allowed_remaining,
            (0..max).collect::<Vec<_>>(),
            "Allowed remaining values should span 0..max-1"
        );
        for result in &results {
            if let RateLimitResult::Limited { remaining, .. } = result {
                assert_eq!(*remaining, 0, "Limited remaining should always be 0");
            }
        }
    }

    #[tokio::test]
    async fn test_fixed_window_burst() {
        let limiter = create_test_limiter().await;
        let rule_name = "test_fixed_burst";
        let key = uuid::Uuid::new_v4().to_string();
        let interval = 10;
        let max = 5;
        let num_requests = 10;

        let results = fire_concurrent_requests(
            &limiter,
            rule_name,
            &key,
            interval,
            max,
            Algorithm::FixedWindow,
            num_requests,
        )
        .await;

        let allowed_count = results
            .iter()
            .filter(|r| matches!(r, RateLimitResult::Allowed { .. }))
            .count();
        let limited_count = results
            .iter()
            .filter(|r| matches!(r, RateLimitResult::Limited { .. }))
            .count();

        assert_eq!(allowed_count, usize::try_from(max).unwrap());
        assert_eq!(limited_count, num_requests - usize::try_from(max).unwrap());

        let mut allowed_remaining: Vec<i64> = results
            .iter()
            .filter_map(|r| {
                if let RateLimitResult::Allowed { remaining, .. } = r {
                    Some(*remaining)
                } else {
                    None
                }
            })
            .collect();
        allowed_remaining.sort_unstable();
        assert_eq!(
            allowed_remaining,
            (0..max).collect::<Vec<_>>(),
            "Allowed remaining values should span 0..max-1"
        );
        for result in &results {
            if let RateLimitResult::Limited { remaining, .. } = result {
                assert_eq!(*remaining, 0, "Limited remaining should always be 0");
            }
        }
    }

    #[tokio::test]
    async fn test_token_bucket_burst() {
        let limiter = create_test_limiter().await;
        let rule_name = "test_bucket_burst";
        let key = uuid::Uuid::new_v4().to_string();
        let interval = 10;
        let max = 5;
        let num_requests = 10;

        let results = fire_concurrent_requests(
            &limiter,
            rule_name,
            &key,
            interval,
            max,
            Algorithm::TokenBucket,
            num_requests,
        )
        .await;

        let allowed_count = results
            .iter()
            .filter(|r| matches!(r, RateLimitResult::Allowed { .. }))
            .count();
        let limited_count = results
            .iter()
            .filter(|r| matches!(r, RateLimitResult::Limited { .. }))
            .count();

        assert_eq!(
            allowed_count,
            usize::try_from(max).unwrap(),
            "Should allow burst up to max tokens"
        );
        assert_eq!(limited_count, num_requests - usize::try_from(max).unwrap());

        let mut allowed_remaining: Vec<i64> = results
            .iter()
            .filter_map(|r| {
                if let RateLimitResult::Allowed { remaining, .. } = r {
                    Some(*remaining)
                } else {
                    None
                }
            })
            .collect();
        allowed_remaining.sort_unstable();
        assert_eq!(
            allowed_remaining,
            (0..max).collect::<Vec<_>>(),
            "Allowed remaining values should span 0..max-1"
        );
        for result in &results {
            if let RateLimitResult::Limited { remaining, .. } = result {
                assert_eq!(*remaining, 0, "Limited remaining should always be 0");
            }
        }
    }

    #[tokio::test]
    async fn test_gcra_burst() {
        let limiter = create_test_limiter().await;
        let rule_name = "test_gcra_burst";
        let key = uuid::Uuid::new_v4().to_string();
        let interval = 10;
        let max = 5;
        let num_requests = 10;

        let results = fire_concurrent_requests(
            &limiter,
            rule_name,
            &key,
            interval,
            max,
            Algorithm::Gcra,
            num_requests,
        )
        .await;

        let allowed_count = results
            .iter()
            .filter(|r| matches!(r, RateLimitResult::Allowed { .. }))
            .count();
        let limited_count = results
            .iter()
            .filter(|r| matches!(r, RateLimitResult::Limited { .. }))
            .count();

        assert_eq!(
            allowed_count,
            usize::try_from(max).unwrap(),
            "GCRA should allow exactly max requests in burst"
        );
        assert_eq!(limited_count, num_requests - usize::try_from(max).unwrap());

        let mut allowed_remaining: Vec<i64> = results
            .iter()
            .filter_map(|r| {
                if let RateLimitResult::Allowed { remaining, .. } = r {
                    Some(*remaining)
                } else {
                    None
                }
            })
            .collect();
        allowed_remaining.sort_unstable();
        assert_eq!(
            allowed_remaining,
            (0..max).collect::<Vec<_>>(),
            "Allowed remaining values should span 0..max-1"
        );
        for result in &results {
            if let RateLimitResult::Limited { remaining, .. } = result {
                assert_eq!(*remaining, 0, "Limited remaining should always be 0");
            }
        }
    }
}

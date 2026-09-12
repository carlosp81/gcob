use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use redis::aio::MultiplexedConnection;
use redis::RedisResult;
use tokio::sync::Mutex;

/// Rate limit policy: `limit` requests per `window_seconds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitPolicy {
    pub limit: u32,
    pub window_seconds: u64,
}

/// Payment-creating calls (`invoice`, `xpay`).
pub const PAYMENT_POLICY: RateLimitPolicy = RateLimitPolicy {
    limit: 3,
    window_seconds: 3600,
};

/// Read-only node information.
pub const GETINFO_POLICY: RateLimitPolicy = RateLimitPolicy {
    limit: 60,
    window_seconds: 3600,
};

/// Stream subscription creation.
pub const STREAM_POLICY: RateLimitPolicy = RateLimitPolicy {
    limit: 12,
    window_seconds: 3600,
};

/// Policy for a CLN method name (as mapped from the gRPC path).
///
/// `None` means the method is not rate limited; unknown paths are rejected by
/// the auth layer anyway.
pub fn policy_for_method(method: &str) -> Option<RateLimitPolicy> {
    match method {
        "invoice" | "xpay" => Some(PAYMENT_POLICY),
        "getinfo" => Some(GETINFO_POLICY),
        "xpay_stream" | "invoice_watch" | "watch_channels" | "watch_peers" | "watch_system" => {
            Some(STREAM_POLICY)
        }
        _ => None,
    }
}

// --- Redis rate limiter ---

pub async fn check_rate_limit(
    redis_cm: &MultiplexedConnection,
    key: &str,
    policy: RateLimitPolicy,
) -> Result<bool, redis::RedisError> {
    let mut con = redis_cm.clone();
    check_rate_limit_redis(&mut con, key, policy).await
}

async fn check_rate_limit_redis(
    con: &mut MultiplexedConnection,
    key: &str,
    policy: RateLimitPolicy,
) -> Result<bool, redis::RedisError> {
    let key = format!("rate_limit:{}", key);

    let script = redis::Script::new(
        r#"
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local current = redis.call('INCR', key)
        if current == 1 then
            redis.call('EXPIRE', key, window)
        end
        if current > limit then
            return 0
        else
            return 1
        end
        "#,
    );

    let result: RedisResult<i32> = script
        .key(key)
        .arg(policy.limit)
        .arg(policy.window_seconds)
        .invoke_async(con)
        .await;

    match result {
        Ok(1) => Ok(true),
        Ok(_) => Ok(false),
        Err(e) => Err(e),
    }
}

// --- In-memory fallback rate limiter ---

struct TokenBucket {
    tokens: u32,
    capacity: u32,
    refill_duration: Duration,
    last_refill: Instant,
}

#[derive(Default)]
pub struct InMemoryRateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

impl InMemoryRateLimiter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn check(&self, key: &str, policy: RateLimitPolicy) -> bool {
        let refill_duration = Duration::from_secs(policy.window_seconds);
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();

        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: policy.limit,
                capacity: policy.limit,
                refill_duration,
                last_refill: now,
            });
        bucket.capacity = policy.limit;
        bucket.refill_duration = refill_duration;

        // Refill tokens based on elapsed time.
        let elapsed = now.duration_since(bucket.last_refill);
        if elapsed >= bucket.refill_duration {
            bucket.tokens = bucket.capacity;
            bucket.last_refill = now;
        } else if bucket.tokens < bucket.capacity {
            let refill_tokens = (elapsed.as_secs_f64() / bucket.refill_duration.as_secs_f64()
                * bucket.capacity as f64) as u32;
            if refill_tokens > 0 {
                bucket.tokens = (bucket.tokens + refill_tokens).min(bucket.capacity);
                bucket.last_refill = now;
            }
        }

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            true
        } else {
            false
        }
    }

    pub async fn cleanup(&self) {
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();
        buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill) < bucket.refill_duration * 2
        });
    }

    /// Number of tracked keys; used by availability tests to assert that
    /// spoofed claims cannot grow the limiter state.
    #[cfg(test)]
    pub(crate) async fn bucket_count(&self) -> usize {
        self.buckets.lock().await.len()
    }
}

// --- Combined rate limiter with fallback ---

pub async fn check_rate_limit_with_fallback(
    redis_cm: &Option<MultiplexedConnection>,
    fallback: &InMemoryRateLimiter,
    key: &str,
    policy: RateLimitPolicy,
) -> bool {
    // Try Redis first
    if let Some(cm) = redis_cm {
        match check_rate_limit(cm, key, policy).await {
            Ok(allowed) => return allowed,
            Err(e) => {
                tracing::warn!("Redis rate limit failed, using fallback: {}", e);
            }
        }
    }
    // Fallback to in-memory
    fallback.check(key, policy).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payment() -> RateLimitPolicy {
        PAYMENT_POLICY
    }

    #[test]
    fn policy_mapping_is_per_method() {
        assert_eq!(policy_for_method("invoice"), Some(PAYMENT_POLICY));
        assert_eq!(policy_for_method("xpay"), Some(PAYMENT_POLICY));
        assert_eq!(policy_for_method("getinfo"), Some(GETINFO_POLICY));
        assert_eq!(policy_for_method("xpay_stream"), Some(STREAM_POLICY));
        assert_eq!(policy_for_method("invoice_watch"), Some(STREAM_POLICY));
        assert_eq!(policy_for_method("watch_channels"), Some(STREAM_POLICY));
        assert_eq!(policy_for_method("watch_peers"), Some(STREAM_POLICY));
        assert_eq!(policy_for_method("watch_system"), Some(STREAM_POLICY));
        assert_eq!(policy_for_method("unknown"), None);
    }

    #[tokio::test]
    async fn in_memory_allows_under_limit() {
        let limiter = InMemoryRateLimiter::new();
        assert!(limiter.check("xpay:client-1", payment()).await);
        assert!(limiter.check("xpay:client-1", payment()).await);
        assert!(limiter.check("xpay:client-1", payment()).await);
    }

    #[tokio::test]
    async fn in_memory_rejects_over_limit() {
        let limiter = InMemoryRateLimiter::new();
        assert!(limiter.check("xpay:client-1", payment()).await);
        assert!(limiter.check("xpay:client-1", payment()).await);
        assert!(limiter.check("xpay:client-1", payment()).await);
        assert!(!limiter.check("xpay:client-1", payment()).await);
    }

    #[tokio::test]
    async fn in_memory_different_clients_and_methods_are_independent() {
        let limiter = InMemoryRateLimiter::new();
        assert!(limiter.check("xpay:client-A", payment()).await);
        assert!(limiter.check("xpay:client-A", payment()).await);
        assert!(limiter.check("xpay:client-A", payment()).await);
        assert!(!limiter.check("xpay:client-A", payment()).await);
        // Different client and different method keep their own budget.
        assert!(limiter.check("xpay:client-B", payment()).await);
        assert!(limiter.check("getinfo:client-A", GETINFO_POLICY).await);
    }

    #[tokio::test]
    async fn in_memory_respects_policy_capacity() {
        let limiter = InMemoryRateLimiter::new();
        let policy = RateLimitPolicy {
            limit: 2,
            window_seconds: 3600,
        };
        assert!(limiter.check("k", policy).await);
        assert!(limiter.check("k", policy).await);
        assert!(!limiter.check("k", policy).await);
    }

    #[tokio::test]
    async fn in_memory_refills_after_duration() {
        let limiter = InMemoryRateLimiter::new();
        let policy = RateLimitPolicy {
            limit: 1,
            window_seconds: 1,
        };
        assert!(limiter.check("client-1", policy).await);
        assert!(!limiter.check("client-1", policy).await);
        // Wait for a full window.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(limiter.check("client-1", policy).await);
    }

    #[tokio::test]
    async fn in_memory_cleanup_removes_expired() {
        let limiter = InMemoryRateLimiter::new();
        let policy = RateLimitPolicy {
            limit: 1,
            window_seconds: 1,
        };
        limiter.check("client-1", policy).await;
        // Force the bucket to look old enough for cleanup.
        {
            let mut buckets = limiter.buckets.lock().await;
            if let Some(bucket) = buckets.get_mut("client-1") {
                bucket.last_refill = Instant::now() - Duration::from_secs(5);
            }
        }
        limiter.cleanup().await;
        let buckets = limiter.buckets.lock().await;
        assert!(buckets.is_empty());
    }
}

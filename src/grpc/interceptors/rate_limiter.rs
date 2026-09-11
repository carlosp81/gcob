use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use redis::aio::MultiplexedConnection;
use redis::RedisResult;
use tokio::sync::Mutex;

const RATE_LIMIT_PER_HOUR: u32 = 3;
const WINDOW_SECONDS: u64 = 3600;

// --- Redis rate limiter ---

pub async fn check_rate_limit(
    redis_cm: &MultiplexedConnection,
    client_id: &str,
) -> Result<bool, redis::RedisError> {
    let mut con = redis_cm.clone();
    check_rate_limit_redis(&mut con, client_id).await
}

async fn check_rate_limit_redis(
    con: &mut MultiplexedConnection,
    client_id: &str,
) -> Result<bool, redis::RedisError> {
    let key = format!("rate_limit:{}", client_id);

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
        .arg(RATE_LIMIT_PER_HOUR)
        .arg(WINDOW_SECONDS)
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
    last_refill: Instant,
}

pub struct InMemoryRateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    capacity: u32,
    refill_duration: Duration,
}

impl InMemoryRateLimiter {
    pub fn new(capacity: u32, refill_duration: Duration) -> Arc<Self> {
        Arc::new(Self {
            buckets: Mutex::new(HashMap::new()),
            capacity,
            refill_duration,
        })
    }

    pub async fn check(&self, client_id: &str) -> bool {
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();

        let bucket = buckets
            .entry(client_id.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: self.capacity,
                last_refill: now,
            });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill);
        if elapsed >= self.refill_duration {
            bucket.tokens = self.capacity;
            bucket.last_refill = now;
        } else if bucket.tokens < self.capacity {
            // Partial refill based on time proportion
            let refill_tokens =
                (elapsed.as_secs_f64() / self.refill_duration.as_secs_f64()
                    * self.capacity as f64) as u32;
            if refill_tokens > 0 {
                bucket.tokens = (bucket.tokens + refill_tokens).min(self.capacity);
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
        let max_age = self.refill_duration * 2;
        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) < max_age);
    }
}

// --- Combined rate limiter with fallback ---

pub async fn check_rate_limit_with_fallback(
    redis_cm: &Option<MultiplexedConnection>,
    fallback: &InMemoryRateLimiter,
    client_id: &str,
) -> bool {
    // Try Redis first
    if let Some(cm) = redis_cm {
        match check_rate_limit(cm, client_id).await {
            Ok(allowed) => return allowed,
            Err(e) => {
                tracing::warn!("Redis rate limit failed, using fallback: {}", e);
            }
        }
    }
    // Fallback to in-memory
    fallback.check(client_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_allows_under_limit() {
        let limiter = InMemoryRateLimiter::new(3, Duration::from_secs(3600));
        assert!(limiter.check("client-1").await);
        assert!(limiter.check("client-1").await);
        assert!(limiter.check("client-1").await);
    }

    #[tokio::test]
    async fn in_memory_rejects_over_limit() {
        let limiter = InMemoryRateLimiter::new(3, Duration::from_secs(3600));
        assert!(limiter.check("client-1").await);
        assert!(limiter.check("client-1").await);
        assert!(limiter.check("client-1").await);
        assert!(!limiter.check("client-1").await);
    }

    #[tokio::test]
    async fn in_memory_different_clients_independent() {
        let limiter = InMemoryRateLimiter::new(2, Duration::from_secs(3600));
        assert!(limiter.check("client-A").await);
        assert!(limiter.check("client-A").await);
        assert!(!limiter.check("client-A").await);
        // Client B should still have full tokens
        assert!(limiter.check("client-B").await);
    }

    #[tokio::test]
    async fn in_memory_refills_after_duration() {
        let limiter = InMemoryRateLimiter::new(1, Duration::from_millis(50));
        assert!(limiter.check("client-1").await);
        assert!(!limiter.check("client-1").await);
        // Wait for refill
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(limiter.check("client-1").await);
    }

    #[tokio::test]
    async fn in_memory_cleanup_removes_expired() {
        let limiter = InMemoryRateLimiter::new(1, Duration::from_millis(10));
        limiter.check("client-1").await;
        // Wait for bucket to expire
        tokio::time::sleep(Duration::from_millis(30)).await;
        limiter.cleanup().await;
        let buckets = limiter.buckets.lock().await;
        assert!(buckets.is_empty());
    }
}

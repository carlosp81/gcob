use redis::aio::MultiplexedConnection;
use redis::RedisResult;

const RATE_LIMIT_PER_HOUR: u32 = 3;
const WINDOW_SECONDS: u64 = 3600;

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

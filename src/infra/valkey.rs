use redis::{aio::MultiplexedConnection, Client};

use anyhow::Result;
use std::sync::Arc;

#[allow(dead_code)]
pub struct ConnectionHandler {
    pub inner: Arc<MultiplexedConnection>,
}

#[allow(dead_code)]
impl ConnectionHandler {
    pub async fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
        let client = Client::open(redis_url)?;
        let connection = client.get_multiplexed_async_connection().await?;

        Ok(ConnectionHandler {
            inner: Arc::new(connection),
        })
    }
}

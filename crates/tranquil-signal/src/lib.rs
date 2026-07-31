mod client;
#[cfg(feature = "sqlite")]
pub mod sqlite_store;
#[cfg(feature = "postgres")]
pub mod store;

#[cfg(feature = "fjall-store")]
pub mod fjall_store;

#[cfg(all(test, feature = "postgres"))]
mod tests;
#[cfg(all(test, feature = "fjall-store"))]
mod tests_fjall;

pub use client::{
    DeviceName, InvalidDeviceName, InvalidSignalUsername, LinkGeneration, LinkResult, MessageBody,
    MessageTooLong, SignalClient, SignalError, SignalSlot, SignalUsername,
};
pub use presage;
#[cfg(feature = "sqlite")]
pub use sqlite_store::SqliteSignalStore;
#[cfg(feature = "postgres")]
pub use store::PgSignalStore;

#[async_trait::async_trait]
pub trait SignalStoreProvider: Send + Sync {
    async fn is_signal_linked(&self) -> bool;
    async fn clear_signal_data(&self) -> Result<(), SignalError>;
    async fn link_signal_device(
        &self,
        device_name: DeviceName,
        shutdown: tokio_util::sync::CancellationToken,
        link_cancel: tokio_util::sync::CancellationToken,
        linking_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<LinkResult, SignalError>;
    async fn load_signal_client(
        &self,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Option<SignalClient>;
}

#[cfg(feature = "sqlite")]
pub struct SqliteSignalStoreProvider {
    pub pool: sqlx::SqlitePool,
}

#[cfg(feature = "sqlite")]
#[async_trait::async_trait]
impl SignalStoreProvider for SqliteSignalStoreProvider {
    async fn is_signal_linked(&self) -> bool {
        SqliteSignalStore::new(self.pool.clone())
            .is_linked()
            .await
            .unwrap_or(false)
    }

    async fn clear_signal_data(&self) -> Result<(), SignalError> {
        SqliteSignalStore::new(self.pool.clone())
            .clear_all()
            .await
            .map_err(|e| SignalError::Store(e.to_string()))
    }

    async fn link_signal_device(
        &self,
        device_name: DeviceName,
        shutdown: tokio_util::sync::CancellationToken,
        link_cancel: tokio_util::sync::CancellationToken,
        linking_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<LinkResult, SignalError> {
        SignalClient::link_device_with_store(
            SqliteSignalStore::new(self.pool.clone()),
            device_name,
            shutdown,
            link_cancel,
            linking_flag,
        )
        .await
    }

    async fn load_signal_client(
        &self,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Option<SignalClient> {
        SignalClient::from_store(SqliteSignalStore::new(self.pool.clone()), shutdown).await
    }
}

#[cfg(feature = "postgres")]
pub struct PgSignalStoreProvider {
    pub pool: sqlx::PgPool,
}

#[cfg(feature = "postgres")]
#[async_trait::async_trait]
impl SignalStoreProvider for PgSignalStoreProvider {
    async fn is_signal_linked(&self) -> bool {
        PgSignalStore::new(self.pool.clone())
            .is_linked()
            .await
            .unwrap_or(false)
    }

    async fn clear_signal_data(&self) -> Result<(), SignalError> {
        PgSignalStore::new(self.pool.clone())
            .clear_all()
            .await
            .map_err(SignalError::from)
    }

    async fn link_signal_device(
        &self,
        device_name: DeviceName,
        shutdown: tokio_util::sync::CancellationToken,
        link_cancel: tokio_util::sync::CancellationToken,
        linking_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<LinkResult, SignalError> {
        SignalClient::link_device(&self.pool, device_name, shutdown, link_cancel, linking_flag)
            .await
    }

    async fn load_signal_client(
        &self,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Option<SignalClient> {
        SignalClient::from_pool(&self.pool, shutdown).await
    }
}

use async_trait::async_trait;
use tokio::sync::broadcast;
use tranquil_db_traits::{DbError, RepoEventNotifier, RepoEventReceiver};

/// SQLite has no server-side LISTEN/NOTIFY equivalent. Repository writers
/// share this in-process channel instead; a single PDS process is the intended
/// deployment model for this backend.
#[derive(Clone)]
pub struct SqliteRepoEventNotifier {
    sender: broadcast::Sender<()>,
}

impl SqliteRepoEventNotifier {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn notify(&self) {
        let _ = self.sender.send(());
    }

    pub fn sender(&self) -> broadcast::Sender<()> {
        self.sender.clone()
    }
}

#[async_trait]
impl RepoEventNotifier for SqliteRepoEventNotifier {
    async fn subscribe(&self) -> Result<Box<dyn RepoEventReceiver>, DbError> {
        Ok(Box::new(SqliteRepoEventReceiver {
            receiver: self.sender.subscribe(),
        }))
    }
}

struct SqliteRepoEventReceiver {
    receiver: broadcast::Receiver<()>,
}

#[async_trait]
impl RepoEventReceiver for SqliteRepoEventReceiver {
    async fn recv(&mut self) -> Option<()> {
        self.receiver.recv().await.ok()
    }
}

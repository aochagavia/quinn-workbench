use futures::FutureExt;
use futures::future::Shared;

#[derive(Clone)]
pub struct CancellationToken {
    rx: Shared<futures::channel::oneshot::Receiver<()>>,
}

impl CancellationToken {
    pub fn new() -> (Self, CancellationSignal) {
        let (tx, rx) = futures::channel::oneshot::channel();
        let token = Self { rx: rx.shared() };
        let signal = CancellationSignal { tx };

        (token, signal)
    }

    pub fn is_cancelled(&self) -> bool {
        match self.rx.clone().now_or_never() {
            // Future is not ready
            None => false,
            // Sender sent a cancel signal
            Some(Ok(())) => true,
            // Sender dropped
            Some(Err(_)) => false,
        }
    }

    pub async fn cancelled(&self) {
        let result = self.rx.clone().await;
        if result.is_ok() {
            // A cancel was requested, so we are done waiting
        } else {
            // The sender was dropped, so a cancellation will never arrive
            futures::future::pending().await
        }
    }
}

pub struct CancellationSignal {
    tx: futures::channel::oneshot::Sender<()>,
}

impl CancellationSignal {
    pub fn cancel(self) {
        self.tx.send(()).ok();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::async_rt::instant::Instant;
    use crate::async_rt::{sleep, spawn};
    use futures::select_biased;
    use std::time::Duration;

    #[macros::async_test_priv]
    async fn test_cancel() {
        let start = Instant::now();
        let (token, signal) = CancellationToken::new();

        spawn(async move {
            sleep(Duration::from_secs(3)).await;
            signal.cancel();
        });

        let sleep = sleep(Duration::from_secs(5));
        select_biased! {
            _ = token.cancelled().fuse() => (),
            _ = sleep.fuse() => (),
        }

        assert_eq!(start.elapsed(), Duration::from_secs(3));
        assert!(token.is_cancelled());
    }

    #[macros::async_test_priv]
    async fn test_cancel_multiple() {
        let start = Instant::now();
        let (token, signal) = CancellationToken::new();

        let mut handles = Vec::new();
        for _ in 0..4 {
            let token = token.clone();
            handles.push(spawn(async move {
                let sleep = sleep(Duration::from_secs(10));
                select_biased! {
                    _ = token.cancelled().fuse() => (),
                    _ = sleep.fuse() => (),
                }
            }));
        }

        sleep(Duration::from_secs(3)).await;
        signal.cancel();

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(start.elapsed(), Duration::from_secs(3));
        assert!(token.is_cancelled());
    }

    #[macros::async_test_priv]
    async fn test_cancel_drop() {
        let start = Instant::now();
        let (token, signal) = CancellationToken::new();
        drop(signal);

        let sleep = sleep(Duration::from_secs(5));
        select_biased! {
            _ = token.cancelled().fuse() => (),
            _ = sleep.fuse() => (),
        }

        assert_eq!(start.elapsed(), Duration::from_secs(5));
        assert!(!token.is_cancelled());
    }
}

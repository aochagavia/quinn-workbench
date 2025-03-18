use parking_lot::Mutex;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, atomic};
use std::task::{Context, Poll, Waker};

#[derive(Clone)]
pub struct Notify {
    waiting: Arc<Mutex<Vec<(Waiting, Waker)>>>,
}

impl Notify {
    pub fn new() -> Self {
        Notify {
            waiting: Default::default(),
        }
    }

    pub fn notify_waiters(&self) {
        let mut waiting = self.waiting.lock();
        for (w, waker) in waiting.drain(..) {
            // Mark as notified before waking
            w.notified.store(true, atomic::Ordering::SeqCst);
            waker.wake();
        }
    }

    pub fn notified(&self) -> Waiting {
        Waiting {
            notify: self.clone(),
            notified: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[must_use]
pub struct Waiting {
    notify: Notify,
    notified: Arc<AtomicBool>,
}

impl Future for Waiting {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.notified.load(atomic::Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            // Wait until we get notified
            let notify = self.notify.clone();
            let notified = self.notified.clone();
            self.notify
                .waiting
                .lock()
                .push((Waiting { notify, notified }, cx.waker().clone()));
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::async_rt::instant::Instant;
    use crate::async_rt::{sleep, spawn};
    use std::time::Duration;

    #[macros::async_test_priv]
    async fn test_notify_from_task() {
        let start = Instant::now();
        let notify = Notify::new();
        let notify_cp = notify.clone();
        spawn(async move {
            sleep(Duration::from_secs(3)).await;
            notify_cp.notify_waiters();
        });

        notify.notified().await;
        assert_eq!(start.elapsed(), Duration::from_secs(3));
    }

    #[macros::async_test_priv]
    async fn test_notify_already_notified() {
        let start = Instant::now();
        let notify = Notify::new();

        let notify_cp = notify.clone();
        let task = spawn(async move {
            sleep(Duration::from_secs(3)).await;
            notify_cp.notify_waiters();
            notify_cp.notify_waiters();
            sleep(Duration::from_secs(3)).await;
            notify_cp.notify_waiters();
        });

        notify.notified().await;
        assert_eq!(start.elapsed(), Duration::from_secs(3));
        task.await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_secs(6));
    }
}

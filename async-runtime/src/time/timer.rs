use crate::rt::RtInner;
use parking_lot::Mutex;
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::task::{Context, Poll};
use std::time::Instant as StdInstant;

pub struct Timer {
    id: u64,
    rt: Arc<RtInner>,
    deadline: StdInstant,
    currently_pending: Mutex<Option<Arc<PendingTimer>>>,
}

impl Timer {
    pub(crate) fn new(rt: Arc<RtInner>, deadline: StdInstant) -> Self {
        Self {
            id: rt.get_next_id(),
            rt,
            deadline,
            currently_pending: Mutex::default(),
        }
    }
}

impl Timer {
    pub fn reset(mut self: Pin<&mut Self>, deadline: StdInstant) {
        // Update timer
        self.deadline = deadline;
        let pending = Arc::new(PendingTimer {
            timer_id: self.id,
            elapsed_at: self.deadline,
            handler: PendingTimerHandler::wake_waiting_tasks(),
        });
        let previously_pending = self.currently_pending.lock().replace(pending.clone());

        // Enqueue pending timer, so we get woken once we reach the deadline
        self.rt.pending_timers.lock().push(pending.clone());

        // Mark the previously pending timer as ignored, since it no longer should wake anything
        if let Some(previously_pending) = previously_pending {
            previously_pending.handler.set_ignore();
        }
    }
}

impl Future for Timer {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if *self.rt.now.lock() >= self.deadline {
            Poll::Ready(())
        } else {
            let pending = Arc::new(PendingTimer {
                timer_id: self.id,
                elapsed_at: self.deadline,
                handler: PendingTimerHandler::wake_waiting_tasks(),
            });
            *self.currently_pending.lock() = Some(pending.clone());
            self.rt.pending_timers.lock().push(pending);

            self.rt
                .wakers_by_timer_id
                .lock()
                .entry(self.id)
                .or_default()
                .push(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if let Some(pending) = self.currently_pending.lock().as_mut() {
            pending.handler.set_cancel_waiting_tasks();
        }
    }
}

impl Debug for Timer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "timer")
    }
}

pub enum PendingTimerHandlerEnum {
    WakeWaitingTasks,
    Ignore,
    CancelWaitingTasks,
}

pub struct PendingTimerHandler(AtomicU64);

impl PendingTimerHandler {
    pub fn wake_waiting_tasks() -> Self {
        Self(AtomicU64::from(0))
    }

    pub fn set_ignore(&self) {
        self.0.store(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn set_cancel_waiting_tasks(&self) {
        self.0.store(2, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn as_enum(&self) -> PendingTimerHandlerEnum {
        match self.0.load(std::sync::atomic::Ordering::SeqCst) {
            0 => PendingTimerHandlerEnum::WakeWaitingTasks,
            1 => PendingTimerHandlerEnum::Ignore,
            2 => PendingTimerHandlerEnum::CancelWaitingTasks,
            _ => unreachable!(),
        }
    }
}

pub struct PendingTimer {
    pub(crate) timer_id: u64,
    pub(crate) elapsed_at: StdInstant,
    pub(crate) handler: PendingTimerHandler,
}

impl Eq for PendingTimer {}

impl PartialEq<Self> for PendingTimer {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl PartialOrd<Self> for PendingTimer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingTimer {
    fn cmp(&self, other: &Self) -> Ordering {
        other.elapsed_at.cmp(&self.elapsed_at)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::time::instant::Instant;
    use crate::time::sleep;
    use std::task::ready;
    use std::time::Duration;

    #[test]
    fn test_pending_timer_ord_descending() {
        let now = StdInstant::now();
        let timer1 = PendingTimer {
            timer_id: 0,
            elapsed_at: now,
            handler: PendingTimerHandler::wake_waiting_tasks(),
        };
        let timer2 = PendingTimer {
            timer_id: 1,
            elapsed_at: now + Duration::from_secs(5),
            handler: PendingTimerHandler::wake_waiting_tasks(),
        };

        assert!(timer1 > timer2);
    }

    #[crate::test_priv]
    async fn test_timer_with_reset() {
        struct DoubleTimerFuture {
            reset_applied: bool,
            wait: Duration,
            timer: Pin<Box<Timer>>,
        }

        impl DoubleTimerFuture {
            fn new(duration: Duration) -> Self {
                Self {
                    reset_applied: false,
                    wait: duration,
                    timer: Box::pin(sleep(duration)),
                }
            }
        }

        impl Future for DoubleTimerFuture {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                ready!(self.timer.as_mut().poll(cx));

                if self.reset_applied {
                    Poll::Ready(())
                } else {
                    let wait = self.wait;
                    self.timer.as_mut().reset(Instant::now().0 + wait);
                    self.reset_applied = true;
                    Poll::Pending
                }
            }
        }

        let before = Instant::now();
        DoubleTimerFuture::new(Duration::from_secs(2)).await;
        assert_eq!(before.elapsed(), Duration::from_secs(4));
    }
}

use crate::async_rt::RtInner;
use quinn::AsyncTimer;
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant as StdInstant;

pub(super) struct Timer {
    id: u64,
    rt: Arc<RtInner>,
    deadline: StdInstant,
}

impl Timer {
    pub(super) fn new(rt: Arc<RtInner>, deadline: StdInstant) -> Self {
        Self {
            id: rt.get_next_id(),
            rt,
            deadline,
        }
    }
}

impl AsyncTimer for Timer {
    fn reset(mut self: Pin<&mut Self>, i: StdInstant) {
        self.deadline = i;
        self.rt.blocked_timers.lock().push(BlockedTimer {
            timer_id: self.id,
            elapsed_at: self.deadline,
        }.into());
    }

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        if *self.rt.now.lock() >= self.deadline {
            Poll::Ready(())
        } else {
            self.rt.blocked_timers.lock().push(BlockedTimer {
                timer_id: self.id,
                elapsed_at: self.deadline,
            }.into());
            self.rt.wakers_by_timer_id.lock().entry(self.id).or_default().push(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Debug for Timer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "timer")
    }
}

#[derive(Clone)]
pub struct BlockedTimer {
    #[allow(dead_code)]
    pub(super) timer_id: u64,
    pub(super) elapsed_at: StdInstant,
}

impl Eq for BlockedTimer {}

impl PartialEq<Self> for BlockedTimer {
    fn eq(&self, other: &Self) -> bool {
        self.elapsed_at == other.elapsed_at
    }
}

impl PartialOrd<Self> for BlockedTimer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockedTimer {
    fn cmp(&self, other: &Self) -> Ordering {
        other.elapsed_at.cmp(&self.elapsed_at)
    }
}

#[must_use]
pub struct AsyncTimerFuture {
    timer: Pin<Box<dyn AsyncTimer>>,
}

impl Debug for AsyncTimerFuture {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "async timer")
    }
}

impl AsyncTimer for AsyncTimerFuture {
    fn reset(mut self: Pin<&mut Self>, i: StdInstant) {
        self.timer.as_mut().reset(i);
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        AsyncTimer::poll(self.timer.as_mut(), cx)
    }
}

impl Future for AsyncTimerFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.timer.as_mut().poll(cx)
    }
}

impl AsyncTimerFuture {
    pub fn new(timer: Pin<Box<dyn AsyncTimer>>) -> Self {
        Self { timer }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::async_rt::instant::Instant;
    use crate::async_rt::sleep;
    use std::task::ready;
    use std::time::Duration;

    #[macros::async_test_priv]
    async fn test_timer_with_reset() {
        struct DoubleTimerFuture {
            reset_applied: bool,
            wait: Duration,
            timer: Pin<Box<dyn AsyncTimer>>,
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

use futures::channel::oneshot::Canceled;
use futures::{FutureExt, select};
use instant::Instant;
use parking_lot::Mutex;
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime};
use std::cell::RefCell;
use std::cmp;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::fmt::{Debug, Formatter};
use std::net::UdpSocket;
use std::pin::{Pin, pin};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, atomic};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant as StdInstant};
use timer::{AsyncTimerFuture, BlockedTimer, Timer};

pub mod cancellation;
pub mod instant;
pub mod notify;
pub mod timer;

pub struct JoinHandle<T> {
    rx: futures::channel::oneshot::Receiver<T>,
}

impl<T> Future for JoinHandle<T> {
    type Output = anyhow::Result<T, Canceled>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.rx.poll_unpin(cx)
    }
}

pub fn spawn<T: Send + 'static>(f: impl Future<Output = T> + Send + 'static) -> JoinHandle<T> {
    let rt = Rt::active();
    let (tx, rx) = futures::channel::oneshot::channel();
    rt.spawn(Box::pin(async move {
        tx.send(f.await).ok();
    }));

    JoinHandle { rx }
}

pub fn sleep(duration: Duration) -> AsyncTimerFuture {
    Rt::active().sleep(duration)
}

pub fn sleep_until(instant: Instant) -> AsyncTimerFuture {
    Rt::active().sleep_until(instant)
}

pub async fn timeout<F>(duration: Duration, mut future: F) -> Result<F::Output, ()>
where
    F: Future,
{
    let future = pin!(future);
    let timer = sleep(duration);
    select! {
        output = future.fuse() => Ok(output),
        _ = timer.fuse() => Err(()),
    }
}

#[derive(Clone)]
pub struct Rt {
    inner: Arc<RtInner>,
}

struct RtInner {
    now: Mutex<StdInstant>,
    next_task_id: AtomicU64,
    ready_to_poll_tasks: Mutex<VecDeque<Task>>,
    blocked_timers: Mutex<BinaryHeap<Arc<BlockedTimer>>>,
    wakers_by_timer_id: Mutex<HashMap<u64, Vec<Waker>>>,
    blocked_tasks: Mutex<HashMap<u64, Task>>,
}

impl RtInner {
    fn get_next_id(&self) -> u64 {
        self.next_task_id.fetch_add(1, atomic::Ordering::SeqCst)
    }
}

impl Debug for Rt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rt")
    }
}

impl Runtime for Rt {
    fn new_timer(&self, deadline: StdInstant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(Timer::new(self.inner.clone(), deadline))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner
            .ready_to_poll_tasks
            .lock()
            .push_back(Task { future });
    }

    fn wrap_udp_socket(&self, _: UdpSocket) -> std::io::Result<Arc<dyn AsyncUdpSocket>> {
        unimplemented!("not necessary for quinn-workbench")
    }

    fn now(&self) -> StdInstant {
        *self.inner.now.lock()
    }
}

thread_local! {
    static ACTIVE_RT: RefCell<Option<Rt>> = const { RefCell::new(None) };
}

impl Rt {
    pub fn active() -> Rt {
        let maybe_rt = ACTIVE_RT.with_borrow(Option::clone);
        match maybe_rt {
            Some(rt) => rt,
            None => panic!("async runtime is not active in the current thread"),
        }
    }

    fn register_active(&self) {
        let previously_registered = ACTIVE_RT.replace(Some(self.clone()));
        if previously_registered.is_some() {
            panic!("Called `Rt::block_on` inside an active `Rt::block_on`");
        }
    }

    fn unregister_active(&self) {
        ACTIVE_RT.set(None);
    }

    pub fn new() -> Self {
        let now = StdInstant::now();
        Self {
            inner: Arc::new(RtInner {
                now: Mutex::new(now),
                next_task_id: Default::default(),
                ready_to_poll_tasks: Default::default(),
                blocked_timers: Default::default(),
                wakers_by_timer_id: Default::default(),
                blocked_tasks: Default::default(),
            }),
        }
    }

    pub fn sleep(&self, duration: Duration) -> AsyncTimerFuture {
        let deadline = self.now() + duration;
        AsyncTimerFuture::new(self.new_timer(deadline))
    }

    pub fn sleep_until(&self, deadline: Instant) -> AsyncTimerFuture {
        let deadline = cmp::max(deadline.0, self.now());
        AsyncTimerFuture::new(self.new_timer(deadline))
    }

    pub fn block_on<T>(&self, mut f: impl Future<Output = T>) -> T {
        self.register_active();

        let mut f = pin!(f);
        let ready = loop {
            // Poll any tasks that are ready
            loop {
                let Some(mut task) = self.inner.ready_to_poll_tasks.lock().pop_front() else {
                    break;
                };

                let task_id = self.inner.get_next_id();
                let waker = Arc::new(waker::TaskWaker::new(self.inner.clone(), task_id));
                let waker = waker.into();
                let mut cx = Context::from_waker(&waker);
                match task.future.as_mut().poll(&mut cx) {
                    Poll::Ready(()) => {
                        // Task is done, nothing else to do
                    }
                    Poll::Pending => {
                        // Task is pending, so let's mark it as blocked
                        self.inner.blocked_tasks.lock().insert(task_id, task);
                    }
                }
            }

            // Use a noop waker here, since we don't need to wake the runtime's main thread
            let mut cx = Context::from_waker(Waker::noop());
            if let Poll::Ready(value) = f.as_mut().poll(&mut cx) {
                break value;
            }

            // If we have reached this point, the future is pending. If there's nothing to do (i.e.
            // no tasks to poll), advance timers until we do have something to do
            if self.inner.ready_to_poll_tasks.lock().is_empty() {
                // Advance the timer, but refuse to "advance" into the past
                let timer = match self.inner.blocked_timers.lock().pop() {
                    Some(timer) => timer,
                    None => panic!(
                        "`block_on` is stuck: the future is pending and there is nothing else to do, nor timers waiting to advance)"
                    ),
                };

                assert!(*self.inner.now.lock() <= timer.elapsed_at);
                *self.inner.now.lock() = timer.elapsed_at;

                // TODO: possible optimization: only wake if the original timer did actually elapse
                // (now we sometimes wake even though the timer hasn't elapsed, because of resets)

                // Wake the tasks (if any) that were waiting on this timer
                let wakers = self.inner.wakers_by_timer_id.lock().remove(&timer.timer_id).unwrap_or_default();
                for waker in wakers {
                    waker.clone().wake();
                }
            }
        };

        self.unregister_active();
        ready
    }
}

mod waker {
    use super::*;
    use std::task::Wake;

    #[derive(Clone)]
    pub struct TaskWaker {
        task_id: u64,
        rt: Arc<RtInner>,
    }

    impl TaskWaker {
        pub fn new(rt: Arc<RtInner>, task_id: u64) -> Self {
            Self { rt, task_id }
        }
    }

    impl Wake for TaskWaker {
        fn wake(self: Arc<Self>) {
            let Some(task) = self.rt.blocked_tasks.lock().remove(&self.task_id) else {
                // Already woken, nothing to do here
                return;
            };

            self.rt.ready_to_poll_tasks.lock().push_back(task);
        }
    }
}

struct Task {
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
}

#[cfg(test)]
mod test {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use std::time::Duration;

    #[test]
    fn blocked_timer_ord_descending() {
        let now = StdInstant::now();
        let timer1 = BlockedTimer {
            timer_id: 0,
            elapsed_at: now,
            waker: None,
        };
        let timer2 = BlockedTimer {
            timer_id: 1,
            elapsed_at: now + Duration::from_secs(5),
            waker: None,
        };

        assert!(timer1 > timer2);
    }

    #[test]
    fn blocked_timer_ord_min_heap() {
        let rt = Rt::new();
        let now = StdInstant::now();
        rt.inner.blocked_timers.lock().push(BlockedTimer {
            timer_id: 0,
            elapsed_at: now,
            waker: None,
        });
        rt.inner.blocked_timers.lock().push(BlockedTimer {
            timer_id: 1,
            elapsed_at: now + Duration::from_secs(5),
            waker: None,
        });

        assert_eq!(rt.inner.blocked_timers.lock().pop().unwrap().timer_id, 0);
    }

    #[test]
    fn test_waiting_timers_ordered_correctly() {
        let rt = Rt::new();
        rt.block_on(async {
            let rt_cp = rt.clone();
            rt.spawn(Box::pin(async move {
                rt_cp.sleep(Duration::from_secs(5)).await;
            }));

            let now = rt.now();
            rt.sleep(Duration::from_secs(10)).await;
            let later = rt.now();
            assert_eq!(Duration::from_secs(10), later - now);
        });
    }

    #[macros::async_test_priv]
    async fn test_timeout_elapsed() {
        let start = Instant::now();
        let result = timeout(Duration::from_secs(10), async move {
            sleep(Duration::from_secs(15)).await
        })
        .await;

        assert!(result.is_err());
        assert_eq!(start.elapsed(), Duration::from_secs(10));
    }

    #[macros::async_test_priv]
    async fn test_timeout_not_elapsed() {
        let start = Instant::now();
        let result = timeout(Duration::from_secs(10), async move {
            sleep(Duration::from_secs(5)).await
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(start.elapsed(), Duration::from_secs(5));
    }

    #[macros::async_test_priv]
    async fn test_channels() {
        let (mut tx, mut rx) = futures::channel::mpsc::channel(42);
        spawn(async move {
            tx.send(1234).await.unwrap();
        });

        let received = rx.next().await.unwrap();
        assert_eq!(received, 1234);
    }
}

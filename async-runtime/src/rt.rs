use crate::time::Instant;
use crate::time::timer::{PendingTimer, PendingTimerHandlerEnum, Timer};
use futures::FutureExt;
use futures::channel::oneshot::Canceled;
use parking_lot::Mutex;
use std::cell::RefCell;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::fmt::{Debug, Formatter};
use std::pin::{Pin, pin};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, atomic};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant as StdInstant};

thread_local! {
    static ACTIVE_RT: RefCell<Option<Rt>> = const { RefCell::new(None) };
}

#[derive(Clone)]
pub struct Rt {
    inner: Arc<RtInner>,
}

pub(crate) struct RtInner {
    // Time-keeping
    pub(crate) now: Mutex<std::time::Instant>,
    pub(crate) last_time_jump_to: Mutex<std::time::Instant>,
    pub(crate) timer_granularity: Duration,

    // Scheduling
    pub(crate) next_task_id: AtomicU64,
    pub(crate) ready_to_poll_tasks: Mutex<VecDeque<Task>>,
    pub(crate) pending_timers: Mutex<BinaryHeap<Arc<PendingTimer>>>,
    pub(crate) wakers_by_timer_id: Mutex<HashMap<u64, Vec<Waker>>>,
    pub(crate) blocked_tasks: Mutex<HashMap<u64, Task>>,
}

impl RtInner {
    pub(crate) fn get_next_id(&self) -> u64 {
        self.next_task_id.fetch_add(1, atomic::Ordering::SeqCst)
    }
}

impl Debug for Rt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rt")
    }
}

impl Default for Rt {
    fn default() -> Self {
        Self::new(Duration::from_secs(0))
    }
}

impl Rt {
    pub fn new(timer_granularity: Duration) -> Self {
        let now = StdInstant::now();
        Self {
            inner: Arc::new(RtInner {
                now: Mutex::new(now),
                last_time_jump_to: Mutex::new(now),
                timer_granularity,
                next_task_id: Default::default(),
                ready_to_poll_tasks: Default::default(),
                pending_timers: Default::default(),
                wakers_by_timer_id: Default::default(),
                blocked_tasks: Default::default(),
            }),
        }
    }

    pub fn new_timer(&self, deadline: StdInstant) -> Timer {
        Timer::new(self.inner.clone(), deadline)
    }

    pub fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner
            .ready_to_poll_tasks
            .lock()
            .push_back(Task { future });
    }

    pub fn now(&self) -> std::time::Instant {
        *self.inner.now.lock()
    }

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

    pub fn sleep(&self, duration: Duration) -> Timer {
        let deadline = self.now() + duration;
        self.new_timer(deadline)
    }

    pub fn sleep_until(&self, deadline: Instant) -> Timer {
        self.new_timer(deadline.0)
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

                // Poll the next task in the queue
                let task_id = self.inner.get_next_id();
                let waker = Arc::new(waker::TaskWaker::new(self.inner.clone(), task_id));
                let cx_waker = waker.clone().into_waker();
                let mut cx = Context::from_waker(&cx_waker);
                match task.future.as_mut().poll(&mut cx) {
                    Poll::Ready(()) => {
                        // Task is done, nothing else to do
                    }
                    Poll::Pending => {
                        if waker.woken() {
                            // Task is pending, but it was woken while polling
                            self.inner.ready_to_poll_tasks.lock().push_back(task);
                        } else {
                            // Task is pending and is waiting to be woken
                            self.inner.blocked_tasks.lock().insert(task_id, task);
                        }
                    }
                }
            }

            // We are polling the main task on every loop iteration, so we don't need to use a real
            // waker
            let mut cx = Context::from_waker(Waker::noop());
            if let Poll::Ready(value) = f.as_mut().poll(&mut cx) {
                // We are done as soon as the main task is ready
                break value;
            }

            if self.inner.ready_to_poll_tasks.lock().is_empty() {
                // There are no ready-to-poll tasks at this point, so let's advance the time
                self.advance_time();
            }
        };

        self.unregister_active();
        ready
    }

    fn advance_time(&self) {
        loop {
            let blocked_tasks = self.inner.blocked_tasks.lock().len();
            let timer = match self.inner.pending_timers.lock().pop() {
                // There's a pending timer, so we can advance!
                Some(timer) => timer,
                // No pending timers, so advancing time won't let us make progress
                None => panic!(
                    "`block_on` is stuck: the task's future is pending and there is nothing else to do, nor timers waiting to advance. There are {blocked_tasks} blocked tasks."
                ),
            };

            let at_least_one_task_unblocked = self.handle_timer_elapsed(timer);
            if at_least_one_task_unblocked {
                // We made progress, so we can stop handling timers. However, if the next timer is
                // ready, we will handle it right away.
                let next_timer_ready = self
                    .inner
                    .pending_timers
                    .lock()
                    .peek()
                    .is_some_and(|t| t.elapsed_at <= *self.inner.now.lock());
                if !next_timer_ready {
                    break;
                }
            }
        }
    }

    fn handle_timer_elapsed(&self, timer: Arc<PendingTimer>) -> bool {
        match timer.handler.as_enum() {
            PendingTimerHandlerEnum::WakeWaitingTasks => {
                let now = *self.inner.now.lock();

                if now < timer.elapsed_at {
                    if self.inner.timer_granularity.is_zero() {
                        // Advance to the exact moment when the timer elapsed
                        *self.inner.now.lock() = timer.elapsed_at;
                    } else {
                        // Advance an exact multiple of `timer_granularity` since the last time jump
                        let diff = timer.elapsed_at - *self.inner.last_time_jump_to.lock();
                        let elapsed_intervals = (self.inner.timer_granularity.as_secs_f64()
                            / diff.as_secs_f64())
                        .ceil() as u32;
                        let jump_duration = self.inner.timer_granularity * elapsed_intervals;
                        *self.inner.now.lock() = now + jump_duration;
                        *self.inner.last_time_jump_to.lock() = now + jump_duration;
                    }
                }

                // Wake all waiting tasks
                let wakers = self
                    .inner
                    .wakers_by_timer_id
                    .lock()
                    .remove(&timer.timer_id)
                    .unwrap_or_default();
                for waker in wakers {
                    waker.wake();
                }

                // At least one task was unblocked
                true
            }
            PendingTimerHandlerEnum::Ignore => {
                // No tasks unblocked
                false
            }
            PendingTimerHandlerEnum::CancelWaitingTasks => {
                let wakers = self
                    .inner
                    .wakers_by_timer_id
                    .lock()
                    .remove(&timer.timer_id)
                    .unwrap_or_default();

                // Cancel waiting tasks
                for waker in wakers {
                    let is_noop_waker = waker.data().is_null();
                    if is_noop_waker {
                        continue;
                    }

                    // Obtain the task id from the waker
                    let waker: Arc<waker::TaskWaker> = unsafe { Arc::from_raw(waker.data() as _) };
                    let task_id = waker.task_id();
                    std::mem::forget(waker);

                    // Remove blocked task
                    self.inner.blocked_tasks.lock().remove(&task_id);
                }

                // No tasks unblocked, only cancelled
                false
            }
        }
    }
}

pub struct JoinHandle<T> {
    pub(crate) rx: futures::channel::oneshot::Receiver<T>,
}

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, Canceled>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.rx.poll_unpin(cx)
    }
}

pub(crate) mod waker {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{RawWaker, RawWakerVTable};

    #[derive(Clone)]
    pub struct TaskWaker {
        task_id: u64,
        rt: Arc<RtInner>,
        woken: Arc<AtomicBool>,
    }

    impl TaskWaker {
        pub fn new(rt: Arc<RtInner>, task_id: u64) -> Self {
            Self {
                rt,
                task_id,
                woken: Arc::new(false.into()),
            }
        }

        fn wake(self: Arc<Self>) {
            self.woken.store(true, Ordering::SeqCst);

            let Some(blocked) = self.rt.blocked_tasks.lock().remove(&self.task_id) else {
                // Already woken, nothing to do here
                return;
            };

            self.rt.ready_to_poll_tasks.lock().push_back(blocked);
        }

        pub fn woken(&self) -> bool {
            self.woken.load(Ordering::SeqCst)
        }

        pub fn task_id(&self) -> u64 {
            self.task_id
        }

        pub fn into_waker(self: Arc<Self>) -> Waker {
            unsafe { Waker::from_raw(RawWaker::new(Arc::into_raw(self) as _, &VTABLE)) }
        }
    }

    impl Drop for TaskWaker {
        fn drop(&mut self) {
            // The task will never be woken, so let's garbage-collect it
            self.rt.blocked_tasks.lock().remove(&self.task_id);
        }
    }

    pub static VTABLE: RawWakerVTable = RawWakerVTable::new(
        // Clone
        |data| {
            let arc: Arc<TaskWaker> = unsafe { Arc::from_raw(data as _) };
            let cloned = arc.clone();
            std::mem::forget(arc);

            RawWaker::new(Arc::into_raw(cloned) as _, &VTABLE)
        },
        // Wake
        |data| {
            let arc: Arc<TaskWaker> = unsafe { Arc::from_raw(data as _) };
            arc.wake();
        },
        // Wake by ref
        |data| {
            let arc: Arc<TaskWaker> = unsafe { Arc::from_raw(data as _) };
            let cloned = arc.clone();
            std::mem::forget(arc);

            cloned.wake();
        },
        // Drop
        |data| {
            let _arc: Arc<TaskWaker> = unsafe { Arc::from_raw(data as _) };
        },
    );
}

pub(crate) struct Task {
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::time::{sleep, timeout};
    use futures::{SinkExt, StreamExt};
    use parking_lot::Mutex;
    use std::collections::VecDeque;
    use std::future::{self, Future};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;

    #[test]
    fn test_waiting_timers_ordered_correctly() {
        let rt = Rt::default();
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

    #[crate::test_priv]
    async fn test_timeout_elapsed() {
        let start = Instant::now();
        let result = timeout(Duration::from_secs(10), async move {
            sleep(Duration::from_secs(15)).await
        })
        .await;

        assert!(result.is_err());
        assert_eq!(start.elapsed(), Duration::from_secs(10));
    }

    #[crate::test_priv]
    async fn test_timeout_not_elapsed() {
        let start = Instant::now();
        let result = timeout(Duration::from_secs(10), async move {
            sleep(Duration::from_secs(5)).await
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(start.elapsed(), Duration::from_secs(5));
    }

    #[crate::test_priv]
    async fn test_channels() {
        let (mut tx, mut rx) = futures::channel::mpsc::channel(42);
        crate::spawn(async move {
            tx.send(1234).await.unwrap();
        });

        let received = rx.next().await.unwrap();
        assert_eq!(received, 1234);
    }

    #[test]
    fn test_select_timer() {
        let rt = Rt::default();
        rt.block_on(async {
            for _ in 0..100 {
                let result;
                futures::select_biased! {
                    _ = sleep(Duration::from_secs(4)).fuse() => result = Some(42),
                    _ = sleep(Duration::from_secs(1)).fuse() => result = Some(1234),
                }

                assert_eq!(result, Some(1234));
            }
        });
    }

    #[test]
    fn test_select_task() {
        let rt = Rt::default();
        rt.block_on(async {
            for _ in 0..100 {
                let t1 = async {
                    sleep(Duration::from_secs(4)).await;
                };
                let t2 = async {
                    sleep(Duration::from_secs(1)).await;
                };

                let result;
                futures::select_biased! {
                    _ = t1.fuse() => result = Some(42),
                    _ = t2.fuse() => result = Some(1234),
                }

                assert_eq!(result, Some(1234));
            }
        });
    }

    #[test]
    #[should_panic]
    fn test_block_on_stuck_panics() {
        let rt = Rt::default();
        rt.block_on(async {
            // A future that never completes and has no timers
            future::pending::<()>().await;
        });
    }

    #[test]
    fn test_multiple_spawned_tasks_timer_order() {
        let rt = Rt::default();
        let completion_order = Arc::new(Mutex::new(VecDeque::new()));

        rt.block_on(async {
            let order_clone = completion_order.clone();
            rt.spawn(Box::pin(async move {
                sleep(Duration::from_millis(200)).await;
                order_clone.lock().push_back(2);
            }));

            let order_clone = completion_order.clone();
            rt.spawn(Box::pin(async move {
                sleep(Duration::from_millis(100)).await;
                order_clone.lock().push_back(1);
            }));

            let order_clone = completion_order.clone();
            rt.spawn(Box::pin(async move {
                sleep(Duration::from_millis(300)).await;
                order_clone.lock().push_back(3);
            }));

            // Wait for all tasks to complete
            sleep(Duration::from_secs(1)).await;
        });

        let guard = completion_order.lock();
        assert_eq!(guard.len(), 3, "Not all tasks completed");
        assert_eq!(guard[0], 1);
        assert_eq!(guard[1], 2);
        assert_eq!(guard[2], 3);
    }

    #[test]
    fn test_nested_spawn() {
        let rt = Rt::default();
        let inner_task_completed = Arc::new(AtomicBool::new(false));

        rt.block_on(async {
            let rt_clone = rt.clone();
            let flag_clone = inner_task_completed.clone();
            rt.spawn(Box::pin(async move {
                sleep(Duration::from_millis(50)).await;
                rt_clone.spawn(Box::pin(async move {
                    sleep(Duration::from_millis(50)).await;
                    flag_clone.store(true, Ordering::SeqCst);
                }));
            }));

            // Wait for inner task to complete
            sleep(Duration::from_millis(101)).await;
        });
        assert!(
            inner_task_completed.load(Ordering::SeqCst),
            "Nested spawned task did not complete"
        );
    }

    #[test]
    fn test_many_tasks() {
        const NUM_TASKS: usize = 1000;
        let rt = Rt::default();
        let completed_count = Arc::new(AtomicUsize::new(0));

        rt.block_on(async {
            for i in 0..NUM_TASKS {
                let rt_clone = rt.clone();
                let count_clone = completed_count.clone();
                rt.spawn(Box::pin(async move {
                    // Vary sleep times slightly to mix things up
                    rt_clone.sleep(Duration::from_millis(i as u64 % 100)).await;
                    count_clone.fetch_add(1, Ordering::SeqCst);
                }));
            }

            // Wait for everything to complete
            sleep(Duration::from_secs(1234)).await;
        });

        assert_eq!(
            completed_count.load(Ordering::SeqCst),
            NUM_TASKS,
            "Not all of the many tasks completed"
        );
    }

    #[test]
    #[should_panic(expected = "Spawned task panicked")]
    fn test_spawned_task_panics() {
        let rt = Rt::default();
        rt.block_on(async {
            rt.spawn(Box::pin(async {
                sleep(Duration::from_millis(10)).await;
                panic!("Spawned task panicked");
            }));

            // Wait for the spawned task to execute
            sleep(Duration::from_secs(42)).await;
        });
    }

    #[test]
    fn test_zero_duration_sleep() {
        let rt = Rt::default();
        let task_completed = Arc::new(AtomicBool::new(false));
        let flag_clone = task_completed.clone();

        rt.block_on(async {
            let rt_clone = rt.clone();
            rt.spawn(Box::pin(async move {
                rt_clone.sleep(Duration::from_secs(0)).await;
                flag_clone.store(true, Ordering::SeqCst);
            }));

            // At least one await is necessary for the spawned future to run
            sleep(Duration::from_nanos(1)).await;
        });
        assert!(
            task_completed.load(Ordering::SeqCst),
            "Task with zero duration sleep did not complete"
        );
    }

    #[test]
    fn test_main_future_completes_before_spawned_tasks() {
        let rt = Rt::default();
        let done_tasks = Arc::new(Mutex::new(Vec::new()));

        rt.block_on(async {
            let rt_clone = rt.clone();
            let done_tasks_clone = done_tasks.clone();
            rt.spawn(Box::pin(async move {
                // This task will take longer than the main future and won't be polled to completion
                rt_clone.sleep(Duration::from_millis(200)).await;
                done_tasks_clone.lock().push("inner");
            }));

            done_tasks.lock().push("main");
        });

        let done_tasks = done_tasks.lock();
        assert_eq!(&*done_tasks[0], "main");
        assert_eq!(done_tasks.len(), 1);
    }

    struct WakyTask {
        wakes: Arc<AtomicUsize>,
        max_wakes: usize,
        rt: Rt,
    }

    impl Future for WakyTask {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let current_wakes = self.wakes.fetch_add(1, Ordering::SeqCst);
            if current_wakes >= self.max_wakes {
                Poll::Ready(())
            } else {
                // Don't sleep on last iteration
                if current_wakes < self.max_wakes - 1 {
                    let waker = cx.waker().clone();
                    let rt = self.rt.clone();

                    // Wake this task up after a short delay, to ensure the task actually
                    // goes to sleep
                    self.rt.spawn(Box::pin(async move {
                        rt.sleep(Duration::from_millis(10)).await;
                        waker.wake();
                    }));
                } else {
                    cx.waker().wake_by_ref();
                }

                Poll::Pending
            }
        }
    }

    #[test]
    fn test_task_repeatedly_wakes_itself() {
        let rt = Rt::default();
        let wakes = Arc::new(AtomicUsize::new(0));
        const MAX_WAKES: usize = 5;

        rt.block_on(async {
            let rt_clone = rt.clone();
            let wakes = wakes.clone();
            rt.spawn(Box::pin(WakyTask {
                wakes,
                max_wakes: MAX_WAKES,
                rt: rt_clone,
            }));

            // Wait for everything to complete
            sleep(Duration::from_secs(42)).await;
        });

        assert_eq!(
            wakes.load(Ordering::SeqCst),
            MAX_WAKES + 1,
            "Task was not polled the expected number of times"
        );
    }
}

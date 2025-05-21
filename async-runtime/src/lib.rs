pub use async_runtime_macros::test;

#[cfg(test)]
use async_runtime_macros::test_priv;

pub mod rt;
pub mod time;

pub fn spawn<T: Send + 'static>(f: impl Future<Output = T> + Send + 'static) -> rt::JoinHandle<T> {
    let rt = rt::Rt::active();
    let (tx, rx) = futures::channel::oneshot::channel();
    rt.spawn(Box::pin(async move {
        tx.send(f.await).ok();
    }));

    rt::JoinHandle { rx }
}

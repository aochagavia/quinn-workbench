use cfg_if::cfg_if;
use quinn::Runtime;
use std::sync::Arc;

#[cfg(all(feature = "rt-custom", feature = "rt-tokio"))]
compile_error!("Feature 'rt-custom' and 'rt-tokio' cannot be enabled at the same time.");

cfg_if! {
    if #[cfg(feature = "rt-custom")] {
        pub use async_runtime::time;
        pub use async_runtime::spawn;
        pub use async_runtime::time::timer::Timer;
        pub use async_runtime::rt::JoinHandle;
        use crate::quinn_interop::RtAdapter;

        pub fn new_rt() -> async_runtime::rt::Rt {
            async_runtime::rt::Rt::new()
        }

        pub fn active_rt() -> Arc<dyn Runtime> {
            Arc::new(RtAdapter)
        }
    } else if #[cfg(feature = "rt-tokio")] {
        pub use tokio::time;
        pub use tokio::spawn;
        pub use tokio::task::JoinHandle;
        pub use tokio::time::Sleep as Timer;

        pub fn new_rt() -> tokio::runtime::Runtime {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .start_paused(true)
                .build()
                .expect("failed to initialize tokio")
        }

        pub fn active_rt() -> Arc<dyn Runtime> {
            Arc::new(quinn::TokioRuntime)
        }
    }
}

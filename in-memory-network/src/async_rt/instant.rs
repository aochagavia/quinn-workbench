use crate::async_rt::Rt;
use quinn::Runtime;
use std::ops::{Add, Sub};
use std::time::Duration;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[repr(transparent)]
pub struct Instant(pub(super) std::time::Instant);

impl Instant {
    pub fn now() -> Self {
        let now = Rt::active().now();
        Self(now)
    }

    pub fn elapsed(&self) -> Duration {
        Self::now().0 - self.0
    }
}

impl Sub for Instant {
    type Output = Duration;

    fn sub(self, other: Self) -> Self::Output {
        self.0 - other.0
    }
}

impl Add<Duration> for Instant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl<'b> Sub<&'b Instant> for &Instant {
    type Output = Duration;

    fn sub(self, other: &'b Instant) -> Self::Output {
        self.0 - other.0
    }
}

impl Add<Duration> for &Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Self::Output {
        Instant(self.0 + rhs)
    }
}

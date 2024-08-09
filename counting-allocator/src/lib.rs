use std::alloc::{GlobalAlloc, Layout, System as SystemAlloc};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;

pub struct CountingAlloc;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED_PEAK: AtomicUsize = AtomicUsize::new(0);

pub fn get_currently_allocated() -> usize {
    ALLOCATED.load(Relaxed)
}

pub fn get_peak_allocated() -> usize {
    ALLOCATED_PEAK.load(Relaxed)
}

fn track_allocation(size: usize) {
    let prev = ALLOCATED.fetch_add(size, Relaxed);
    let new = prev + size;
    ALLOCATED_PEAK.fetch_max(new, Relaxed);
}

fn track_deallocation(size: usize) {
    let prev = ALLOCATED.fetch_sub(size, Relaxed);

    // Underflow should be impossible
    assert!(prev.checked_sub(size).is_some());

    // Note: no need to do anything with ALLOCATED_PEAK here, since the amount of allocated bytes
    // can only diminish
}

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = SystemAlloc.alloc(layout);
        if !ret.is_null() {
            track_allocation(layout.size());
        }
        ret
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        SystemAlloc.dealloc(ptr, layout);
        track_deallocation(layout.size());
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ret = SystemAlloc.alloc_zeroed(layout);
        if !ret.is_null() {
            track_allocation(layout.size());
        }
        ret
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let ret = SystemAlloc.realloc(ptr, layout, new_size);
        if !ret.is_null() {
            let size_difference = layout.size() as isize - new_size as isize;
            if size_difference > 0 {
                track_deallocation(size_difference as usize);
            } else {
                track_allocation(size_difference.unsigned_abs());
            }
        }
        ret
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_manual() {
        let layout_4_bytes = Layout::for_value(&[0u8; 4]);
        let layout_12_bytes = Layout::for_value(&[0u8; 12]);
        let layout_24_bytes = Layout::for_value(&[0u8; 24]);

        // Alloc 4 bytes
        let ptr = unsafe { CountingAlloc.alloc(layout_4_bytes) };
        assert!(!ptr.is_null());
        assert_eq!(get_currently_allocated(), 4);
        assert_eq!(get_peak_allocated(), 4);

        // Dealloc 4 bytes
        unsafe { CountingAlloc.dealloc(ptr, layout_4_bytes) };
        assert_eq!(get_currently_allocated(), 0);
        assert_eq!(get_peak_allocated(), 4);

        // Alloc 12 bytes
        let ptr = unsafe { CountingAlloc.alloc(layout_12_bytes) };
        assert!(!ptr.is_null());
        assert_eq!(get_currently_allocated(), 12);
        assert_eq!(get_peak_allocated(), 12);

        // Realloc to 4 bytes
        let ptr = unsafe { CountingAlloc.realloc(ptr, layout_12_bytes, 4) };
        assert!(!ptr.is_null());
        assert_eq!(get_currently_allocated(), 4);
        assert_eq!(get_peak_allocated(), 12);

        // Realloc to 24 bytes
        let ptr = unsafe { CountingAlloc.realloc(ptr, layout_4_bytes, 24) };
        assert!(!ptr.is_null());
        assert_eq!(get_currently_allocated(), 24);
        assert_eq!(get_peak_allocated(), 24);

        // Dealloc 24 bytes
        unsafe { CountingAlloc.dealloc(ptr, layout_24_bytes) };
        assert_eq!(get_currently_allocated(), 0);
        assert_eq!(get_peak_allocated(), 24);
    }
}

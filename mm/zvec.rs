// SPDX-License-Identifier: GPL-2.0

//! Toy zpool backend
//!
use core::ptr::{NonNull, copy_nonoverlapping};
use core::sync::atomic::{AtomicU64, Ordering};
use kernel::alloc::{Flags, KBox, KVec, NumaNode};
use kernel::page::PAGE_SHIFT;
use kernel::prelude::*; //{c_void, EINVAL};
use kernel::str::CString;
use kernel::zpool::*;

struct MyZpool {
    name: CString,
    bytes_used: AtomicU64,
}

struct MyZpoolDriver;

impl ZpoolDriver for MyZpoolDriver {
    type Pool = KBox<MyZpool>;

    fn create(name: CString, gfp: Flags) -> Result<KBox<MyZpool>> {
        let my_pool = MyZpool { name, bytes_used: AtomicU64::new(0) };
        let pool = KBox::new(my_pool, gfp)?;

        pr_debug!("Pool {:?} created\n", pool.name);
        Ok(pool)
    }

    fn malloc(pool: &MyZpool, size: usize, _gfp: Flags, _nid: NumaNode) -> Result<ZpoolHandle> {
        let pow = size.next_power_of_two().trailing_zeros().max(6);
        match pow {
            0 => Err(EINVAL),
            m if m > PAGE_SHIFT as u32 => Err(ENOSPC),
            _ => {
                let vec = KVec::<u8>::with_capacity(1 << pow, GFP_KERNEL)?;
                let (ptr, _len, _cap) = vec.into_raw_parts();

                // We assume that kmalloc-64, kmalloc-128 etc. kmem caches will be used for
                // our allocations, so it's actually `1 << pow` bytes that we have consumed.
                pool.bytes_used.fetch_add(1 << pow, Ordering::Relaxed);

                // `kmalloc` guarantees that an allocation of size x*2^n is 2^n aligned.
                // Therefore the 6 lower bits are zeros and we can use these to store `pow`.
                Ok(ZpoolHandle::from_raw(ptr as usize | (pow as usize - 6)))
            }
        }
    }

    unsafe fn free(pool: &MyZpool, handle: ZpoolHandle) {
        let h = handle.as_raw();
        let n = (h & 0x3F) + 6;
        let uptr = h & !0x3F;

        // SAFETY:
        // - we derive `uptr` from handle by zeroing 6 lower bits where we store the power
        //   denominator for the vector capacity. As noted above, the result will be exactly the
        //   pointer to the area allocated by `KVec`. Thus, uptr is a valid pointer pointing to
        //   the vector allocated by `alloc` function above.
        // - 1 << n == capacity and is coming from the first 6 bits of handle.
        let vec = unsafe { KVec::<u8>::from_raw_parts(uptr as *mut u8, 0, 1 << n) };
        drop(vec);
        pool.bytes_used.fetch_sub(1 << n, Ordering::Relaxed);
    }

    unsafe fn read_begin(_pool: &MyZpool, handle: ZpoolHandle) -> NonNull<u8> {
        let uptr = handle.as_raw() & !0x3F;
        // SAFETY:
        // - we derive `uptr` from handle by zeroing 6 lower bits where we store the power
        //   denominator for the vector capacity. As noted above, the result will be exactly the
        //   pointer to the area allocated by `KVec`. Thus, uptr is a valid pointer pointing to
        //   the vector allocated by `alloc` function above.
        unsafe { NonNull::new_unchecked(uptr as *mut u8) }
    }

    unsafe fn read_end(_pool: &MyZpool, _handle: ZpoolHandle, _handle_mem: NonNull<u8>) {}

    unsafe fn write(_p: &MyZpool, handle: ZpoolHandle, handle_mem: NonNull<u8>, mem_len: usize) {
        let uptr = handle.as_raw() & !0x3F;
        // SAFETY:
        // - `handle_mem` is a valid non-null pointer provided by zpool,
        // - `uptr` is derived from handle by zeroing 6 lower bits where we store the power
        //   denominator for the vector capacity. As noted above, the result will be exactly the
        //   pointer to the area allocated by `KVec`. Thus, uptr is a valid pointer pointing to
        //   the vector allocated by `alloc` function above.
        unsafe {
            copy_nonoverlapping(handle_mem.as_ptr().cast(), uptr as *mut c_void, mem_len)
        };
    }

    fn total_pages(pool: &MyZpool) -> u64 {
        pool.bytes_used.load(Ordering::Relaxed) >> PAGE_SHIFT
    }
}

kernel::module_zpool_driver! {
    type: MyZpoolDriver,
    name: "zvec",
    authors: ["Vitaly Wool"],
    description: "Rust Zpool backend playground",
    license: "GPL",
}


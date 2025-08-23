use core::ptr::{NonNull, copy_nonoverlapping};
use core::sync::atomic::{AtomicU64, Ordering};
use kernel::alloc::{Flags, KBox, KVec, NumaNode};
use kernel::page::PAGE_SHIFT;
use kernel::prelude::*; //{c_void, EINVAL};
use kernel::str::CStr;
use kernel::zpool::*;

struct MyZpool {
    name: &'static CStr,
    bytes_used: AtomicU64,
}

struct MyZpoolDriver;

impl ZpoolDriver for MyZpoolDriver {
    type Pool = KBox<MyZpool>;

    fn create(name: &'static CStr, gfp: Flags) -> Result<KBox<MyZpool>> {
        let my_pool = MyZpool { name, bytes_used: AtomicU64::new(0) };
        let pool = KBox::new(my_pool, gfp)?;

        Ok(pool)
    }

    fn destroy(p: KBox<MyZpool>) {
        drop(p);
    }

    fn malloc(pool: &mut MyZpool, size: usize, gfp: Flags, _nid: NumaNode) -> Result<usize> {
        let mut pow: usize = 0;
        for n in 6..=PAGE_SHIFT {
            if size <= 1 << n {
                pow = n;
                break;
            }
        }
        match pow {
            0 => Err(EINVAL),
            _ => {
                let vec = KVec::<u64>::with_capacity(1 << (pow - 3), gfp)?;
                let (ptr, _len, _cap) = vec.into_raw_parts();
                pool.bytes_used.fetch_add(1 << pow, Ordering::Relaxed);
                Ok(ptr as usize | (pow - 6))
            }
        }
    }

    unsafe fn free(pool: &MyZpool, handle: usize) {
        let n = (handle & 0x3F) + 3;
        let uptr = handle & !0x3F;

        // SAFETY:
        // - uptr comes from handle which points to the KVec allocation from `alloc`
        // - size == capacity and is coming from the first 6 bits of handle
        let vec = unsafe { KVec::<u64>::from_raw_parts(uptr as *mut u64, 1 << n, 1 << n) };
        drop(vec);
        pool.bytes_used.fetch_sub(1 << (n + 3), Ordering::Relaxed);
    }

    unsafe fn read_begin(_pool: &MyZpool, handle: usize) -> NonNull<u8> {
        let uptr = handle & !0x3F;
        // SAFETY: uptr points to a memory area allocated by KVec
        unsafe { NonNull::new_unchecked(uptr as *mut u8) }
    }

    unsafe fn read_end(_pool: &MyZpool, _handle: usize, _handle_mem: NonNull<u8>) {}

    unsafe fn write(_p: &MyZpool, handle: usize, handle_mem: NonNull<u8>, mem_len: usize) {
        let uptr = handle & !0x3F;
        // SAFETY: handle_mem is a valid non-null pointer provided by zpool, uptr points to
        // a KVec allocated in `malloc` and is therefore also valid
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


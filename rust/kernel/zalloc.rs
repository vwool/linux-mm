// SPDX-License-Identifier: GPL-2.0

//! Implementation of Rust interface towards zsmalloc API.

use crate::prelude::{c_int, c_uchar, c_uint, c_ulong, c_void, Box, KBox};
use crate::{
    error::Result,
    kernel::alloc::{flags, Flags},
    str::{CStr, CStrExt, CString},
};
use core::ptr::NonNull;
use kernel::alloc::NumaNode;

use crate::pr_info;

/// The Rust representation of zpool handle.
pub struct ZallocHandle(usize);

impl ZallocHandle {
    /// Create `ZallocHandle` from the raw representation.
    pub fn from_raw(h: usize) -> Self {
        Self(h)
    }

    /// Get the raw representation of the handle.
    pub fn as_raw(self) -> usize {
        self.0
    }
}

/// Zalloc API.
///
/// The [`ZallocDriver`] trait serves as an interface for Zalloc drivers implemented in Rust.
/// Such drivers implement memory storage pools in accordance with the zpool API.
///
/// # Example
///
/// A zpool driver implementation which uses KVec of 2**n sizes, n = 6, 7, ..., PAGE_SHIFT.
/// Every zpool object is packed into a KVec that is sufficiently large, and n (the
/// denominator) is saved in the least significant bits of the handle, which is guaranteed
/// to be at least 2**6 aligned by kmalloc.
///
/// ```
/// use core::ptr::{NonNull, copy_nonoverlapping};
/// use core::sync::atomic::{AtomicU64, Ordering};
/// use kernel::alloc::{Flags, flags, KBox, KVec, NumaNode};
/// use kernel::page::{PAGE_SIZE, PAGE_SHIFT};
/// use kernel::prelude::EINVAL;
/// use kernel::str::CString;
/// use kernel::zalloc::*;
///
/// struct MyZalloc {
///     name: CString,
///     bytes_used: AtomicU64,
/// }
///
/// impl MyZalloc {
///     fn new(name: CString, gfp: Flags) -> Result<Self> {
///         Ok(Self { name, bytes_used: AtomicU64::new(0) })
///     }
/// }
///
/// impl ZallocDriver for MyZalloc {
///     fn malloc(&mut self, size: usize, _gfp: Flags, _nid: NumaNode) -> Result<ZallocHandle> {
///         let pow = size.next_power_of_two().trailing_zeros().max(6);
///         match pow {
///             0 => Err(EINVAL),
///             m if m > PAGE_SHIFT as u32 => Err(ENOSPC),
///             _ => {
///                 let vec = KVec::<u8>::with_capacity(1 << pow, GFP_KERNEL)?;
///                 let (ptr, _len, _cap) = vec.into_raw_parts();
///
///                 // We assume that kmalloc-64, kmalloc-128 etc. kmem caches will be used for
///                 // our allocations, so it's actually `1 << pow` bytes that we have consumed.
///                 self.bytes_used.fetch_add(1 << pow, Ordering::Relaxed);
///
///                 // `kmalloc` guarantees that an allocation of size x*2^n is 2^n aligned.
///                 // Therefore the 6 lower bits are zeros and we can use these to store `pow`.
///                 Ok(ZallocHandle::from_raw(ptr as usize | (pow as usize - 6)))
///             }
///         }
///     }
///
///     unsafe fn free(&mut self, handle: ZallocHandle) {
///         let h = handle.as_raw();
///         let n = (h & 0x3F) + 6;
///         let uptr = h & !0x3F;
///
///         // SAFETY:
///         // - we derive `uptr` from handle by zeroing 6 lower bits where we store the power
///         //   denominator for the vector capacity. As noted above, the result will be exactly the
///         //   pointer to the area allocated by `KVec`. Thus, uptr is a valid pointer pointing to
///         //   the vector allocated by `alloc` function above.
///         // - 1 << n == capacity and is coming from the first 6 bits of handle.
///         let vec = unsafe { KVec::<u8>::from_raw_parts(uptr as *mut u8, 0, 1 << n) };
///         drop(vec);
///         self.bytes_used.fetch_sub(1 << n, Ordering::Relaxed);
///     }
///
///     unsafe fn read_begin(&self, handle: ZallocHandle) -> NonNull<u8> {
///         let uptr = handle.as_raw() & !0x3F;
///         // SAFETY:
///         // - we derive `uptr` from handle by zeroing 6 lower bits where we store the power
///         //   denominator for the vector capacity. As noted above, the result will be exactly the
///         //   pointer to the area allocated by `KVec`. Thus, uptr is a valid pointer pointing to
///         //   the vector allocated by `alloc` function above.
///         unsafe { NonNull::new_unchecked(uptr as *mut u8) }
///     }
///
///     unsafe fn write(&self, handle: ZallocHandle, h_mem: NonNull<u8>, mem_len: usize) {
///         let uptr = handle.as_raw() & !0x3F;
///         // SAFETY:
///         // - `h_mem` is a valid non-null pointer provided by zswap.
///         // - `uptr` is derived from handle by zeroing 6 lower bits where we store the power
///         //   denominator for the vector capacity. As noted above, the result will be exactly the
///         //   pointer to the area allocated by `KVec`. Thus, uptr is a valid pointer pointing to
///         //   the vector allocated by `alloc` function above.
///         unsafe {
///             copy_nonoverlapping(h_mem.as_ptr().cast(), uptr as *mut c_void, mem_len)
///         };
///     }
///
///     fn total_pages(&self) -> u64 {
///         self.bytes_used.load(Ordering::Relaxed) >> PAGE_SHIFT
///     }
///
///     fn huge_class_size(&self) -> usize { PAGE_SIZE }
/// }
///
/// // Uncomment this for compile time registration (disabled to avoid build error)
/// // kernel::DeclareZallocBackend!(MyZalloc);
/// ```
///
pub trait ZallocDriver {
    /// Allocate an object of `size` bytes from `pool`, with the allocation flags `gfp` and
    /// preferred NUMA node `nid`. If the allocation is successful, an opaque handle is returned.
    fn malloc(&mut self, size: usize, gfp: Flags, nid: NumaNode) -> Result<ZallocHandle>;

    /// Free an object previously allocated from the `pool`, represented by `handle`.
    ///
    /// # Safety
    ///
    /// - `handle` must be a valid handle previously returned by `malloc`.
    /// - `handle` must not be used any more after the call to `free`.
    unsafe fn free(&mut self, handle: ZallocHandle);

    /// Make all the necessary preparations for the caller to be able to read from the object
    /// represented by `handle` and return a valid pointer to that object's memory to be read.
    ///
    /// # Safety
    ///
    /// - `handle` must be a valid handle previously returned by `malloc`.
    unsafe fn read_begin(&self, handle: ZallocHandle) -> NonNull<u8>;

    /// Write to the object represented by a previously allocated `handle`. `handle_mem` points
    /// to the memory to copy data from, and `mem_len` defines the length of the data block to
    /// be copied.
    ///
    /// # Safety
    ///
    /// - `handle` must be a valid handle previously returned by `malloc`.
    /// - `handle_mem` must be a valid pointer into the allocated memory aread represented by
    ///   `handle`.
    /// - `handle_mem + mem_len - 1` must not point outside the allocated memory area.
    unsafe fn write(&self, handle: ZallocHandle, handle_mem: NonNull<u8>, mem_len: usize);

    /// Get the number of pages used by the `pool`.
    fn total_pages(&self) -> u64;

    /// Get the maximum size of a compressed object that a backend can hold
    fn huge_class_size(&self) -> usize;
}

fn handle_from_result<T, F>(f: F) -> T
where
    T: From<usize>,
    F: FnOnce() -> Result<T>,
{
    match f() {
        Ok(v) => v,
        Err(_e) => T::from(0),
    }
}

/// Declare a backend implementing zs api in Rust.
#[macro_export]
macro_rules! DeclareZallocBackend {
    ($tt: tt) => {
        const __LOG_PREFIX: &[u8] = b"zpool_rust\0";

        $crate::macros::paste! {
            struct [<$tt Creator>];
            impl ZallocCreator for [<$tt Creator>] {
                fn create_pool(&self, name: CString, gfp: Flags) -> Result<KBox<dyn ZallocDriver>> {
                    let pool = <$tt>::new(name, gfp)?;
                    Ok(KBox::new(pool, GFP_KERNEL)? as KBox<dyn ZallocDriver>)
                }

                fn borrow_pool(&self, ptr: *mut c_void) -> &mut dyn ZallocDriver {
                    // SAFETY: `ptr` is a pointer to the pool previously allocated by `create_pool`
                    unsafe { &mut *ptr.cast::<$tt>() }
                }

                fn from_raw(&self, ptr: *mut c_void) -> KBox<dyn ZallocDriver> {
                    // SAFETY: `ptr` is a pointer to the pool previously allocated by `create_pool`
                    unsafe { KBox::from_raw(ptr.cast::<$tt>()) }
                }
            }

            unsafe impl Sync for [<$tt Creator>] {}
            impl [<$tt Creator>] {
                const fn new() -> &'static Self {
                    &Self {}
                }
            }
            #[no_mangle]
            static __default_zalloc_backend: &'static dyn ZallocCreator = <[<$tt Creator>]>::new();
        }
    };
}

/// Allocator creator backend trait.
///
/// This is a helper trait to be implemented by a Rust backend to initialize and process zs pools.
pub trait ZallocCreator: Sync {
    /// Create a pool for zalloc allocations.
    fn create_pool(&self, name: CString, gfp: Flags) -> Result<KBox<dyn ZallocDriver>>;

    /// Borrow a pool.
    fn borrow_pool(&self, ptr: *mut c_void) -> &mut dyn ZallocDriver;

    /// Borrow a pool.
    #[allow(clippy::wrong_self_convention)]
    fn from_raw(&self, ptr: *mut c_void) -> KBox<dyn ZallocDriver>;

}

unsafe extern "C" {
    // We need this for compile time backend registration.
    // Since the registration happens via DeclareZallocBackend, we have control over it.
    #[allow(improper_ctypes)]
    static __default_zalloc_backend: &'static dyn ZallocCreator;
}

/// Create a pool.
///
/// # Safety
///
/// `name` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn zs_create_pool(name: *const c_uchar) -> *mut c_void {
    pr_info!("zs_create_pool CALLED\n");
    match (|| -> Result<KBox<dyn ZallocDriver>> {
        // SAFETY: the memory pointed to by name is guaranteed by the caller to be a valid C
        // string.
        let name_r = unsafe { CStr::from_char_ptr(name).to_cstring() }?;
        // SAFETY: __default_zalloc_backend defined by a backend and valid, otherwise a build
        // error would have occured.
        unsafe {
            <_ as ZallocCreator>::create_pool(__default_zalloc_backend, name_r, flags::GFP_KERNEL)
        }
    })() {
        Err(_) => core::ptr::null_mut(),
        Ok(pool) => Box::into_raw(pool).cast(),
    }
}

/// Destroy the pool.
///
/// # Safety
///
/// `pool` must be a pointer to the pool previously allocated by `zs_create_pool`.
#[no_mangle]
pub unsafe extern "C" fn zs_destroy_pool(pool: *mut c_void) {
    // SAFETY: The pointer originates from an `into_raw` call.
    drop(unsafe { <dyn ZallocCreator>::from_raw(__default_zalloc_backend, pool) })
}

/// Allocate an object of `size` bytes from `pool`, with the allocation flags `gfp` and
/// preferred NUMA node `nid`. If the allocation is successful, an opaque handle
/// is returned.
///
/// # Safety
///
/// `pool` must be a pointer to the pool previously allocated by `zs_create_pool`.
#[no_mangle]
pub unsafe extern "C" fn zs_malloc(
    pool: *mut c_void,
    size: usize,
    gfp: u32,
    nid: c_int,
) -> c_ulong {
    // SAFETY: The pointer originates from an `into_foreign` call. If `pool` is passed to
    // `from_foreign`, then that happens in `zs_destroy_pool` which will not be called
    // during this method.
    let pool = unsafe { <dyn ZallocCreator>::borrow_pool(__default_zalloc_backend, pool) };
    handle_from_result(|| {
        let the_nid = match nid {
            kernel::bindings::NUMA_NO_NODE => NumaNode::NO_NODE,
            _ => NumaNode::new(nid)?,
        };
        let h = pool.malloc(size, Flags::from_raw(gfp)?, the_nid)?;
        Ok(h.as_raw())
    })
}

/// Free an object previously allocated from the `pool`, represented by `handle`.
///
/// # Safety
///
/// * `pool` must be a pointer to the pool previously allocated by `zs_create_pool`.
/// * `handle` must be one of the handles previously allocated by `zs_malloc`.
#[no_mangle]
pub unsafe extern "C" fn zs_free(pool: *mut c_void, handle: usize) {
    // SAFETY: The pointer originates from an `into_foreign` call. If `pool` is passed to
    // `from_foreign`, then that happens in `zs_destroy_pool` which will not be called
    // during this method.
    let pool = unsafe { <dyn ZallocCreator>::borrow_pool(__default_zalloc_backend, pool) };

    // SAFETY:
    // - the caller (`zswap`) guarantees that `handle` is a valid handle previously
    // allocated by `malloc`.
    // - the caller (`zswap`) guarantees that it will not call any other function with this
    //   `handle` as a parameter after this call.
    unsafe { pool.free(ZallocHandle::from_raw(handle)) }
}

/// Make all the necessary preparations for the caller to be able to read from the object
/// represented by `handle` and return a valid pointer to that object's memory to be read.
///
/// # Safety
///
/// * `pool` must be a pointer to the pool previously allocated by `zs_create_pool`.
/// * `handle` must be one of the handles previously allocated by `zs_malloc`.
#[no_mangle]
pub unsafe extern "C" fn zs_obj_read_begin(
    pool: *mut c_void,
    handle: usize,
    _local_copy: *mut c_void,
) -> *mut c_void {
    // SAFETY: The pointer originates from an `into_foreign` call. If `pool` is passed to
    // `from_foreign`, then that happens in `zs_destroy_pool` which will not be called
    // during this method.
    let pool = unsafe { <dyn ZallocCreator>::borrow_pool(__default_zalloc_backend, pool) };

    // SAFETY: the caller (`zswap`) guarantees that `handle` is a valid handle previously
    // allocated by `malloc`.
    let non_null_ptr = unsafe { pool.read_begin(ZallocHandle::from_raw(handle)) };
    non_null_ptr.as_ptr().cast()
}

/// Finish reading from a previously allocated `handle`. `handle_mem` must be the pointer
/// previously returned by `read_begin`.
///
/// # Safety
///
/// No special safety requirements since this function is a no-op.
#[no_mangle]
pub unsafe extern "C" fn zs_obj_read_end(
    _pool: *mut c_void,
    _handle: usize,
    _handle_mem: *mut c_void,
) {
}

/// Write to the object represented by a previously allocated `handle`. `handle_mem` points
/// to the memory to copy data from, and `mem_len` defines the length of the data block to
/// be copied.
///
/// # Safety
///
/// * `pool` must be a pointer to the pool previously allocated by `zs_create_pool`.
/// * `handle` must be one of the handles previously allocated by `zs_malloc`.
/// * `handle_mem` must be a valid non-null memory pointer.
/// * `mem_len` should be small enough so that `handle_mem` + `mem_len` doesn't point to a location
///   past the area allocated for `handle_mem`
#[no_mangle]
pub unsafe extern "C" fn zs_obj_write(
    pool: *mut c_void,
    handle: usize,
    handle_mem: *mut c_void,
    mem_len: usize,
) {
    // SAFETY: The pointer originates from an `into_foreign` call. If `pool` is passed to
    // `from_foreign`, then that happens in `zs_destroy_pool` which will not be called
    // during this method.
    let pool = unsafe { <dyn ZallocCreator>::borrow_pool(__default_zalloc_backend, pool) };

    // SAFETY: `handle_mem` is guaranteed to be non-null by the caller (`zswap`).
    let handle_mem_ptr = unsafe { NonNull::new_unchecked(handle_mem.cast()) };

    // SAFETY: the caller (`zswap`) guarantees that `handle` is a valid handle previously
    // allocated by `malloc`.
    unsafe { pool.write(ZallocHandle::from_raw(handle), handle_mem_ptr, mem_len) }
}

/// Get the number of pages used by the `pool`.
///
/// # Safety
///
/// * `pool` must be a pointer to the pool previously allocated by `zs_create_pool`.
#[no_mangle]
pub unsafe extern "C" fn zs_get_total_pages(pool: *mut c_void) -> u64 {
    // SAFETY: The pointer originates from an `into_foreign` call. If `pool` is passed to
    // `from_foreign`, then that happens in `zs_destroy_pool` which will not be called
    // during this method.
    let pool = unsafe { <dyn ZallocCreator>::borrow_pool(__default_zalloc_backend, pool) };
    pool.total_pages()
}

/// Compact the `pool` for it to occupy less space. Not necessary at this point.
///
/// # Safety
///
/// No special safety requirements since this function is a no-op.
#[no_mangle]
pub unsafe extern "C" fn zs_compact(_pool: *mut c_void) -> usize {
    0
}

/// Get the 'can be stored compressed' threshold from a backend.
///
/// # Safety
///
/// * `pool` must be a pointer to the pool previously allocated by `zs_create_pool`.
#[no_mangle]
pub unsafe extern "C" fn zs_huge_class_size(pool: *mut c_void) -> usize {
    // SAFETY: The pointer originates from an `into_foreign` call. If `pool` is passed to
    // `from_foreign`, then that happens in `zs_destroy_pool` which will not be called
    // during this method.
    let pool = unsafe { <dyn ZallocCreator>::borrow_pool(__default_zalloc_backend, pool) };
    pool.huge_class_size()
}

/// Fill in pool's page migration statistics to `stats`. Not used in zswap, used in zram.
/// Since we don't compact Rust pools, leave this as a no-op.
///
/// # Safety
///
/// No special safety requirements since this function is a no-op.
#[no_mangle]
pub unsafe extern "C" fn zs_pool_stats(_pool: *mut c_void, _stats: *mut c_void) {}

/// Return index of the zsmalloc's size class. Not used in zswap used in zram in marginal cases
/// so we'll skip this for now.
///
/// # Safety
///
/// No special safety requirements since this function is a no-op.
#[no_mangle]
pub unsafe extern "C" fn zs_lookup_class_index(_pool: *mut c_void, _size: c_uint) -> c_uint {
    0
}

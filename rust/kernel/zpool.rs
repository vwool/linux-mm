use crate::{
    bindings,
    error::{Result,Error},
    kernel::alloc::Flags,
    str::CStr,
    types::{Opaque, ForeignOwnable},
};
use kernel::alloc::{NumaNode,numa};
use core::ffi::{c_uchar,c_void,c_int};
use core::ptr::null_mut;
use kernel::ThisModule;

/// zpool API
pub trait Zpool {
    type Pool: ForeignOwnable;

    /// pool creation
    fn create(name: *const c_uchar, gfp: Flags) -> Result<Self::Pool, Error>;
    /// pool destruction
    fn destroy(pool: Self::Pool);
    /// object allocation
    fn malloc(pool: <Self::Pool as ForeignOwnable>::Borrowed<'_>, size: usize, gfp: Flags, nid: NumaNode) -> Result<usize, Error>;
    /// object release
    fn free(pool: <Self::Pool as ForeignOwnable>::Borrowed<'_>, handle: usize);
    /// object read begin
    fn read_begin(pool: <Self::Pool as ForeignOwnable>::Borrowed<'_>, handle: usize) -> usize;
    /// object read end
    fn read_end(pool: <Self::Pool as ForeignOwnable>::Borrowed<'_>, handle: usize, handle_mem: *mut c_void);
    /// object write
    fn write(pool: <Self::Pool as ForeignOwnable>::Borrowed<'_>, handle: usize, handle_mem: *mut c_void, mem_len: usize);
    /// get number of pages used
    fn total_pages(pool: <Self::Pool as ForeignOwnable>::Borrowed<'_>) -> u64;
}

/// zpool driver registration trait
pub trait Registration {
    /// register a zpool driver
    unsafe fn register(&self, name: &'static CStr, module: &'static ThisModule) -> Result;
    /// pool creation callback
    extern "C" fn _create(name: *const c_uchar, gfp: u32) -> *mut c_void;
    /// pool destruction callback
    extern "C" fn _destroy(pool: *mut c_void);
    /// callback for object allocation
    extern "C" fn _malloc(pool: *mut c_void, size: usize, gfp: u32, handle: *mut usize, nid: c_int)
        -> c_int;
    /// callback for object release
    extern "C" fn _free(pool: *mut c_void, handle: usize);
    /// callback to signal beginning of a read
    extern "C" fn _obj_read_begin(pool: *mut c_void, handle: usize, local_copy: *mut c_void)
        -> *mut c_void;
    /// callback to signal end of a read
    extern "C" fn _obj_read_end(pool: *mut c_void, handle: usize, handle_mem: *mut c_void);
    /// object write callback
    extern "C" fn _obj_write(pool: *mut c_void, handle: usize, handle_mem: *mut c_void, mem_len: usize);
    /// callback to return the number of pages in the pool
    extern "C" fn _total_pages(pool: *mut c_void) -> u64;
}

/// zpool driver structure
pub struct ZpoolDriver<T: Zpool> {
    inner: Opaque<bindings::zpool_driver>,

    /// zpool callback functions that a zpool driver must provide
    pub callbacks: T,
}

impl<T:Zpool> Clone for ZpoolDriver<T> {
    fn clone(&self) -> Self { todo!() }
}

unsafe impl<T:Zpool> Sync for ZpoolDriver<T> {
}

impl<T:Zpool> ZpoolDriver<T> {
    /// create an instance of a zpool driver
    pub const fn new(t: T) -> Self {
        Self { inner: Opaque::uninit(), callbacks: t }
    }
}

impl<T: Zpool> Registration for ZpoolDriver<T> {
    extern "C" fn _create(name: *const c_uchar, gfp: u32) -> *mut c_void {
        let pool = T::create(name, Flags::new(gfp));
        match pool {
            Err(_) => null_mut(),
            Ok(p) => T::Pool::into_foreign(p),
        }
    }
    extern "C" fn _destroy(pool: *mut c_void) {
        // SAFETY: The pointer originates from an `into_foreign` call.
        T::destroy(unsafe { T::Pool::from_foreign(pool) })
    }
    extern "C" fn _malloc(pool: *mut c_void, size: usize, gfp: u32, handle: *mut usize, nid: c_int)
                    -> c_int {
        // SAFETY: The pointer originates from an `into_foreign` call. If `pool` is passed to
        // `from_foreign`, then that happens in `_destroy` which will not be called during this
        // method.
        let pool = unsafe { T::Pool::borrow(pool) };
        let real_nid = match nid {
            bindings::NUMA_NO_NODE => Ok(numa::NUMA_NO_NODE),
            _ => NumaNode::new(nid),
        };
        if real_nid.is_err() {
            return -(bindings::EINVAL as i32);
        }

        // SAFETY: pool is guaranteed to be non-null by zpool
        let result = T::malloc(pool, size, Flags::new(gfp), real_nid.unwrap());
        match result {
            Err(_) => -(bindings::ENOMEM as i32),
            Ok(h) => {
                // SAFETY: handle is guaranteed to be a valid pointer by zpool
                unsafe { *handle = h };
                0
            }
        }
    }
    extern "C" fn _free(pool: *mut c_void, handle: usize) {
        // SAFETY: The pointer originates from an `into_foreign` call. If `pool` is passed to
        // `from_foreign`, then that happens in `_destroy` which will not be called during this
        // method.
        let pool = unsafe { T::Pool::borrow(pool) };
        T::free(pool, handle)
    }
    extern "C" fn _obj_read_begin(pool: *mut c_void, handle: usize, _local_copy: *mut c_void)
                    -> *mut c_void {
        // SAFETY: The pointer originates from an `into_foreign` call. If `pool` is passed to
        // `from_foreign`, then that happens in `_destroy` which will not be called during this
        // method.
        let pool = unsafe { T::Pool::borrow(pool) };
        T::read_begin(pool, handle) as *mut c_void
    }
    extern "C" fn _obj_read_end(pool: *mut c_void, handle: usize, handle_mem: *mut c_void) {
        // SAFETY: The pointer originates from an `into_foreign` call. If `pool` is passed to
        // `from_foreign`, then that happens in `_destroy` which will not be called during this
        // method.
        let pool = unsafe { T::Pool::borrow(pool) };
        T::read_end(pool, handle, handle_mem)
    }
    extern "C" fn _obj_write(pool: *mut c_void, handle: usize, handle_mem: *mut c_void, mem_len: usize) {
        // SAFETY: The pointer originates from an `into_foreign` call. If `pool` is passed to
        // `from_foreign`, then that happens in `_destroy` which will not be called during this
        // method.
        let pool = unsafe { T::Pool::borrow(pool) };
        T::write(pool, handle, handle_mem, mem_len);
    }
    extern "C" fn _total_pages(pool: *mut c_void) -> u64 {
        // SAFETY: The pointer originates from an `into_foreign` call. If `pool` is passed to
        // `from_foreign`, then that happens in `_destroy` which will not be called during this
        // method.
        let pool = unsafe { T::Pool::borrow(pool) };
        T::total_pages(pool)
    }

    unsafe fn register(&self,
                       name: &'static CStr,
                       module: &'static ThisModule) -> Result {
        unsafe {
            (*(self.inner.get())).create = Some(Self::_create);
            (*(self.inner.get())).destroy = Some(Self::_destroy);
            (*(self.inner.get())).malloc = Some(Self::_malloc);
            (*(self.inner.get())).free = Some(Self::_free);
            (*(self.inner.get())).obj_read_begin = Some(Self::_obj_read_begin);
            (*(self.inner.get())).obj_read_end = Some(Self::_obj_read_end);
            (*(self.inner.get())).obj_write = Some(Self::_obj_write);
            (*(self.inner.get())).total_pages = Some(Self::_total_pages);

            (*(self.inner.get())).owner = module.0;
            (*(self.inner.get())).type_ = name.as_char_ptr() as *mut u8;

        }
        Ok(unsafe {
            bindings::zpool_register_driver(self.inner.get())
        })

    }
}



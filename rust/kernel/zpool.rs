use crate::{
    bindings,
    error::Result,
    str::CStr,
    types::Opaque,
    ThisModule,
};
use core::ffi::{c_uchar,c_void,c_int};

/// zpool API
pub trait Zpool {
    /// pool creation
    fn create(name: *const c_uchar, gfp: u32) -> *mut c_void;
    /// pool destruction
    fn destroy(pool: *mut c_void);
    /// object allocation
    fn malloc(pool: *mut c_void, size: usize, gfp: u32, handle: *mut usize, nid: c_int) -> c_int;
    /// object release
    fn free(pool: *mut c_void, handle: usize);
    /// object read begin
    fn read_begin(_pool: *mut c_void, handle: usize, _local_copy: *mut c_void) -> *mut c_void;
    /// object read end
    fn read_end(pool: *mut c_void, handle: usize, handle_mem: *mut c_void);
    /// object write
    fn write(pool: *mut c_void, handle: usize, handle_mem: *mut c_void, mem_len: usize);
    /// get number of pages used
    fn total_pages(pool: *mut c_void) -> u64;
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
        T::create(name, gfp)
    }
    extern "C" fn _destroy(pool: *mut c_void) {
        T::destroy(pool)
    }
    extern "C" fn _malloc(pool: *mut c_void, size: usize, gfp: u32, handle: *mut usize, nid: c_int)
                    -> c_int {
        T::malloc(pool, size, gfp, handle, nid)
    }
    extern "C" fn _free(pool: *mut c_void, handle: usize) {
        T::free(pool, handle)
    }
    extern "C" fn _obj_read_begin(pool: *mut c_void, handle: usize, local_copy: *mut c_void)
                    -> *mut c_void {
        T::read_begin(pool, handle, local_copy)
    }
    extern "C" fn _obj_read_end(pool: *mut c_void, handle: usize, handle_mem: *mut c_void) {
        T::read_end(pool, handle, handle_mem)
    }
    extern "C" fn _obj_write(pool: *mut c_void, handle: usize, handle_mem: *mut c_void, mem_len: usize) {
        T::write(pool, handle, handle_mem, mem_len)
    }
    extern "C" fn _total_pages(pool: *mut c_void) -> u64 {
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



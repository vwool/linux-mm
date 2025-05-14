use crate::{
    bindings,
    error::{to_result, Result},
    str::CStr,
    types::{Opaque},
    ThisModule,
};
use core::ptr;
use core::ffi::{c_uchar,c_void,c_ulong,c_int};
use kernel::alloc::Flags;

pub trait Zpool {
    fn Create(name: *const c_uchar, gfp: u32) -> *mut c_void;
    fn Destroy(pool: *mut c_void);
    fn Malloc(pool: *mut c_void, size: usize, gfp: u32, handle: *mut usize, nid: c_int) -> c_int;
    fn Free(pool: *mut c_void, handle: usize);
    fn ReadBegin(_pool: *mut c_void, handle: usize, _local_copy: *mut c_void) -> *mut c_void;
    fn ReadEnd(pool: *mut c_void, handle: usize, handle_mem: *mut c_void);
    fn Write(pool: *mut c_void, handle: usize, handle_mem: *mut c_void, mem_len: usize);
    fn TotalPages(pool: *mut c_void) -> u64;
}

pub trait Registration {
    unsafe fn register(&self, name: &'static CStr, module: &'static ThisModule) -> Result;
    extern "C" fn _create(name: *const c_uchar, gfp: u32) -> *mut c_void;
    extern "C" fn _destroy(pool: *mut c_void);
    extern "C" fn _malloc(pool: *mut c_void, size: usize, gfp: u32, handle: *mut usize, nid: c_int)
        -> c_int;
    extern "C" fn _free(pool: *mut c_void, handle: usize);
    extern "C" fn _obj_read_begin(pool: *mut c_void, handle: usize, local_copy: *mut c_void)
        -> *mut c_void;
    extern "C" fn _obj_read_end(pool: *mut c_void, handle: usize, handle_mem: *mut c_void);
    extern "C" fn _obj_write(pool: *mut c_void, handle: usize, handle_mem: *mut c_void, mem_len: usize);
    extern "C" fn _total_pages(pool: *mut c_void) -> u64;
}

pub struct ZpoolDriver<T: Zpool> {
    inner: Opaque<bindings::zpool_driver>,
    pub callbacks: T,
}

impl<T:Zpool> Clone for ZpoolDriver<T> {
    fn clone(&self) -> Self { todo!() }
}

unsafe impl<T:Zpool> Sync for ZpoolDriver<T> {
}

impl<T:Zpool> ZpoolDriver<T> {
    pub const fn new(t: T) -> Self {
        Self { inner: Opaque::uninit(), callbacks: t }
    }
}

impl<T: Zpool> Registration for ZpoolDriver<T> {
    extern "C" fn _create(name: *const c_uchar, gfp: u32) -> *mut c_void {
        T::Create(name, gfp)
    }
    extern "C" fn _destroy(pool: *mut c_void) {
        T::Destroy(pool)
    }
    extern "C" fn _malloc(pool: *mut c_void, size: usize, gfp: u32, handle: *mut usize, nid: c_int)
                    -> c_int {
        T::Malloc(pool, size, gfp, handle, nid)
    }
    extern "C" fn _free(pool: *mut c_void, handle: usize) {
        T::Free(pool, handle)
    }
    extern "C" fn _obj_read_begin(pool: *mut c_void, handle: usize, local_copy: *mut c_void)
                    -> *mut c_void {
        T::ReadBegin(pool, handle, local_copy)
    }
    extern "C" fn _obj_read_end(pool: *mut c_void, handle: usize, handle_mem: *mut c_void) {
        T::ReadEnd(pool, handle, handle_mem)
    }
    extern "C" fn _obj_write(pool: *mut c_void, handle: usize, handle_mem: *mut c_void, mem_len: usize) {
        T::Write(pool, handle, handle_mem, mem_len)
    }
    extern "C" fn _total_pages(pool: *mut c_void) -> u64 {
        T::TotalPages(pool)
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



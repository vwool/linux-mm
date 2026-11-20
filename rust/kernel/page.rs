// SPDX-License-Identifier: GPL-2.0

//! Kernel page allocation and management.

use crate::{
    alloc::{
        flags::{
            __GFP_HIGHMEM,
            __GFP_ZERO, //
        },
        AllocError,
        Flags, //
    },
    bindings,
    error::{
        code::*,
        Result, //
    },
    io::{
        Io,
        IoCopyable,
        SysMem,
        SysMemBackend, //
    },
    sync::aref::{
        self,
        ARef,
        AlwaysRefCounted, //
    },
    types::{
        Opaque,
        Ownable,
        Owned, //
    },
    uaccess::UserSliceReader, //
};
use core::{
    marker::PhantomData,
    ops::Deref,
    pin::Pin,
    ptr::{
        self,
        NonNull, //
    }, //
};

/// A bitwise shift for the page size.
pub const PAGE_SHIFT: usize = bindings::PAGE_SHIFT as usize;

/// The number of bytes in a page.
pub const PAGE_SIZE: usize = bindings::PAGE_SIZE;

/// A bitmask that gives the page containing a given address.
pub const PAGE_MASK: usize = !(PAGE_SIZE - 1);

/// Rounds up to the next multiple of [`PAGE_SIZE`].
///
/// Returns [`None`] on integer overflow.
///
/// # Examples
///
/// ```
/// use kernel::page::{
///     page_align,
///     PAGE_SIZE,
/// };
///
/// // Requested address is already aligned.
/// assert_eq!(page_align(0x0), Some(0x0));
/// assert_eq!(page_align(PAGE_SIZE), Some(PAGE_SIZE));
///
/// // Requested address needs alignment up.
/// assert_eq!(page_align(0x1), Some(PAGE_SIZE));
/// assert_eq!(page_align(PAGE_SIZE + 1), Some(2 * PAGE_SIZE));
///
/// // Requested address causes overflow (returns `None`).
/// let overflow_addr = usize::MAX - (PAGE_SIZE / 2);
/// assert_eq!(page_align(overflow_addr), None);
/// ```
#[inline(always)]
pub const fn page_align(addr: usize) -> Option<usize> {
    let Some(sum) = addr.checked_add(PAGE_SIZE - 1) else {
        return None;
    };
    Some(sum & PAGE_MASK)
}

/// Trait to be implemented by types which provide an [`Iterator`] of [`Page<Base>`] references,
/// such as [`VmallocPageIter`](kernel::alloc::allocator::VmallocPageIter).
pub trait AsPageIter {
    /// The [`Iterator`] type, e.g. [`VmallocPageIter`](kernel::alloc::allocator::VmallocPageIter).
    type Iter<'a>: Iterator<Item = &'a Page<Base>>
    where
        Self: 'a;

    /// Returns an [`Iterator`] of [`Page<Base>`] references over all pages owned by `self`.
    fn page_iter(&mut self) -> Self::Iter<'_>;
}

mod private {
    pub trait Sealed {}
}

/// Marker trait for the kinds of a [`Page`].
///
/// A page kind describes what is known about a `struct page`, and thereby what a [`Page`] of that
/// kind can be used for. See [`Base`], [`Shared`], [`RefCounted`], [`Frozen`] and [`Exclusive`].
///
/// A [`Page`] of any other kind dereferences to a [`Page`] of the base kind [`Base`]. The
/// purpose of the dereference is coercion: a reference to a page of any kind can be passed to code
/// that takes a `&Page<Base>`. A [`Page<RefCounted>`] and a [`Page<Frozen>`] dereference to a
/// [`Page<Shared>`], which in turn dereferences to a [`Page<Base>`]. A [`Page<Exclusive>`]
/// dereferences directly to a [`Page<Base>`], as Rust references to its data can exist.
pub trait PageKind: private::Sealed {}

/// The base [`PageKind`]: a valid page with no further guarantees.
///
/// Nothing is known about how the allocation of a [`Page<Base>`] is managed. In particular,
/// the page is not necessarily managed by the page reference count. For instance, pages owned by
/// the slab allocator are not. Thus, it is not possible to obtain an [`ARef`] from a
/// `&Page<Base>`.
///
/// # Invariants
///
/// A [`Page<Base>`] has no invariants in addition to the ones of [`Page`].
pub struct Base;

impl private::Sealed for Base {}
impl PageKind for Base {}

/// A [`PageKind`] for a page whose data is not subject to the Rust aliasing rules.
///
/// The data of a [`Page<Shared>`] can be accessed concurrently by other parties, such as user
/// space, devices or other kernel code. Thus, no Rust reference to the data of the page exists.
///
/// A [`Page<RefCounted>`] and a [`Page<Frozen>`] dereference to a [`Page<Shared>`]. A page that
/// is managed by other means can be referenced as a [`Page<Shared>`] with [`Page::from_raw`].
///
/// # Invariants
///
/// For a [`Page<Shared>`]:
///
/// - No Rust reference to the data of the page exists, except for the duration of an unsafe
///   operation whose caller rules out all other accesses to that data. In particular, the page is
///   not a [`Page<Exclusive>`].
/// - The data of the page is initialized.
/// - No plain access to the data of the page races with another access to that data. A plain
///   access is a non-atomic, non-volatile access performed by kernel code.
pub struct Shared;

impl private::Sealed for Shared {}
impl PageKind for Shared {}

/// The default [`PageKind`]: a page that is managed by the page reference count.
///
/// A [`Page<RefCounted>`] is accessed through a shared reference or through an owning
/// [`ARef<Page>`]. The page allocation is freed when the last reference to it is dropped.
///
/// # Invariants
///
/// For a [`Page<RefCounted>`]:
///
/// - The allocation of the page is managed by the page reference count, and the reference count is
///   non-zero.
/// - It is permitted to take additional references to the page with `get_page()`.
/// - The invariants of [`Shared`] hold for the page.
pub struct RefCounted;

impl private::Sealed for RefCounted {}
impl PageKind for RefCounted {}

/// A `struct page`.
///
/// A `Page` is generic over a [`PageKind`], which describes what is known about the page:
///
/// - `Page<Base>` is a page for which nothing is known beyond its validity.
/// - `Page<Shared>` is a page whose data is initialized and not referenced by Rust references.
/// - `Page<RefCounted>`, or just `Page`, is a page that is managed by the page reference count.
/// - `Page<Frozen>` is a uniquely owned page that references cannot be taken to.
/// - `Page<Exclusive>` is a uniquely owned page whose data follows standard Rust aliasing rules.
///
/// Operations that are valid for any page are available for all page kinds. All other page kinds
/// dereference to [`Page<Base>`], so that a reference to a page of any kind coerces to a
/// `&Page<Base>`. See [`PageKind`] for details.
///
/// # Invariants
///
/// - The `Page` is backed by a valid `struct page`.
/// - The invariants of `Kind` hold for the page, see the documentation of the [`PageKind`] types.
#[repr(transparent)]
pub struct Page<Kind: PageKind = RefCounted> {
    page: Opaque<bindings::page>,
    _kind: PhantomData<Kind>,
}

// SAFETY: Pages have no logic that relies on them staying on a given thread, so moving them across
// threads is safe.
unsafe impl<Kind: PageKind> Send for Page<Kind> {}

// SAFETY: Pages have no logic that relies on them not being accessed concurrently, so accessing
// them concurrently is safe.
unsafe impl<Kind: PageKind> Sync for Page<Kind> {}

impl Deref for Page<Shared> {
    type Target = Page<Base>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: `Page` is transparent over `struct page` for all page kinds, so the pointer cast
        // is valid. `Base` has no invariants in addition to the ones of `Page`, which hold for
        // `self`.
        unsafe { &*ptr::from_ref(self).cast() }
    }
}

impl Deref for Page<RefCounted> {
    type Target = Page<Shared>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: `Page` is transparent over `struct page` for all page kinds, so the pointer cast
        // is valid. By the type invariant of `Page<RefCounted>`, the invariants of `Shared` hold
        // for `self`.
        unsafe { &*ptr::from_ref(self).cast() }
    }
}

impl Page<RefCounted> {
    /// Allocates a new page.
    ///
    /// The page is always zeroed. That is, `__GFP_ZERO` is added to `flags`.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::page::Page;
    ///
    /// let page = Page::alloc_page(GFP_KERNEL)?;
    /// # Ok::<(), kernel::alloc::AllocError>(())
    /// ```
    #[inline]
    pub fn alloc_page(flags: Flags) -> Result<ARef<Self>, AllocError> {
        let flags = flags | __GFP_ZERO;

        // SAFETY: Depending on the value of `gfp_flags`, this call may sleep. Other than that, it
        // is always safe to call this method.
        let page = unsafe { bindings::alloc_pages(flags.as_raw(), 0) };
        let page = NonNull::new(page).ok_or(AllocError)?;
        // INVARIANT: The page was just allocated with `alloc_pages()`, so it is managed by the
        // page reference count. We allocated with `__GFP_ZERO`, so the data of the page is
        // initialized. The page is newly allocated, so nothing references or accesses its data.
        // SAFETY: We just successfully allocated a page, so we own the reference count returned
        // by `alloc_pages`, and we transfer that reference to the new `ARef<Page>`. Since `Page`
        // is transparent, we can cast the pointer directly.
        Ok(unsafe { ARef::from_raw(page.cast()) })
    }
}

impl<Kind: PageKind> Page<Kind> {
    /// Returns a raw pointer to the page.
    pub fn as_ptr(&self) -> *mut bindings::page {
        self.page.get()
    }

    /// Get the node id containing this page.
    #[inline]
    pub fn nid(&self) -> i32 {
        // SAFETY: Always safe to call with a valid page.
        unsafe { bindings::page_to_nid(self.as_ptr()) }
    }

    /// Create a `&Page<Kind>` from a raw `struct page` pointer.
    ///
    /// It is up to the caller to select the correct [`PageKind`] for the page.
    ///
    /// # Safety
    ///
    /// Callers must ensure that, for the duration of `'a`:
    /// - `ptr` is convertible to a shared reference.
    /// - The invariants of `Kind` hold for the page pointed to by `ptr`, see the documentation of
    ///   the [`PageKind`] types.
    ///
    /// Note that the invariants of [`RefCounted`] do not hold for all pages. For instance, pages
    /// owned by the slab allocator are not managed by the page reference count. Likewise, the
    /// invariants of [`Shared`] do not hold for a page whose data is referenced by Rust
    /// references, or whose data is not initialized. Use [`Base`] for pages where nothing is
    /// known beyond their validity.
    #[inline]
    pub unsafe fn from_raw<'a>(ptr: *const bindings::page) -> &'a Self {
        // INVARIANT: By the function safety requirements, `ptr` refers to a valid `struct page`
        // for which the invariants of `Kind` hold, so the returned reference upholds the type
        // invariants of `Page<Kind>`.
        // SAFETY: By function safety requirements, `ptr` is not null and is convertible to a shared
        // reference.
        unsafe { &*ptr.cast() }
    }

    /// Runs a piece of code with this page mapped to an address.
    ///
    /// The page is unmapped when this call returns.
    ///
    /// # Using the raw pointer
    ///
    /// It is up to the caller to use the provided raw pointer correctly. The pointer is valid for
    /// `PAGE_SIZE` bytes and for the duration in which the closure is called. The pointer might
    /// only be mapped on the current thread, and when that is the case, dereferencing it on other
    /// threads is UB. Other than that, the usual rules for dereferencing a raw pointer apply: don't
    /// cause data races, the memory may be uninitialized, and so on.
    ///
    /// If multiple threads map the same page at the same time, then they may reference with
    /// different addresses. However, even if the addresses are different, the underlying memory is
    /// still the same for these purposes (e.g., it's still a data race if they both write to the
    /// same underlying byte at the same time).
    fn with_page_mapped<T>(&self, f: impl FnOnce(*mut u8) -> T) -> T {
        // SAFETY: `page` is valid due to the type invariants on `Page`.
        let mapped_addr = unsafe { bindings::kmap_local_page(self.as_ptr()) };

        let res = f(mapped_addr.cast());

        // This unmaps the page mapped above.
        //
        // SAFETY: Since this API takes the user code as a closure, it can only be used in a manner
        // where the pages are unmapped in reverse order. This is as required by `kunmap_local`.
        //
        // In other words, if this call to `kunmap_local` happens when a different page should be
        // unmapped first, then there must necessarily be a call to `kmap_local_page` other than the
        // call just above in `with_page_mapped` that made that possible. In this case, it is the
        // unsafe block that wraps that other call that is incorrect.
        unsafe { bindings::kunmap_local(mapped_addr) };

        res
    }

    /// Runs a piece of code with a raw pointer to a slice of this page, with bounds checking.
    ///
    /// If `f` is called, then it will be called with a pointer that points at `off` bytes into the
    /// page, and the pointer will be valid for at least `len` bytes. The pointer is only valid on
    /// this task, as this method uses a local mapping.
    ///
    /// If `off` and `len` refers to a region outside of this page, then this method returns
    /// [`EINVAL`] and does not call `f`.
    ///
    /// # Using the raw pointer
    ///
    /// It is up to the caller to use the provided raw pointer correctly. The pointer is valid for
    /// `len` bytes and for the duration in which the closure is called. The pointer might only be
    /// mapped on the current thread, and when that is the case, dereferencing it on other threads
    /// is UB. Other than that, the usual rules for dereferencing a raw pointer apply: don't cause
    /// data races, the memory may be uninitialized, and so on.
    ///
    /// If multiple threads map the same page at the same time, then they may reference with
    /// different addresses. However, even if the addresses are different, the underlying memory is
    /// still the same for these purposes (e.g., it's still a data race if they both write to the
    /// same underlying byte at the same time).
    fn with_pointer_into_page<T>(
        &self,
        off: usize,
        len: usize,
        f: impl FnOnce(*mut u8) -> Result<T>,
    ) -> Result<T> {
        let bounds_ok = off <= PAGE_SIZE && len <= PAGE_SIZE && (off + len) <= PAGE_SIZE;

        if bounds_ok {
            self.with_page_mapped(move |page_addr| {
                // SAFETY: The `off` integer is at most `PAGE_SIZE`, so this pointer offset will
                // result in a pointer that is in bounds or one off the end of the page.
                f(unsafe { page_addr.add(off) })
            })
        } else {
            Err(EINVAL)
        }
    }

    /// Runs a piece of code with a range of this page mapped as a [`SysMem`] view.
    ///
    /// If `f` is called, then it is called with a view of the `len` bytes of the page that start
    /// at `offset`. Accesses through the view are volatile or byte-wise atomic, so the view is
    /// suitable for a page whose data is subject to concurrent writes by hardware or user space.
    /// The view is valid for the duration of the call to `f`.
    ///
    /// If `offset` and `len` refer to a region outside of this page, then this method returns
    /// [`EINVAL`] and does not call `f`.
    ///
    /// # Safety
    ///
    /// * Callers must ensure that no plain access to the mapped range races with an access
    ///   performed through the view, see [`SysMem`].
    /// * Callers must ensure that no mutable reference to the data of the page that overlaps with
    ///   the mapped range exists during this call. If `f` writes through the view, no reference to
    ///   that data may exist during this call. Such references can be obtained from a
    ///   [`Page<Exclusive>`], see [`Page::as_slice`].
    /// * If the page is referenced as a [`Page`] of another kind than [`Base`], `f` must only
    ///   write initialized bytes through the view.
    /// * Callers must ensure that the view is only used on the current task, as this method may
    ///   use a local mapping.
    unsafe fn with_page_as_sysmem<T>(
        &self,
        offset: usize,
        len: usize,
        f: impl FnOnce(SysMem<'_, [u8]>) -> Result<T>,
    ) -> Result<T> {
        self.with_pointer_into_page(offset, len, move |ptr| {
            // SAFETY:
            // - If `with_pointer_into_page` calls into this closure, then it has performed a
            //   bounds check and guarantees that `ptr` is valid for `len` bytes for the duration
            //   of the closure. A byte slice has an alignment of 1.
            // - By the safety requirements of this function, no plain access to the range races
            //   with an access through the view.
            f(unsafe { SysMem::new(ptr::slice_from_raw_parts_mut(ptr, len)) })
        })
    }

    /// Maps the page and reads from it into the given buffer.
    ///
    /// This method will perform bounds checks on the page offset. If `offset .. offset+len` goes
    /// outside of the page, then this call returns [`EINVAL`].
    ///
    /// The copy is byte-wise atomic, so it is well-defined even if the data of the page is
    /// concurrently written by hardware, by user space, or by other kernel code using atomic or
    /// volatile accesses. In that case, the data that is read may be arbitrary.
    ///
    /// # Safety
    ///
    /// * Callers must ensure that `dst` is valid for writing `len` bytes, and that this memory
    ///   does not overlap with the data of the page.
    /// * Callers must ensure that this call does not race with a plain write to the same page that
    ///   overlaps with this read, see [`SysMem`].
    /// * Callers must ensure that no mutable reference to the data of the page that overlaps with
    ///   this read exists during this call.
    pub unsafe fn read_raw(&self, dst: *mut u8, offset: usize, len: usize) -> Result {
        let copy = |src: SysMem<'_, [u8]>| {
            // SAFETY: By the safety requirements of this function, `dst` is valid for writing
            // `len` bytes, which is equal to `src.size()`, and it does not overlap with `src`.
            unsafe { SysMemBackend::copy_from_io(src, dst) };
            Ok(())
        };

        // SAFETY: By the safety requirements of this function, no plain write races with the read
        // through the view, and no mutable reference to the data that is read exists. `copy` does
        // not write through the view, and it only uses the view on the current task.
        unsafe { self.with_page_as_sysmem(offset, len, copy) }
    }

    /// Maps the page and reads from it into the given system memory region using byte-wise atomic
    /// memory operations.
    ///
    /// This method will perform bounds checks on the page offset. If `offset .. offset+dst.len()`
    /// goes outside of the page, then this call returns [`EINVAL`].
    ///
    /// The writes to `dst` are byte-wise atomic, so they are well-defined even if `dst` is
    /// concurrently accessed by hardware, by user space, or by other kernel code using atomic or
    /// volatile accesses. The reads from the page are byte-wise atomic as well.
    ///
    /// # Safety
    ///
    /// Callers must ensure that:
    ///
    /// - This call does not race with a plain write to the source page that overlaps with this
    ///   read, see [`SysMem`].
    /// - No mutable reference to the data of the page that overlaps with this read exists during
    ///   this call.
    /// - The memory region of `dst` does not overlap with the memory of the page.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::{
    ///     io::SysMem,
    ///     page::Page,
    /// };
    ///
    /// let page = Page::alloc_page(GFP_KERNEL | __GFP_ZERO)?;
    /// let mut buf = [0xffu8; 16];
    ///
    /// // SAFETY: `buf` is a local array that outlives `dst`, and it is not accessed in any other
    /// // way while `dst` is alive.
    /// let dst = unsafe { SysMem::new(&raw mut buf as *mut [u8]) };
    ///
    /// // SAFETY: No plain write to `page` happens during this call, no reference to the data of
    /// // `page` exists, and `buf` is not part of the page.
    /// unsafe { page.read_sysmem(dst, 0)? };
    /// assert_eq!(buf, [0u8; 16]);
    /// # Ok::<(), Error>(())
    /// ```
    pub unsafe fn read_sysmem(&self, dst: SysMem<'_, [u8]>, offset: usize) -> Result {
        self.with_pointer_into_page(offset, dst.len(), move |src| {
            // SAFETY:
            // - If `with_pointer_into_page` calls into this closure, then it has performed a
            //   bounds check and guarantees that `src` is valid for `dst.len()` bytes, which is
            //   equal to `dst.size()`.
            // - By the safety requirements of this function, no plain write to the page races
            //   with this call, so `src` is valid for volatile reads.
            // - By the safety requirements of this function, `src` does not overlap with `dst`.
            unsafe { SysMemBackend::copy_to_io(dst, src) };
            Ok(())
        })
    }

    /// Maps the page and writes into it from the given buffer.
    ///
    /// This method will perform bounds checks on the page offset. If `offset .. offset+len` goes
    /// outside of the page, then this call returns [`EINVAL`].
    ///
    /// The copy is byte-wise atomic, so it is well-defined even if the data of the page is
    /// concurrently accessed by hardware, by user space, or by other kernel code using atomic or
    /// volatile accesses.
    ///
    /// # Safety
    ///
    /// * Callers must ensure that `src` is valid for reading `len` bytes, and that this memory
    ///   does not overlap with the data of the page.
    /// * Callers must ensure that this call does not race with a plain read or write to the same
    ///   page that overlaps with this write, see [`SysMem`].
    /// * Callers must ensure that no reference to the data of the page that overlaps with this
    ///   write exists during this call. Such references can be obtained from a
    ///   [`Page<Exclusive>`], see [`Page::as_slice`].
    /// * If the page is referenced as a [`Page`] of another kind than [`Base`], callers must
    ///   ensure that the `len` bytes at `src` are initialized, as the invariants of those page
    ///   kinds require the data of the page to be initialized.
    pub unsafe fn write_raw(&self, src: *const u8, offset: usize, len: usize) -> Result {
        let copy = |dst: SysMem<'_, [u8]>| {
            // SAFETY: By the safety requirements of this function, `src` is valid for reading
            // `len` bytes, which is equal to `dst.size()`, and it does not overlap with `dst`.
            unsafe { SysMemBackend::copy_to_io(dst, src) };
            Ok(())
        };

        // SAFETY: By the safety requirements of this function, no plain access races with the
        // write through the view, no reference to the data that is written exists, and the bytes
        // written are initialized if the page requires it. `copy` only uses the view on the
        // current task.
        unsafe { self.with_page_as_sysmem(offset, len, copy) }
    }

    /// Maps the page and writes into it from the given system memory region using byte-wise atomic
    /// memory operations.
    ///
    /// This method will perform bounds checks on the page offset. If `offset .. offset+src.len()`
    /// goes outside of the page, then this call returns [`EINVAL`].
    ///
    /// The reads from `src` are byte-wise atomic, so they are well-defined even if `src` is
    /// concurrently accessed by hardware, by user space, or by other kernel code using atomic or
    /// volatile accesses. The writes to the page are byte-wise atomic as well.
    ///
    /// # Safety
    ///
    /// Callers must ensure that:
    ///
    /// - This call does not race with a plain read or write to the destination page that overlaps
    ///   with this write, see [`SysMem`].
    /// - No reference to the data of the page that overlaps with this write exists during this
    ///   call. Such references can be obtained from a [`Page<Exclusive>`], see
    ///   [`Page::as_slice`].
    /// - If the page is referenced as a [`Page`] of another kind than [`Base`], the bytes of `src`
    ///   are initialized.
    /// - The memory region of `src` does not overlap with the memory of the page.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::{
    ///     io::SysMem,
    ///     page::Page,
    /// };
    ///
    /// let page = Page::alloc_page(GFP_KERNEL)?;
    /// let mut data = [0xabu8; 16];
    /// let mut buf = [0u8; 16];
    ///
    /// // SAFETY: `data` and `buf` are local arrays that outlive the views, and they are not
    /// // accessed in any other way while the views are alive.
    /// let (src, dst) = unsafe {
    ///     (
    ///         SysMem::new(&raw mut data as *mut [u8]),
    ///         SysMem::new(&raw mut buf as *mut [u8]),
    ///     )
    /// };
    ///
    /// // SAFETY: No plain access to `page` happens during these calls, no reference to the data
    /// // of `page` exists, `data` is initialized, and neither `data` nor `buf` is part of the
    /// // page.
    /// unsafe {
    ///     page.write_sysmem(src, 0)?;
    ///     page.read_sysmem(dst, 0)?;
    /// }
    /// assert_eq!(buf, data);
    /// # Ok::<(), Error>(())
    /// ```
    pub unsafe fn write_sysmem(&self, src: SysMem<'_, [u8]>, offset: usize) -> Result {
        self.with_pointer_into_page(offset, src.len(), move |dst| {
            // SAFETY:
            // - If `with_pointer_into_page` calls into this closure, then it has performed a
            //   bounds check and guarantees that `dst` is valid for `src.len()` bytes, which is
            //   equal to `src.size()`.
            // - By the safety requirements of this function, no plain access to the page races
            //   with this call, so `dst` is valid for volatile writes.
            // - By the safety requirements of this function, `dst` does not overlap with `src`.
            unsafe { SysMemBackend::copy_from_io(src, dst) };
            Ok(())
        })
    }

    /// Maps the page and zeroes the given slice.
    ///
    /// This method will perform bounds checks on the page offset. If `offset .. offset+len` goes
    /// outside of the page, then this call returns [`EINVAL`].
    ///
    /// The writes are byte-wise atomic, so they are well-defined even if the data of the page is
    /// concurrently accessed by hardware, by user space, or by other kernel code using atomic or
    /// volatile accesses.
    ///
    /// # Safety
    ///
    /// * Callers must ensure that this call does not race with a plain read or write to the same
    ///   page that overlaps with this write, see [`SysMem`].
    /// * Callers must ensure that no reference to the data of the page that overlaps with this
    ///   write exists during this call. Such references can be obtained from a
    ///   [`Page<Exclusive>`], see [`Page::as_slice`].
    pub unsafe fn fill_zero_raw(&self, offset: usize, len: usize) -> Result {
        let fill = |dst: SysMem<'_, [u8]>| {
            dst.fill_zero();
            Ok(())
        };

        // SAFETY: By the safety requirements of this function, no plain access races with the
        // write through the view, and no reference to the data that is written exists. The bytes
        // written are initialized. `fill` only uses the view on the current task.
        unsafe { self.with_page_as_sysmem(offset, len, fill) }
    }

    /// Copies data from userspace into this page.
    ///
    /// This method will perform bounds checks on the page offset. If `offset .. offset+len` goes
    /// outside of the page, then this call returns [`EINVAL`].
    ///
    /// Like the other `UserSliceReader` methods, data races are allowed on the userspace address.
    /// However, they are not allowed on the page you are copying into.
    ///
    /// # Safety
    ///
    /// * Callers must ensure that this call does not race with a read or write to the same page
    ///   that overlaps with this write.
    /// * Callers must ensure that no reference to the data of the page that overlaps with this
    ///   write exists during this call. Such references can be obtained from a
    ///   [`Page<Exclusive>`], see [`Page::as_slice`].
    pub unsafe fn copy_from_user_slice_raw(
        &self,
        reader: &mut UserSliceReader,
        offset: usize,
        len: usize,
    ) -> Result {
        self.with_pointer_into_page(offset, len, move |dst| {
            // SAFETY: If `with_pointer_into_page` calls into this closure, then it has performed a
            // bounds check and guarantees that `dst` is valid for `len` bytes. The caller
            // guarantees that there are no races, so `dst` is valid for atomic writes.
            unsafe { reader.read_raw(dst, len) }
        })
    }
}

// SAFETY: By the type invariant, a `Page<RefCounted>` is managed by the page reference count.
// Incrementing it via `get_page()` keeps the page alive at least until a matching `put_page()`,
// which frees the page when the count reaches zero.
unsafe impl aref::RefCounted for Page<RefCounted> {
    #[inline]
    fn inc_ref(&self) {
        // SAFETY: By the type invariant, `self.as_ptr()` points to a valid `struct page` with a
        // non-zero reference count.
        unsafe { bindings::get_page(self.as_ptr()) };
    }

    #[inline]
    unsafe fn dec_ref(obj: NonNull<Self>) {
        // SAFETY: By the function safety requirements, the caller relinquishes a reference count
        // on the page. Since `Page` is transparent, we can cast the pointer directly.
        unsafe { bindings::put_page(obj.cast().as_ptr()) };
    }
}

// SAFETY: All instances of `Page` are reference counted, so a `&Page` proves that the refcount is
// non-zero and it is okay to obtain an `ARef<Page>` from it.
unsafe impl AlwaysRefCounted for Page {}

/// A [`PageKind`] for a frozen page.
///
/// The reference count of a frozen page is zero, and references to it cannot be taken. A
/// [`Page<Frozen>`] is accessed through an owning [`Owned<Page<Frozen>>`], and the page is freed
/// when the [`Owned<Page<Frozen>>`] is dropped.
///
/// Unlike for a [`Page<Exclusive>`], nothing is known about who accesses the data of a
/// [`Page<Frozen>`]. For instance, the owner can share the data of the page with a device. Thus,
/// no Rust reference to the data of the page exists, and a [`Page<Frozen>`] dereferences to a
/// [`Page<Shared>`].
///
/// # Invariants
///
/// For a [`Page<Frozen>`]:
///
/// - The page is an order 0 frozen page: it was allocated with `alloc_frozen_pages()`, and its
///   reference count is zero for as long as the [`Page<Frozen>`] exists.
/// - The page is owned by a unique [`Owned<Page<Frozen>>`]. No references to the page exist
///   together with the [`Owned<Page<Frozen>>`], other than the ones borrowed from it.
/// - The invariants of [`Shared`] hold for the page.
pub struct Frozen;

impl private::Sealed for Frozen {}
impl PageKind for Frozen {}

impl Deref for Page<Frozen> {
    type Target = Page<Shared>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: `Page` is transparent over `struct page` for all page kinds, so the pointer cast
        // is valid. By the type invariant of `Page<Frozen>`, the invariants of `Shared` hold for
        // `self`.
        unsafe { &*ptr::from_ref(self).cast() }
    }
}

impl Page<Frozen> {
    /// Allocates a new frozen page.
    ///
    /// The page is always zeroed. That is, `__GFP_ZERO` is added to `flags`.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::page::Page;
    ///
    /// let page = Page::alloc_frozen(GFP_KERNEL)?;
    /// # Ok::<(), kernel::alloc::AllocError>(())
    /// ```
    #[inline]
    pub fn alloc_frozen(flags: Flags) -> Result<Owned<Self>, AllocError> {
        let flags = flags | __GFP_ZERO;

        // SAFETY: Depending on the value of `gfp_flags`, this call may sleep. Other than that, it
        // is always safe to call this method.
        let page = unsafe { bindings::alloc_frozen_pages(flags.as_raw(), 0) };
        let page = NonNull::new(page).ok_or(AllocError)?;

        // INVARIANT: The page was just allocated with `alloc_frozen_pages()`, so it is frozen and
        // we own it. We allocated with `__GFP_ZERO`, so the data of the page is initialized. The
        // page is newly allocated, so nothing references or accesses its data.
        // SAFETY:
        // - We just successfully allocated the page, so `page` points to a valid `struct page`.
        //   Since `Page` is transparent over `struct page`, we can cast the pointer directly.
        // - The page was just allocated, so no other `Owned` exists for it.
        // - A `struct page` is never moved, so the page is pinned.
        // - `Page<Frozen>` allows no other references to exist together with the `Owned`, and
        //   none exist, as the page is newly allocated and references cannot be taken to a frozen
        //   page. Thus, it is sound to hand out `&Page<Frozen>` and `Pin<&mut Page<Frozen>>`.
        // - Pages have no logic that relies on them staying on a given thread or on them not being
        //   accessed concurrently.
        Ok(unsafe { Owned::from_raw(page.cast()) })
    }
}

impl Ownable for Page<Frozen> {
    #[inline]
    unsafe fn release(this: NonNull<Self>) {
        // SAFETY: By the function safety requirements, we have exclusive ownership of the page, and
        // by the type invariant the page is an order 0 frozen page, so we can free it with
        // `free_frozen_pages()`. Since `Page` is transparent over `struct page`, we can cast the
        // pointer directly.
        unsafe { bindings::free_frozen_pages(this.cast().as_ptr(), 0) };
    }
}

/// A [`PageKind`] for a page whose data area follows standard Rust aliasing rules.
///
/// A [`Page<Exclusive>`] is accessed through an owning [`Owned<Page<Exclusive>>`]. It has the same
/// usage constraints as other Rust types. Thus, it cannot be mapped to user space or shared with
/// devices. This makes it safe to reference the contents of the page, see [`Page::as_slice`] and
/// [`Page::as_mut_slice`].
///
/// A [`Page<Exclusive>`] is backed by a frozen page. The reference count of a frozen page is zero,
/// and references to it cannot be taken. Thus, the exclusive ownership of the page is upheld by
/// the kernel, and not only by the Rust type system.
///
/// # Invariants
///
/// For a [`Page<Exclusive>`]:
///
/// - The page is an order 0 frozen page: it was allocated with `alloc_frozen_pages()`, and its
///   reference count is zero for as long as the [`Page<Exclusive>`] exists.
/// - The page is owned by a unique [`Owned<Page<Exclusive>>`]. No references to the page exist
///   together with the [`Owned<Page<Exclusive>>`], other than the ones borrowed from it.
/// - The data of the page is accessed only through references to the [`Page<Exclusive>`],
///   including the [`Page<Base>`] references it dereferences to.
/// - Safe code reads the data of the page only through a shared reference, and writes it only
///   through a mutable reference. The unsafe raw accessors of [`Page`] can write through a shared
///   reference, their callers are required to rule out races with all other accesses, and to
///   ensure that no reference to the data they write exists.
/// - The data of the page is initialized.
/// - The page is not a highmem page, so its data is permanently mapped in the kernel address
///   space.
pub struct Exclusive;

impl private::Sealed for Exclusive {}
impl PageKind for Exclusive {}

impl Deref for Page<Exclusive> {
    type Target = Page<Base>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: `Page` is transparent over `struct page` for all page kinds, so the pointer cast
        // is valid. `Base` has no invariants in addition to the ones of `Page`, which hold for
        // `self`.
        unsafe { &*ptr::from_ref(self).cast() }
    }
}

impl Page<Exclusive> {
    /// Allocates a new exclusive page.
    ///
    /// The page is always zeroed, and it is never allocated from highmem. That is, `__GFP_ZERO` is
    /// added to `flags`, and `__GFP_HIGHMEM` is removed from `flags`.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::page::{
    ///     Page,
    ///     PAGE_SIZE, //
    /// };
    ///
    /// let mut page = Page::alloc_exclusive(GFP_KERNEL)?;
    /// assert_eq!(page.as_slice().len(), PAGE_SIZE);
    /// assert!(page.as_slice().iter().all(|byte| *byte == 0));
    ///
    /// page.as_pin_mut().as_mut_slice()[..4].copy_from_slice(&[1, 2, 3, 4]);
    /// assert_eq!(page.as_slice()[..5], [1, 2, 3, 4, 0]);
    /// # Ok::<(), kernel::alloc::AllocError>(())
    /// ```
    #[inline]
    pub fn alloc_exclusive(flags: Flags) -> Result<Owned<Self>, AllocError> {
        let flags = (flags | __GFP_ZERO) & !__GFP_HIGHMEM;

        // SAFETY: Depending on the value of `gfp_flags`, this call may sleep. Other than that, it
        // is always safe to call this method.
        let page = unsafe { bindings::alloc_frozen_pages(flags.as_raw(), 0) };
        let page = NonNull::new(page).ok_or(AllocError)?;

        // INVARIANT:
        // - The page was just allocated with `alloc_frozen_pages()`, so it is frozen, we own it,
        //   and its data is only accessible through the returned `Owned<Page<Exclusive>>`.
        // - We allocated with `__GFP_ZERO`, so the data of the page is initialized.
        // - We allocated without `__GFP_HIGHMEM`, so the page is not a highmem page.
        // SAFETY:
        // - We just successfully allocated the page, so `page` points to a valid `struct page`.
        //   Since `Page` is transparent over `struct page`, we can cast the pointer directly.
        // - The page was just allocated, so no other `Owned` exists for it.
        // - A `struct page` is never moved, so the page is pinned.
        // - `Page<Exclusive>` allows no other references to exist together with the `Owned`, and
        //   none exist, as the page is newly allocated and references cannot be taken to a frozen
        //   page. Thus, it is sound to hand out `&Page<Exclusive>` and
        //   `Pin<&mut Page<Exclusive>>`.
        // - Pages have no logic that relies on them staying on a given thread or on them not being
        //   accessed concurrently.
        Ok(unsafe { Owned::from_raw(page.cast()) })
    }

    /// Returns a pointer to the data of the page.
    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: By the type invariant of `Page`, `self.as_ptr()` points to a valid `struct page`.
        unsafe { bindings::page_address(self.as_ptr()) }.cast()
    }

    /// Returns the data of the page as a slice of [`PAGE_SIZE`] bytes.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY:
        // - By the type invariant, the page is not a highmem page, so `data_ptr()` returns a
        //   non-null pointer that is valid for reads of `PAGE_SIZE` bytes for as long as the page
        //   exists, which is at least the lifetime of `self`.
        // - By the type invariant, the data of the page is initialized.
        // - By the type invariant, the data of the page is only written by safe code through a
        //   mutable reference to the page, which cannot exist together with `self`. Callers of the
        //   unsafe raw accessors must ensure that no reference to the data they write exists.
        //   Thus, the data is not mutated for the lifetime of the returned reference.
        unsafe { core::slice::from_raw_parts(self.data_ptr(), PAGE_SIZE) }
    }

    /// Returns the data of the page as a mutable slice of [`PAGE_SIZE`] bytes.
    #[inline]
    pub fn as_mut_slice(self: Pin<&mut Self>) -> &mut [u8] {
        // SAFETY:
        // - By the type invariant, the page is not a highmem page, so `data_ptr()` returns a
        //   non-null pointer that is valid for reads and writes of `PAGE_SIZE` bytes for as long as
        //   the page exists, which is at least the lifetime of `self`.
        // - By the type invariant, the data of the page is initialized.
        // - By the type invariant, the data of the page is only accessed through references to the
        //   page. `self` is a mutable reference, so no other reference to the page exists, and
        //   thus no other access to the data happens for the lifetime of the returned reference.
        unsafe { core::slice::from_raw_parts_mut(self.data_ptr(), PAGE_SIZE) }
    }
}

impl Ownable for Page<Exclusive> {
    #[inline]
    unsafe fn release(this: NonNull<Self>) {
        // SAFETY: By the function safety requirements, we have exclusive ownership of the page, and
        // by the type invariant the page is an order 0 frozen page, so we can free it with
        // `free_frozen_pages()`. Since `Page` is transparent over `struct page`, we can cast the
        // pointer directly.
        unsafe { bindings::free_frozen_pages(this.cast().as_ptr(), 0) };
    }
}

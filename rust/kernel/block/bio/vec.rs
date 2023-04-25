// SPDX-License-Identifier: GPL-2.0

//! Types for working with `struct bio_vec` IO vectors
//!
//! C header: [`include/linux/bvec.h`](../../include/linux/bvec.h)

use super::Bio;
use crate::{
    error::{
        code,
        Result, //
    },
    io::{
        Io,
        SysMemLocal, //
    },
    page::{
        Page,
        Shared,
        PAGE_SIZE, //
    },
    prelude::*, //
};
use core::fmt;

/// A segment of an IO request.
///
/// [`Segment`] represents a contiguous range of physical memory addresses of an IO request. A
/// segment has a offset and a length, representing the amount of data that needs to be processed.
/// Processing the data increases the offset and reduces the length.
///
/// The data buffer of a [`Segment`] is borrowed from a `Bio`.
///
/// # Implementation details
///
/// In the context of user driven block IO, the pages backing a [`Segment`] are often mapped to user
/// space concurrently with the IO operation. Further, the page backing a `Segment` may be part of
/// multiple IO operations, if user space decides to issue multiple concurrent IO operations
/// involving the same page. Thus, the data represented by a [`Segment`] must always be assumed to
/// be subject to racy writes.
///
/// A [`Segemnt`] is a wrapper around a `strutct bio_vec`.
///
/// # Invariants
///
/// `bio_vec` must always be initialized and valid for read and write
pub struct Segment<'a> {
    bio_vec: bindings::bio_vec,
    _marker: core::marker::PhantomData<&'a ()>,
}

impl Segment<'_> {
    /// Get he length of the segment in bytes.
    #[inline(always)]
    pub fn len(&self) -> u32 {
        self.bio_vec.bv_len
    }

    /// Returns true if the length of the segment is 0.
    #[inline(always)]
    pub fn at_end(&self) -> bool {
        self.len() == 0
    }

    /// Get the offset field of the `bio_vec`.
    #[inline(always)]
    pub fn offset(&self) -> usize {
        self.bio_vec.bv_offset as usize
    }

    /// Advance the offset of the segment.
    ///
    /// If `count` is greater than the remaining size of the segment, an error
    /// is returned.
    pub fn advance(&mut self, count: u32) -> Result {
        if self.len() < count {
            return Err(code::EINVAL);
        }

        self.bio_vec.bv_offset += count;
        self.bio_vec.bv_len -= count;
        Ok(())
    }

    /// Returns the page at index `page_idx` of the pages that back this segment.
    #[inline]
    fn page(&self, page_idx: usize) -> &Page<Shared> {
        // SAFETY: By the type invariant, `bio_vec` is valid, so `bv_page` points to an array of
        // valid `struct page` that covers the segment for the duration of the borrow of the bio,
        // and callers only pass a `page_idx` within the segment. The invariants of `Shared` hold
        // for these pages:
        // - The data of a segment is shared with the submitter of the bio, and possibly with user
        //   space. The page is not a `Page<Exclusive>`, as those are frozen pages that are not
        //   shared, and no other Rust reference to the data of the page exists.
        // - The pages are not allocated by Rust, so from the point of view of Rust their data is
        //   initialized, although it may be arbitrary.
        // - The data of a segment is subject to racy writes, so the kernel only accesses it with
        //   byte-wise atomic operations.
        unsafe { Page::<Shared>::from_raw(self.bio_vec.bv_page.add(page_idx)) }
    }

    /// Read data from this segment into `dst`.
    ///
    /// Copies data from the current offset of this segment into the start of `dst`. The copy stops
    /// at the next page boundary of this segment, at the end of this segment, or at the end of
    /// `dst`, whichever comes first. This call will advance offset and reduce length of `self`.
    ///
    /// Returns the number of bytes read.
    #[inline]
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let src_offset = self.offset() % PAGE_SIZE;
        let length = (PAGE_SIZE - src_offset)
            .min(self.len() as usize)
            .min(dst.len());
        let page_idx = self.offset() / PAGE_SIZE;

        let src_page = self.page(page_idx);

        src_page
            .with_page_as_sysmem_local(src_offset, length, |src| {
                src.copy_to_slice(&mut dst[..length]);
                Ok(())
            })
            .expect("Assertion failure, bounds check failed.");

        self.advance(length as u32)
            .expect("Assertion failure, bounds check failed.");

        length
    }

    /// Write data from `src` to this segment.
    ///
    /// Copies data from the start of `src` to the current offset of this segment. The copy stops
    /// at the next page boundary of this segment, at the end of this segment, or at the end of
    /// `src`, whichever comes first. This call will advance offset and reduce length of `self`.
    ///
    /// Returns the number of bytes written.
    #[inline]
    pub fn write(&mut self, src: &[u8]) -> usize {
        let dst_offset = self.offset() % PAGE_SIZE;
        let length = (PAGE_SIZE - dst_offset)
            .min(self.len() as usize)
            .min(src.len());
        let page_idx = self.offset() / PAGE_SIZE;

        let dst_page = self.page(page_idx);

        dst_page
            .with_page_as_sysmem_local(dst_offset, length, |dst| {
                dst.copy_from_slice(&src[..length]);
                Ok(())
            })
            .expect("Assertion failure, bounds check failed.");

        self.advance(length as u32)
            .expect("Assertion failure, bounds check failed.");

        length
    }

    /// Copy zeroes to the current page of this segment.
    ///
    /// Copies  `PAGE_SIZE - (self.offset() % PAGE_SIZE` bytes of data to this
    /// segment starting at `self.offset()`. This call will advance offset and reduce length of
    /// `self`.
    ///
    /// Returns the number of bytes written to this segment.
    #[inline]
    pub fn zero_page(&mut self) -> usize {
        let offset = self.offset() % PAGE_SIZE;
        let length = (PAGE_SIZE - offset).min(self.len() as usize);
        let page_idx = self.offset() / PAGE_SIZE;

        let dst_page = self.page(page_idx);

        let fill = |dst: SysMemLocal<'_, [u8]>| {
            dst.fill_zero();
            Ok(())
        };

        dst_page
            .with_page_as_sysmem_local(offset, length, fill)
            .expect("Assertion failure, bounds check failed.");

        self.advance(length as u32)
            .expect("Assertion failure, bounds check failed.");

        length
    }
}

impl core::fmt::Display for Segment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Segment {:?} len: {}, offset: {}",
            self.bio_vec.bv_page, self.bio_vec.bv_len, self.bio_vec.bv_offset
        )
    }
}

/// An iterator over `Segment`
///
/// The iterator takes a copy of the bio's `bvec_iter` when it is created and
/// advances that copy as it yields [`Segment`]s, leaving the `Bio` untouched. A
/// `struct bvec_iter` is a standalone cursor into the bio's `bio_vec` array: as
/// described in the kernel's [immutable biovecs] documentation, the `bio_vec`
/// array is immutable once the bio is submitted and all of the position that
/// changes while iterating is held in the `bvec_iter`, not in the array. Such an
/// iterator can therefore be freely copied and moved, and advancing one copy
/// affects neither the `Bio` nor any other copy of the iterator.
///
/// [immutable biovecs]: srctree/Documentation/block/biovecs.rst
///
/// # Invariants
///
/// If `iter.bi_size` > 0, `iter` must always index a valid `bio_vec` in `bio.io_vec()`.
pub struct BioSegmentIterator<'a> {
    bio: Pin<&'a mut Bio>,
    iter: bindings::bvec_iter,
}

impl<'a> BioSegmentIterator<'a> {
    /// Create a new segment iterator for iterating the segments of `bio`. The
    /// iterator starts at the beginning of `bio`.
    #[inline(always)]
    pub(crate) fn new(bio: Pin<&'a mut Bio>) -> BioSegmentIterator<'a> {
        let iter = bio.raw_iter();

        // INVARIANT: `bio.raw_iter()` returns an index that indexes into a valid
        // `bio_vec` in `bio.io_vec()`.
        Self { bio, iter }
    }

    // The accessors in this implementation block are modelled after C side
    // macros and static functions `bvec_iter_*` and `mp_bvec_iter_*` from
    // bvec.h.

    /// Construct a `bio_vec` from the current iterator state.
    ///
    /// This will return a `bio_vec`of size <= PAGE_SIZE
    ///
    /// # Safety
    ///
    /// Caller must ensure that `self.iter.bi_size` > 0 before calling this
    /// method.
    #[inline]
    unsafe fn io_vec(&self) -> bindings::bio_vec {
        debug_assert!(self.iter.bi_size > 0);
        // SAFETY: By safety requirement of this function `self.iter.bi_size` is
        // greater than 0.
        unsafe {
            bindings::bio_vec {
                bv_page: self.page(),
                bv_len: self.len(),
                bv_offset: self.offset(),
            }
        }
    }

    /// Get the currently indexed `bio_vec` entry.
    ///
    /// # Safety
    ///
    /// Caller must ensure that `self.iter.bi_size` > 0 before calling this
    /// method.
    #[inline(always)]
    unsafe fn bvec(&self) -> &bindings::bio_vec {
        debug_assert!(self.iter.bi_size > 0);
        // SAFETY: By the safety requirement of this function and the type
        // invariant of `Self`, `self.iter.bi_idx` indexes into a valid
        // `bio_vec`
        unsafe { self.bio.io_vec().offset(self.iter.bi_idx as isize).as_ref() }
    }

    /// Get the  as u32currently indexed page, indexing into pages of order >= 0.
    ///
    /// # Safety
    ///
    /// Caller must ensure that `self.iter.bi_size` > 0 before calling this
    /// method.
    #[inline(always)]
    unsafe fn page(&self) -> *mut bindings::page {
        debug_assert!(self.iter.bi_size > 0);
        // SAFETY: By C API contract, the following offset cannot exceed pages
        // allocated to this bio.
        unsafe { self.mp_page().add(self.mp_page_idx()) }
    }

    /// Get the remaining bytes in the current page. Never more than PAGE_SIZE.
    ///
    /// # Safety
    ///
    /// Caller must ensure that `self.iter.bi_size` > 0 before calling this
    /// method.
    #[inline(always)]
    unsafe fn len(&self) -> u32 {
        debug_assert!(self.iter.bi_size > 0);
        // SAFETY: By safety requirement of this function `self.iter.bi_size` is
        // greater than 0.
        unsafe {
            self.mp_len()
                .min((bindings::PAGE_SIZE as u32) - self.offset())
        }
    }

    /// Get the offset from the last page boundary in the currently indexed
    /// `bio_vec` entry. Never more than PAGE_SIZE.
    ///
    /// # Safety
    ///
    /// Caller must ensure that `self.iter.bi_size` > 0 before calling this
    /// method.
    #[inline(always)]
    unsafe fn offset(&self) -> u32 {
        debug_assert!(self.iter.bi_size > 0);
        // SAFETY: By safety requirement of this function `self.iter.bi_size` is
        // greater than 0.
        unsafe { self.mp_offset() % (bindings::PAGE_SIZE as u32) }
    }

    /// Return the first page of the currently indexed `bio_vec` entry. This
    /// might be a multi-page entry, meaning that page might have order > 0.
    ///
    /// # Safety
    ///
    /// Caller must ensure that `self.iter.bi_size` > 0 before calling this
    /// method.
    #[inline(always)]
    unsafe fn mp_page(&self) -> *mut bindings::page {
        debug_assert!(self.iter.bi_size > 0);
        // SAFETY: By safety requirement of this function `self.iter.bi_size` is
        // greater than 0.
        unsafe { self.bvec().bv_page }
    }

    /// Get the offset in whole pages into the currently indexed `bio_vec`. This
    /// can be more than 0 is the page has order > 0.
    ///
    /// # Safety
    ///
    /// Caller must ensure that `self.iter.bi_size` > 0 before calling this
    /// method.
    #[inline(always)]
    unsafe fn mp_page_idx(&self) -> usize {
        debug_assert!(self.iter.bi_size > 0);
        // SAFETY: By safety requirement of this function `self.iter.bi_size` is
        // greater than 0.
        (unsafe { self.mp_offset() } / (bindings::PAGE_SIZE as u32)) as usize
    }

    /// Get the offset in the currently indexed `bio_vec` multi-page entry. This
    /// can be more than `PAGE_SIZE` if the page has order > 0.
    ///
    /// # Safety
    ///
    /// Caller must ensure that `self.iter.bi_size` > 0 before calling this
    /// method.
    #[inline(always)]
    unsafe fn mp_offset(&self) -> u32 {
        debug_assert!(self.iter.bi_size > 0);
        // SAFETY: By safety requirement of this function `self.iter.bi_size` is
        // greater than 0.
        unsafe { self.bvec().bv_offset + self.iter.bi_offset }
    }

    /// Get the number of remaining bytes for the currently indexed `bio_vec`
    /// entry. Can be more than PAGE_SIZE for `bio_vec` entries with pages of
    /// order > 0.
    ///
    /// # Safety
    ///
    /// Caller must ensure that `self.iter.bi_size` > 0 before calling this
    /// method.
    #[inline(always)]
    unsafe fn mp_len(&self) -> u32 {
        debug_assert!(self.iter.bi_size > 0);
        // SAFETY: By safety requirement of this function `self.iter.bi_size` is
        // greater than 0.
        self.iter
            .bi_size
            .min(unsafe { self.bvec().bv_len } - self.iter.bi_offset)
    }
}

impl<'a> core::iter::Iterator for BioSegmentIterator<'a> {
    type Item = Segment<'a>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.iter.bi_size == 0 {
            return None;
        }

        // SAFETY: We checked that `self.iter.bi_size` > 0 above.
        let bio_vec_ret = unsafe { self.io_vec() };

        // SAFETY: By existence of reference `&bio`, `bio.0` contains a valid
        // `struct bio`. By type invariant of `BioSegmentItarator` `self.iter`
        // indexes into a valid `bio_vec` entry. By C API contracit, `bv_len`
        // does not exceed the size of the bio.
        unsafe {
            bindings::bio_advance_iter_single(
                self.bio.0.get(),
                &raw mut self.iter,
                bio_vec_ret.bv_len,
            )
        };

        Some(Segment {
            bio_vec: bio_vec_ret,
            _marker: core::marker::PhantomData,
        })
    }
}

// SPDX-License-Identifier: GPL-2.0

//! Rust zblock driver
//!
use core::alloc::Layout;
use core::mem;
use core::ptr::{copy_nonoverlapping, NonNull};
use core::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use kernel::alloc::allocator::Vmalloc;
use kernel::alloc::{Allocator, Flags, KVec, NumaNode};
use kernel::error::{Error, Result};
use kernel::list::{List, ListArc, ListLinks};
use kernel::page::{PAGE_MASK, PAGE_SHIFT, PAGE_SIZE};
use kernel::prelude::*;
use kernel::rbtree::*;
use kernel::str::CString;
use kernel::sync::{new_spinlock, SpinLock};
use kernel::zalloc::*;

const SLOT_BITS: usize = PAGE_SHIFT - 6; // reserve 6 bits for the table
const MAX_SLOTS: usize = 1 << SLOT_BITS;
const SLOT_MASK: usize = (1 << SLOT_BITS) - 1;

macro_rules! round_up_pow2 {
    ($n: expr, $o: expr) => {
        (($n + (1 << $o) - 1) >> $o) << $o
    };
}

macro_rules! round_down_pow2 {
    ($n: expr, $o: expr) => {
        ($n >> $o) << $o
    };
}

const ZBLOCK_HEADER_SIZE: usize = round_up_pow2!(mem::size_of::<ZblockBlock>(), 4);

macro_rules! block_data_size {
    ($o: expr) => {
        (PAGE_SIZE * $o) - ZBLOCK_HEADER_SIZE
    };
}

macro_rules! slot_size {
    ($n: expr, $o: expr) => {
        round_down_pow2!(block_data_size!($o) / $n, 3)
    };
}

struct SlotInfo {
    info: [AtomicU64; MAX_SLOTS >> 6],
}

impl SlotInfo {
    fn init(&mut self) {
        for i in 0..(MAX_SLOTS >> 6) {
            self.info[i] = AtomicU64::new(0)
        }
    }

    fn set0(&self) {
        self.info[0].store(1, Ordering::Release);
    }

    fn find_and_set(&self, max_slots: u16) -> u16 {
        let max_slots_rem = max_slots & 0x3F;
        let i_max = (max_slots + 0x3F) >> 6;
        loop {
            for i in 0..i_max {
                let j_max = if i == i_max - 1 { max_slots_rem } else { 0x40 };
                let mut val = self.info[i as usize].load(Ordering::Acquire);
                loop {
                    let j = val.trailing_ones();
                    if j >= j_max.into() {
                        break;
                    }
                    match self.info[i as usize].compare_exchange(
                        val,
                        val | (1 << j),
                        Ordering::Release,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return (i << 6) | j as u16,
                        Err(v) => val = v,
                    }
                }
            }
        }
        // can't get here
    }
    fn clear(&self, slot: u16) {
        let rem = slot & 0x3F;
        let mut val = self.info[(slot >> 6) as usize].load(Ordering::Acquire);
        loop {
            match self.info[(slot >> 6) as usize].compare_exchange(
                val,
                val & !(1 << rem),
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(v) => val = v,
            }
        }
    }
}

#[derive(Copy, Clone)]
struct BlockDesc {
    slot_size: usize,
    n_pages: usize,
    slots_per_block: u16,
}

macro_rules! DefineBlock {
    ($n: expr, $o: expr) => {{
        BlockDesc {
            slot_size: slot_size!($n, $o),
            slots_per_block: $n,
            n_pages: $o,
        }
    }};
}

macro_rules! DescriptorArray {
    ($n: expr) => {{
        match $n {
            0x1000 => kernel::kvec![
                DefineBlock!(28, 1),
                DefineBlock!(18, 1),
                DefineBlock!(12, 1),
                DefineBlock!(10, 1),
                DefineBlock!(17, 2),
                DefineBlock!(15, 2),
                DefineBlock!(13, 2),
                DefineBlock!(6, 1),
                DefineBlock!(11, 2),
                DefineBlock!(5, 1),
                DefineBlock!(19, 4),
                DefineBlock!(9, 2),
                DefineBlock!(17, 4),
                DefineBlock!(4, 1),
                DefineBlock!(15, 4),
                DefineBlock!(7, 2),
                DefineBlock!(10, 3),
                DefineBlock!(19, 6),
                DefineBlock!(3, 1),
                DefineBlock!(20, 7),
                DefineBlock!(11, 4),
                DefineBlock!(8, 3),
                DefineBlock!(18, 7),
                DefineBlock!(17, 7),
                DefineBlock!(7, 3),
                DefineBlock!(9, 4),
                DefineBlock!(15, 7),
                DefineBlock!(4, 2),
                DefineBlock!(21, 11),
                DefineBlock!(13, 7),
                DefineBlock!(9, 5),
                DefineBlock!(7, 4),
                DefineBlock!(5, 3),
                DefineBlock!(13, 8),
                DefineBlock!(11, 7),
                DefineBlock!(3, 2),
                DefineBlock!(10, 7),
                DefineBlock!(11, 8),
                DefineBlock!(9, 7),
                DefineBlock!(6, 5),
                DefineBlock!(9, 8),
                DefineBlock!(7, 8),
            ],
            _ => kernel::kvec![
                DefineBlock!(185, 1),
                DefineBlock!(113, 1),
                DefineBlock!(86, 1),
                DefineBlock!(72, 1),
                DefineBlock!(58, 1),
                DefineBlock!(49, 1),
                DefineBlock!(42, 1),
                DefineBlock!(37, 1),
                DefineBlock!(33, 1),
                DefineBlock!(59, 2),
                DefineBlock!(27, 1),
                DefineBlock!(25, 1),
                DefineBlock!(23, 1),
                DefineBlock!(21, 1),
                DefineBlock!(39, 2),
                DefineBlock!(37, 2),
                DefineBlock!(35, 2),
                DefineBlock!(33, 2),
                DefineBlock!(31, 2),
                DefineBlock!(29, 2),
                DefineBlock!(27, 2),
                DefineBlock!(25, 2),
                DefineBlock!(12, 1),
                DefineBlock!(11, 1),
                DefineBlock!(21, 2),
                DefineBlock!(10, 1),
                DefineBlock!(19, 2),
                DefineBlock!(9, 1),
                DefineBlock!(17, 2),
                DefineBlock!(8, 1),
                DefineBlock!(15, 2),
                DefineBlock!(14, 2),
                DefineBlock!(27, 4),
                DefineBlock!(13, 2),
                DefineBlock!(25, 4),
                DefineBlock!(12, 2),
                DefineBlock!(23, 4),
                DefineBlock!(11, 2),
                DefineBlock!(21, 4),
                DefineBlock!(10, 2),
                DefineBlock!(19, 4),
                DefineBlock!(9, 2),
                DefineBlock!(17, 4),
                DefineBlock!(4, 1),
                DefineBlock!(23, 6),
                DefineBlock!(11, 3),
                DefineBlock!(7, 2),
                DefineBlock!(10, 3),
                DefineBlock!(16, 5),
                DefineBlock!(6, 2),
                DefineBlock!(11, 4),
                DefineBlock!(8, 3),
                DefineBlock!(5, 2),
                DefineBlock!(7, 3),
                DefineBlock!(11, 5),
                DefineBlock!(4, 2),
                DefineBlock!(9, 5),
                DefineBlock!(8, 5),
                DefineBlock!(3, 2),
                DefineBlock!(7, 6),
                DefineBlock!(7, 8),
            ],
        }
    }};
}

#[pin_data]
struct ZblockBlock {
    slot_info: SlotInfo,
    #[pin]
    links: ListLinks,
    free_slots: AtomicU16,
}

impl ZblockBlock {
    #[inline]
    fn init(&mut self, free_slots: u16) {
        self.slot_info.init();
        self.free_slots = AtomicU16::new(free_slots);
    }

    #[inline]
    fn as_raw(&self) -> *const ZblockBlock {
        self
    }
}

kernel::list::impl_list_arc_safe! {
    impl ListArcSafe<0> for ZblockBlock { untracked; }
}

kernel::list::impl_list_item! {
    impl ListItem<0> for ZblockBlock { using ListLinks { self.links }; }
}

#[pin_data]
struct BlockList {
    #[pin]
    inner: SpinLock<BlockListInner>,
    block_count: AtomicUsize,
}

struct BlockListInner {
    block_list: List<ZblockBlock>,
}

impl BlockList {
    fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            inner <- new_spinlock!(BlockListInner {
                block_list: List::new(),
            }, "BlockList::lock"),
            block_count: AtomicUsize::new(0),
        })
    }
}

struct ZblockPool {
    name: CString,
    block_descs: KVec<BlockDesc>,
    block_lists: Pin<KBox<[BlockList]>>,
    tree: RBTree<usize, usize>,
}

impl ZblockPool {
    fn new(name: CString, gfp: Flags) -> Result<Self> {
        let block_descs = DescriptorArray!(PAGE_SIZE)?;
        let mut pool = Self {
            block_lists: KBox::pin_slice(|_idx| BlockList::new(), block_descs.len(), gfp)?,
            block_descs,
            name,
            tree: RBTree::new(),
        };
        for i in 0..pool.num_block_desc() {
            let slot_size = pool.block_desc(i).slot_size;
            pool.tree.try_create_and_insert(slot_size, i, gfp)?;
        }
        pr_info!(
            "Created pool {:?} with {} block lists\n",
            pool.name,
            pool.num_block_desc()
        );
        Ok(pool)
    }
    #[inline]
    fn num_block_desc(&self) -> usize {
        self.block_descs.len()
    }
    #[inline]
    fn block_desc(&self, i: usize) -> &BlockDesc {
        &self.block_descs[i]
    }

    fn alloc_block(&self, block_type: usize, gfp: Flags, nid: NumaNode) -> Result<ZallocHandle> {
        // SAFETY:
        // - the align is not 0 and is a power of 2 (PAGE_SIZE)
        // - size does not overflow isize
        let layout = unsafe {
            Layout::from_size_align_unchecked(
                PAGE_SIZE * self.block_desc(block_type).n_pages,
                PAGE_SIZE,
            )
        };
        let ptr = Vmalloc::alloc(layout, gfp, nid)?;
        let block: *mut ZblockBlock = ptr.as_ptr().cast();

        // SAFETY:
        // block is guaranteed to be a valid pointer, because Vmalloc::alloc() succeeded if we
        // are here
        unsafe {
            (*block).init(self.block_desc(block_type).slots_per_block - 1);
            (*block).slot_info.set0();
        }

        let list = &self.block_lists[block_type];
        let mut inner = list.inner.lock();

        // SAFETY:
        // * block is a valid pointer to ZblockBlock which implements ListArcSafe
        // * this ZblockBlock doesn't have a ListArc reference
        // * ZblockBlock doesn't track ListArc
        inner
            .block_list
            .push_front(unsafe { ListArc::from_raw(block) });

        list.block_count.fetch_add(1, Ordering::Relaxed);
        Ok(metadata_to_handle(block, block_type, 0))
    }
}

// Helpers

#[inline]
fn metadata_to_handle(block: *const ZblockBlock, block_type: usize, slot: u16) -> ZallocHandle {
    let b: usize = block.cast::<usize>() as usize;
    ZallocHandle::from_raw(b + (block_type << SLOT_BITS) + (slot as usize))
}

#[inline]
fn handle_to_metadata(handle: ZallocHandle) -> (*mut ZblockBlock, usize, u16) {
    let h = handle.as_raw();
    let b: *mut ZblockBlock = (h & PAGE_MASK) as *mut ZblockBlock;
    let t = (h & (PAGE_SIZE - 1)) >> SLOT_BITS;
    let s = h & SLOT_MASK;
    (b, t, s as u16)
}

fn cache_find_block(list: &BlockList, block_desc: &BlockDesc) -> Option<(*const ZblockBlock, u16)> {
    let slots_per_block = block_desc.slots_per_block;
    let mut inner = list.inner.lock();
    let mut cursor = inner.block_list.cursor_front();
    if let Some(next) = cursor.peek_next() {
        let slot = next.slot_info.find_and_set(slots_per_block);
        if next.free_slots.fetch_sub(1, Ordering::Acquire) == 1 {
            // no free slots left, remove from the list and return
            let item = next.remove().into_raw();
            return Some((item, slot));
        }
        return Some((next.as_raw(), slot));
    }
    None
}

impl ZallocDriver for ZblockPool {
    fn malloc(&self, size: usize, gfp: Flags, nid: NumaNode) -> Result<ZallocHandle> {
        if size == 0 || size > PAGE_SIZE {
            return Err(EINVAL);
        }

        match self.tree.cursor_lower_bound(&size) {
            None => Err(ENOSPC),
            Some(binding) => {
                let (_, v) = binding.current();
                // *v is the block list index we will use
                match cache_find_block(&self.block_lists[*v], &self.block_descs[*v]) {
                    None => self.alloc_block(*v, gfp, nid),
                    Some((block, slot)) => Ok(metadata_to_handle(block, *v, slot)),
                }
            }
        }
    }

    unsafe fn free(&self, handle: ZallocHandle) {
        let (block, block_type, slot) = handle_to_metadata(handle);
        // SAFETY:
        // * handle is guaranteed to be valid by the framework
        // * we extract block from the handle, and since handle is valid then block is a valid
        // pointer to ZblockBlock
        let the_block: &mut ZblockBlock = unsafe { &mut *block };

        let slots_per_block = self.block_desc(block_type).slots_per_block;
        let list = &self.block_lists[block_type];
        let mut inner = list.inner.lock();
        the_block.slot_info.clear(slot);
        let prev_free_slots = the_block.free_slots.fetch_add(1, Ordering::Acquire);
        match prev_free_slots {
            val if val == slots_per_block - 1 => {
                list.block_count.fetch_sub(1, Ordering::Relaxed);
                // SAFETY: the_block can't be in a different list, it is determined by block_type
                let o = unsafe { inner.block_list.remove(the_block) };
                match o {
                    None => {
                        pr_warn!("block already removed\n");
                    }
                    Some(item) => {
                        let _item = item.into_raw();
                    }
                }
                let layout = Layout::new::<ZblockBlock>();
                // SAFETY: block is guaranteed to be a valid pointer since it's constructed
                // from handle that we have passed to the frontend before
                unsafe { Vmalloc::free(NonNull::new_unchecked(block.cast::<u8>()), layout) }
            }
            0 => {
                // SAFETY:
                // * block is a valid pointer to ZblockBlock which implements ListArcSafe
                // * this ZblockBlock doesn't have a ListArc reference
                // * ZblockBlock doesn't track ListArc
                inner
                    .block_list
                    .push_back(unsafe { ListArc::from_raw(block) });
            }
            _ => {}
        }
    }

    unsafe fn read_begin(&self, handle: ZallocHandle) -> NonNull<u8> {
        let (block, block_type, slot) = handle_to_metadata(handle);
        let handle_mem = (block as usize)
            + ZBLOCK_HEADER_SIZE
            + (slot as usize) * self.block_desc(block_type).slot_size;

        // SAFETY: handle_mem points to the allocated area within the block
        unsafe { NonNull::new_unchecked(handle_mem as *mut u8) }
    }

    unsafe fn write(&self, handle: ZallocHandle, handle_mem: NonNull<u8>, mem_len: usize) {
        let (block, block_type, slot) = handle_to_metadata(handle);

        let map_addr = (block as usize)
            + ZBLOCK_HEADER_SIZE
            + (slot as usize) * self.block_desc(block_type).slot_size;
        // SAFETY: handle_mem is a valid non-null pointer provided by the frontend, map_addr
        // points to an area within an allocated block and is therefore also valid
        unsafe {
            copy_nonoverlapping(handle_mem.as_ptr().cast(), map_addr as *mut c_void, mem_len);
        }
    }

    fn total_pages(&self) -> u64 {
        let mut total_pages: usize = 0;

        for i in 0..self.num_block_desc() {
            let block_count = self.block_lists[i].block_count.load(Ordering::Relaxed);
            total_pages += block_count * self.block_desc(i).n_pages;
        }
        total_pages as u64
    }

    fn huge_class_size(&self) -> usize {
        PAGE_SIZE
    }
}

kernel::DeclareZallocBackend!(ZblockPool);

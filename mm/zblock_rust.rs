// SPDX-License-Identifier: GPL-2.0

//! Rust zblock driver
//!
use core::alloc::Layout;
use core::mem;
use core::ptr::{copy_nonoverlapping, NonNull};
use core::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use kernel::alloc::allocator::Vmalloc;
use kernel::alloc::{Allocator, Flags, KVec, NumaNode};
use kernel::error::Error;
use kernel::list::{List, ListArc, ListLinks};
use kernel::page::{PAGE_MASK, PAGE_SHIFT, PAGE_SIZE};
use kernel::prelude::*;
use kernel::rbtree::*;
use kernel::sync::{new_spinlock, SpinLock};
use kernel::zpool::*;

kernel::module_zpool_driver! {
    type: ZblockRust,
    name: "zblock_rust",
    authors: ["Vitaly Wool"],
    description: "Rust implementation of Zblock",
    license: "GPL",
}

const SLOT_BITS: usize = PAGE_SHIFT - 6; // reserve 6 bits for the table
const MAX_SLOTS: usize = 1 << SLOT_BITS;
const SLOT_MASK: usize = (1 << SLOT_BITS) - 1;

macro_rules! round_up {
    ($n: expr, $o: expr) => {
        $n.div_ceil($o) * $o
    };
}

macro_rules! round_down {
    ($n: expr, $o: expr) => {
        ($n / $o) * $o
    };
}

macro_rules! ZBLOCK_HEADER_SIZE {
    () => {
        round_up!(mem::size_of::<ZblockBlock>(), 32)
    };
}
macro_rules! BLOCK_DATA_SIZE {
    ($o: expr) => {
        (PAGE_SIZE * $o) - ZBLOCK_HEADER_SIZE!()
    };
}

macro_rules! SLOT_SIZE {
    ($n: expr, $o: expr) => {
        round_down!(BLOCK_DATA_SIZE!($o) / $n, 8)
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
    fn set(&mut self, slot: u16) {
        let rem = slot & 0x3F;
        loop {
            let val = self.info[(slot >> 6) as usize].load(Ordering::Relaxed);
            let res = self.info[(slot >> 6) as usize].compare_exchange(
                val,
                val | (1 << rem),
                Ordering::SeqCst,
                Ordering::Relaxed,
            );
            if res == Ok(val) {
                break;
            }
        }
    }
    fn find_and_set(&mut self, max_slots: u16) -> u16 {
        let max_slots_rem = max_slots & 0x3F;
        let i_max = (max_slots + 0x3F) >> 6;
        loop {
            for i in 0..i_max {
                let j_max = if i == i_max - 1 { max_slots_rem } else { 0x40 };
                loop {
                    let val = self.info[i as usize].load(Ordering::Relaxed);
                    let j = val.trailing_ones();
                    if j >= j_max.into() {
                        break;
                    }
                    let res = self.info[i as usize].compare_exchange(
                        val,
                        val | (1 << j),
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                    );
                    if res == Ok(val) {
                        return (i << 6) | j as u16;
                    }
                }
            }
        }
        // can't get here
    }
    fn clear(&mut self, slot: u16) {
        let rem = slot & 0x3F;
        loop {
            let val = self.info[(slot >> 6) as usize].load(Ordering::Relaxed);
            let res = self.info[(slot >> 6) as usize].compare_exchange(
                val,
                val & !(1 << rem),
                Ordering::SeqCst,
                Ordering::Relaxed,
            );
            if res == Ok(val) {
                break;
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
            slot_size: SLOT_SIZE!($n, $o),
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
                DefineBlock!(16, 5),
                DefineBlock!(3, 1),
                DefineBlock!(20, 7),
                DefineBlock!(8, 3),
                DefineBlock!(5, 2),
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
                DefineBlock!(4, 4),
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
    block_descs: KVec<BlockDesc>,
    block_lists: Pin<KBox<[BlockList]>>,
    tree: RBTree<usize, usize>,
}

impl ZblockPool {
    fn new(page_size: usize, gfp: Flags) -> Result<Self> {
        let block_descs = DescriptorArray!(page_size)?;
        Ok(Self {
            block_lists: KBox::pin_slice(|_idx| BlockList::new(), block_descs.len(), gfp)?,
            block_descs,
            tree: RBTree::new(),
        })
    }
    #[inline]
    fn num_block_desc(&self) -> usize {
        self.block_descs.len()
    }
    #[inline]
    fn block_desc(&self, i: usize) -> BlockDesc {
        self.block_descs[i]
    }

    fn alloc_block(&self, block_type: usize, gfp: Flags, nid: NumaNode) -> Result<usize, Error> {
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
        let block: *mut ZblockBlock = ptr.as_ptr().cast::<ZblockBlock>();

        let the_block = from_c_block(block);
        the_block.init(self.block_desc(block_type).slots_per_block - 1);
        the_block.slot_info.set(0);

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

fn from_c_block(block: *const ZblockBlock) -> &'static mut ZblockBlock {
    // SAFETY: block is guaranteed to be a valid pointer to ZblockBlock by the caller
    let the_block: &mut ZblockBlock = unsafe { &mut *block.cast_mut() };
    the_block
}

#[inline]
fn metadata_to_handle(block: *const ZblockBlock, block_type: usize, slot: u16) -> usize {
    let b: usize = block.cast::<usize>() as usize;
    b + (block_type << SLOT_BITS) + (slot as usize)
}

#[inline]
fn handle_to_metadata(handle: usize) -> (*mut ZblockBlock, usize, u16) {
    let b: *mut ZblockBlock = (handle & PAGE_MASK) as *mut ZblockBlock;
    let t = (handle & (PAGE_SIZE - 1)) >> SLOT_BITS;
    let s = handle & SLOT_MASK;
    (b, t, s as u16)
}

fn cache_find_block(list: &BlockList, block_desc: &BlockDesc) -> Option<(*const ZblockBlock, u16)> {
    let slots_per_block = block_desc.slots_per_block;
    let mut inner = list.inner.lock();
    let mut cursor = inner.block_list.cursor_front();
    if let Some(next) = cursor.peek_next() {
        let block = next.as_raw();
        let the_block = from_c_block(block);
        if the_block.free_slots.fetch_sub(1, Ordering::Relaxed) == 1 {
            // no free slots left, remove from the list and drop the ref
            let _item = next.remove().into_raw();
        }
        let slot = the_block.slot_info.find_and_set(slots_per_block);
        return Some((block, slot));
    }
    None
}

struct ZblockRust;

impl ZpoolDriver for ZblockRust {
    type Pool = KBox<ZblockPool>;

    fn create(_name: &CStr, gfp: Flags) -> Result<KBox<ZblockPool>> {
        let mut pool = KBox::new(ZblockPool::new(PAGE_SIZE, gfp)?, gfp)?;
        for i in 0..pool.num_block_desc() {
            let slot_size = pool.block_desc(i).slot_size;
            pool.tree.try_create_and_insert(slot_size, i, gfp)?;
        }

        pr_info!("Created pool with {} block lists\n", pool.num_block_desc());
        Ok(pool)
    }
    fn destroy(p: KBox<ZblockPool>) {
        let pool = KBox::into_inner(p);
        drop(pool.tree);
        drop(pool.block_lists);
    }

    fn malloc(the_pool: &mut ZblockPool, size: usize, gfp: Flags, nid: NumaNode) -> Result<usize> {
        if size == 0 || size > PAGE_SIZE {
            return Err(EINVAL);
        }

        let cursor = the_pool.tree.cursor_lower_bound(&size);
        let block_type: usize = match cursor {
            None => {
                return Err(ENOSPC);
            }
            Some(binding) => {
                let (_k, v) = binding.current();
                *v
            }
        };

        let list = &the_pool.block_lists[block_type];
        let result = cache_find_block(list, &the_pool.block_descs[block_type]);
        match result {
            None => the_pool.alloc_block(block_type, gfp, nid),
            Some((block, slot)) => Ok(metadata_to_handle(block, block_type, slot)),
        }
    }
    unsafe fn free(the_pool: &ZblockPool, handle: usize) {
        let (block, block_type, slot) = handle_to_metadata(handle);
        let the_block = from_c_block(block);

        the_block.slot_info.clear(slot);

        let slots_per_block = the_pool.block_desc(block_type).slots_per_block;
        let list = &the_pool.block_lists[block_type];
        let mut inner = list.inner.lock();
        let prev_free_slots = the_block.free_slots.fetch_add(1, Ordering::Relaxed);
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
                drop(inner);
                let layout = Layout::new::<ZblockBlock>();
                // SAFETY: block is guaranteed to be a valid pointer since it's constructed
                // from handle that we have passed to zpool before
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

    unsafe fn read_begin(the_pool: &ZblockPool, handle: usize) -> NonNull<u8> {
        let (block, block_type, slot) = handle_to_metadata(handle);
        let handle_mem = (block as usize)
            + ZBLOCK_HEADER_SIZE!()
            + (slot as usize) * the_pool.block_desc(block_type).slot_size;

        // SAFETY: handle_mem points to the allocated area within the block
        unsafe { NonNull::new_unchecked(handle_mem as *mut u8) }
    }

    unsafe fn read_end(_pool: &ZblockPool, _handle: usize, _handle_mem: NonNull<u8>) {}

    unsafe fn write(the_pool: &ZblockPool, handle: usize, handle_mem: NonNull<u8>, mem_len: usize) {
        let (block, block_type, slot) = handle_to_metadata(handle);
        pr_debug!(
            "write: handle {:x}, slot {}, type {}\n",
            handle,
            slot,
            block_type
        );

        let map_addr = (block as usize)
            + ZBLOCK_HEADER_SIZE!()
            + (slot as usize) * the_pool.block_desc(block_type).slot_size;
        // SAFETY: handle_mem is a valid non-null pointer provided by zpool, map_addr points to
        // an area within an allocated block and is therefore also valid
        unsafe {
            copy_nonoverlapping(handle_mem.as_ptr().cast(), map_addr as *mut c_void, mem_len);
        }
    }

    fn total_pages(the_pool: &ZblockPool) -> u64 {
        let mut total_pages: usize = 0;

        for i in 0..the_pool.num_block_desc() {
            let block_count = the_pool.block_lists[i].block_count.load(Ordering::Relaxed);
            total_pages += block_count * the_pool.block_desc(i).n_pages;
        }
        total_pages as u64
    }
}

// SPDX-License-Identifier: GPL-2.0

//! Rust zblock driver
//!
use core::format_args;
use core::mem;
use core::ptr::copy_nonoverlapping;
use core::ffi::{c_void,c_ulong,c_uchar,c_int};
use core::sync::atomic::*;
use kernel::bindings::{spinlock,__spin_lock_init,spin_lock,spin_unlock,kmalloc,vmalloc,kfree,vfree_atomic};
use kernel::c_str;
use kernel::alloc::Flags;
use kernel::list::{List, ListArc, ListLinks};
use kernel::prelude::*;
use kernel::page::{PAGE_SIZE,PAGE_MASK,PAGE_SHIFT};
use kernel::rbtree::*;
use kernel::zpool::*;

module! {
    type: ZblockRust,
    name: "zblock_rust",
    author: "Vitaly Wool",
    description: "Rust implementation of Zblock",
    license: "GPL",
}

const SLOT_FREE: u8 = 0;

const SLOT_BITS: usize = PAGE_SHIFT - 6; // reserve 6 bits for the table
const MAX_SLOTS: usize = 1 << SLOT_BITS;
const SLOT_MASK: usize = (1 << SLOT_BITS) - 1;
const NUM_BLOCK_DESC: usize = 61; //37;

macro_rules! round_up {
    ($n: expr, $o: expr) => ((($n + (1 << $o) - 1) >> $o) << $o)
}

macro_rules! round_down {
    ($n: expr, $o: expr) => (($n >> $o) << $o)
}

macro_rules! ZBLOCK_HEADER_SIZE { () => (round_up!(mem::size_of::<ZblockBlock>(), 3)) }
macro_rules! BLOCK_DATA_SIZE {
    ($o: expr) => ((PAGE_SIZE * $o) - ZBLOCK_HEADER_SIZE!())
}

macro_rules! SLOT_SIZE {
    ($n: expr, $o: expr) => (round_down!(BLOCK_DATA_SIZE!($o) / $n, 4))
}

#[derive(Copy, Clone)]
struct SlotInfo {
    _s: [u8; MAX_SLOTS >> 3],
}

impl SlotInfo {
    fn new() -> Self {
        Self { _s: [ SLOT_FREE; (MAX_SLOTS >> 3) as usize ] }
    }
    fn set(&mut self, slot: u16, lock: &mut spinlock) {
        c_spin_lock(lock);
        let rem = slot % 8;
        self._s[(slot >> 3) as usize] |= 1 << rem;
        c_spin_unlock(lock);
    }
    fn test_and_set(&mut self, slot: u16, lock: &mut spinlock) -> bool {
        c_spin_lock(lock);
        let rem = slot % 8;
        let prev = self._s[(slot >> 3) as usize];
        self._s[(slot >> 3) as usize] |= 1 << rem;
        c_spin_unlock(lock);
        prev & (1 << rem) != 0
    }
    fn clear(&mut self, slot: u16, lock: &mut spinlock) {
        c_spin_lock(lock);
        let rem = slot % 8;
        self._s[(slot >> 3) as usize] &= !(1 << rem);
        c_spin_unlock(lock);
    }
    fn get(&self, slot: u16, lock: &mut spinlock) -> bool {
        c_spin_lock(lock);
        let rem = slot % 8;
        let res = self._s[(slot >> 3) as usize] & (1 << rem) != 0;
        c_spin_unlock(lock);
        res
    }
}

#[derive(Copy,Clone)]
struct BlockDesc {
    slot_size: usize,
    n_pages: usize,
    slots_per_block: u16,
}

macro_rules! DefineBlock {
    ($n: expr, $o: expr) => ({
        BlockDesc{slot_size: SLOT_SIZE!($n, $o), slots_per_block: $n, n_pages: $o }
    })
}
/*
static BLOCK_DESC: [BlockDesc; NUM_BLOCK_DESC] = [
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
	DefineBlock!(23, 6),
	DefineBlock!(11, 3),
	DefineBlock!(7, 2),
	DefineBlock!(10, 3),
	DefineBlock!(19, 6),
	DefineBlock!(6, 2),
	DefineBlock!(14, 5),
	DefineBlock!(8, 3),
	DefineBlock!(5, 2),
	DefineBlock!(12, 5),
	DefineBlock!(9, 4),
	DefineBlock!(15, 7),
	DefineBlock!(2, 1),
	DefineBlock!(15, 8),
	DefineBlock!(9, 5),
	DefineBlock!(12, 7),
	DefineBlock!(13, 8),
	DefineBlock!(6, 4),
	DefineBlock!(11, 8),
	DefineBlock!(9, 7),
	DefineBlock!(6, 5),
	DefineBlock!(9, 8),
	DefineBlock!(4, 4),
];
*/
static BLOCK_DESC: [BlockDesc; NUM_BLOCK_DESC] = [
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
];

struct ZblockBlock {
    slot_info: SlotInfo,
    lock: spinlock,
    item: *mut ZblockListItem,
    free_slots: u16,
}

#[pin_data]
struct ZblockListItem {
    block: *mut ZblockBlock,
    #[pin]
    links: ListLinks,
}

impl ZblockListItem {
    fn new(block: *mut ZblockBlock) -> Result<ListArc<Self>> {
        ListArc::pin_init(try_pin_init!(Self {
            block,
            links <- ListLinks::new(),
        }), GFP_KERNEL)
    }
}

kernel::list::impl_has_list_links! {
    impl HasListLinks<0> for ZblockListItem { self.links }
}
kernel::list::impl_list_arc_safe! {
    impl ListArcSafe<0> for ZblockListItem { untracked; }
}
kernel::list::impl_list_item! {
    impl ListItem<0> for ZblockListItem { using ListLinks; }
}

struct BlockList {
    block_count: usize,
    block_list: List<ZblockListItem>,
    lock: spinlock,
}

impl BlockList {
    fn declare_spinlock() -> spinlock {
        let mut lock: spinlock = <_>::default();

        unsafe {
            __spin_lock_init(&mut lock, "pool_lock".as_ptr() as *const u8, core::ptr::null_mut())
        }
        lock
    }

    fn new() -> Self {
        Self {
            block_count: 0,
            block_list: List::new(),
            lock: Self::declare_spinlock(),
        }
    }
}

struct ZblockPool {
    block_lists: [BlockList; NUM_BLOCK_DESC],
    tree: RBTree<usize,usize>
}

type GfpT = u32;

// Helpers

fn c_spin_lock(lock: &mut spinlock) {
    unsafe { spin_lock(lock); }
}

fn c_spin_unlock(lock: &mut spinlock) {
    unsafe { spin_unlock(lock); }
}


macro_rules! metadata_to_handle {
    ($bl:expr, $typ:expr, $sl: expr) => {
        {
            let b: *mut usize = $bl as *mut usize;
            let out = (b as usize) + (($typ as usize) << SLOT_BITS) + ($sl as usize);
            out
        }
    }
}

macro_rules! handle_to_block {
    ($h: expr) => {
        {
            let b: *mut ZblockBlock = ($h & PAGE_MASK as usize) as *mut ZblockBlock;
            b
        }
    }
}

macro_rules! handle_to_block_type {
    ($h: expr) => {
        {
            let t = (($h as usize) & (PAGE_SIZE - 1)) >> SLOT_BITS;
            t
        }
    }
}

macro_rules! handle_to_slot {
    ($h: expr) => (($h & SLOT_MASK) as u16)
}

fn cache_insert_block(block: *mut ZblockBlock, list: &mut BlockList)
{
    let zblock: &mut ZblockBlock = unsafe { &mut *block };

    if zblock.item.is_null() {
        let l_arc = ZblockListItem::new(block).expect("REASON");
        zblock.item = l_arc.into_raw() as *mut ZblockListItem;
    }
    unsafe {
        list.block_list.push_front(ListArc::from_raw(zblock.item));
    }

    pr_debug!("adding block {:x} ({:x}) to vector, count {}\n",
             block as u64, zblock.item as u64, list.block_count);
}

fn cache_append_block(block: *mut ZblockBlock, list: &mut BlockList)
{
    pr_debug!("cache_insert_block\n");
    let zblock: &mut ZblockBlock = unsafe { &mut *block };

    if zblock.item.is_null() {
        let l_arc = ZblockListItem::new(block).expect("REASON");
        zblock.item = l_arc.into_raw() as *mut ZblockListItem;
    }
    unsafe {
        list.block_list.push_back(ListArc::from_raw(zblock.item));
    }

    pr_debug!("adding block {:x} ({:x}) to vector, count {}\n",
             block as u64, zblock.item as u64, list.block_count);
}

fn cache_find_block(list: &mut BlockList, block_type: usize, slot: &mut u16) -> *mut ZblockBlock
{
    pr_debug!("cache_find_block\n");
    c_spin_lock(&mut list.lock);
    let mut cursor = list.block_list.cursor_front();

    let peeker = cursor.peek_next();

    if peeker.is_none() {
        c_spin_unlock(&mut list.lock);
        pr_debug!("block not found\n");
        return core::ptr::null_mut()
    }
    let block: *mut ZblockBlock = peeker.unwrap().block;
    let zblock: &mut ZblockBlock = unsafe { &mut *block };

    pr_debug!("found block {:x}\n", block as u64);
    zblock.free_slots -= 1;
    if zblock.free_slots == 0 {
        unsafe {
            list.block_list.remove(&*zblock.item);
            zblock.item = core::ptr::null_mut();
        }
    }
    c_spin_unlock(&mut list.lock);
    for i in 0..BLOCK_DESC[block_type].slots_per_block {
        if  !zblock.slot_info.test_and_set(i, &mut zblock.lock) {
            *slot = i;
            break;
        }
    }
    block
}

fn alloc_block(pool: &mut ZblockPool, block_type: usize, gfp: GfpT, handle: *mut usize)
                -> *mut ZblockBlock
{
    pr_debug!("alloc_block: type {}\n", block_type);
    let block: *mut ZblockBlock;
    unsafe {
        block = vmalloc(PAGE_SIZE * BLOCK_DESC[block_type].n_pages) as *mut ZblockBlock;
        if block.is_null() {
            return block;
        }
        __spin_lock_init(&mut (*block).lock,
                         "block_lock".as_ptr() as *const u8,
                         core::ptr::null_mut());
        pr_debug!("{:x}\n", block as u64);

        (*block).item = core::ptr::null_mut();
        let mut info = SlotInfo::new();
        info.set(0, &mut (*block).lock);
        (*block).slot_info = info; 
        (*block).free_slots = BLOCK_DESC[block_type].slots_per_block - 1;
        *handle = metadata_to_handle!(block, block_type, 0);
        pr_debug!("handle {:x}\n", *handle);
    }
    let list = &mut pool.block_lists[block_type];
    cache_insert_block(block as *mut ZblockBlock, list);
    list.block_count += 1;

    block
}

#[derive(Copy,Clone)]
struct ZblockRust {
    _dummy: u32,
}

unsafe impl Sync for ZblockRust {}
unsafe impl Send for ZblockRust {}

static RUSTY_BLOCK: ZblockRust = ZblockRust::new();
static ZPOOL_DRIVER: ZpoolDriver<ZblockRust> = ZpoolDriver::new(RUSTY_BLOCK);

impl ZblockRust {
    const fn new() -> Self {
        Self { _dummy: 0 }
    }
}

impl Zpool for ZblockRust {
    fn Create(_name: *const u8, gfp: GfpT) -> *mut c_void {
        let p = unsafe { kmalloc(mem::size_of::<ZblockPool>(), gfp) } as *mut ZblockPool;
        if p.is_null() {
            return core::ptr::null_mut();
        }
        unsafe { (*p).tree = RBTree::new(); }
        for i in 0..NUM_BLOCK_DESC {
            let mut block_list = BlockList::new();
            unsafe {
                copy_nonoverlapping(&mut block_list as *mut BlockList,
                                    &mut (*p).block_lists[i] as  *mut BlockList,
                                    1); 
                (*p).tree.try_create_and_insert(BLOCK_DESC[i].slot_size, i, GFP_KERNEL);
            }
        }
        p as *mut c_void
    }
    fn Destroy(pool: *mut c_void) {
        unsafe {
            kfree(pool);
        }
    }

    fn Malloc(pool: *mut c_void, size: usize, gfp: GfpT, handle: *mut usize, nid: c_int) -> c_int {
        pr_debug!("zblock_pool_alloc, size {}\n", size);
        if size == 0 || size > PAGE_SIZE {
            return -22; // EINVAL
        }

        let p = pool as *mut ZblockPool;
        let cursor = unsafe { (*p).tree.cursor_lower_bound(&size) };
        if cursor.is_none() { // TODO?
            return -28; // ENOSPC
        }
        let binding = cursor.unwrap();
        let (k, v) = binding.current();
        let block_type = *v;

        let the_pool: &mut ZblockPool = unsafe {&mut *(pool as *mut ZblockPool) };
        let list = &mut the_pool.block_lists[block_type];

        loop {
            let mut slot: u16 = 0;
            let mut block = cache_find_block(list, block_type, &mut slot);
            if !block.is_null() {
                unsafe { *handle = metadata_to_handle!(block, block_type, slot) };
                return 0;
            }

            // TODO: use bindings
            const __GFP_MOVABLE: u32 = 1 << 3;
            block = alloc_block(the_pool, block_type, gfp & !__GFP_MOVABLE, handle);
            if block.is_null() {
                return -1; // TODO
            }
            return 0;
        }
    }
    fn Free(pool: *mut c_void, handle: usize) {
        let block: *mut ZblockBlock = handle_to_block!(handle);
        let zblock: &mut ZblockBlock = unsafe { &mut *block };
        let block_type = handle_to_block_type!(handle);
        let slot = handle_to_slot!(handle);
        let the_pool = unsafe { &mut *(pool as *mut ZblockPool) };
        let list = &mut the_pool.block_lists[block_type];

        zblock.slot_info.clear(slot, &mut zblock.lock);

        c_spin_lock(&mut list.lock);
        zblock.free_slots += 1;
        if zblock.free_slots == BLOCK_DESC[block_type].slots_per_block {
            list.block_count -= 1;

            pr_debug!("removing block {:x} ({:x}), count {}\n",
                     block as u64, zblock.item as u64, list.block_count);
            unsafe {
                list.block_list.remove(&*zblock.item);
                vfree_atomic(block as *mut c_void);
            }
            c_spin_unlock(&mut list.lock);
        } else if zblock.free_slots == 1 {
            cache_append_block(block as *mut ZblockBlock, list);
            c_spin_unlock(&mut list.lock);
        } else {
            c_spin_unlock(&mut list.lock);
        }
    }

    fn ReadBegin(_pool: *mut c_void, handle: usize, _local_copy: *mut c_void) -> *mut c_void {
        let block: *mut ZblockBlock = handle_to_block!(handle);
        let block_type = handle_to_block_type!(handle);
        let slot = handle_to_slot!(handle);
        pr_debug!("Read: handle {:x}, slot {}, type {}\n", handle, slot, block_type);

        let map_addr = (block as u64) + (ZBLOCK_HEADER_SIZE!() as u64) +
            (slot as u64) * (BLOCK_DESC[block_type].slot_size as u64);
        pr_debug!("map_addr {:x}\n", map_addr);
        map_addr as *mut c_void
    }

    fn ReadEnd(_pool: *mut c_void, _handle: usize, _handle_mem: *mut c_void) {
    }

    fn Write(_pool: *mut c_void, handle: usize, handle_mem: *mut c_void, mem_len: usize) {
        let block: *mut ZblockBlock = handle_to_block!(handle);
        let block_type = handle_to_block_type!(handle);
        let slot = handle_to_slot!(handle);
        pr_debug!("write: handle {:x}, slot {}, type {}\n", handle, slot, block_type);

        let map_addr = (block as u64) + (ZBLOCK_HEADER_SIZE!() as u64) +
            (slot as u64) * (BLOCK_DESC[block_type].slot_size as u64);
        pr_debug!("map_addr {:x}\n", map_addr);
        unsafe { copy_nonoverlapping(handle_mem, map_addr as *mut c_void, mem_len); }
    }

    fn TotalPages(pool: *mut c_void) -> u64 {
        let mut total_pages: usize = 0;
        let the_pool: &mut ZblockPool = unsafe {&mut *(pool as *mut ZblockPool) };

        for i in 0..NUM_BLOCK_DESC {
            total_pages += the_pool.block_lists[i].block_count * BLOCK_DESC[i].n_pages;
        }
        total_pages as u64
    }
}

impl kernel::Module for ZblockRust {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_debug!("Rusty zblock (init)\n");
        unsafe { let _ = ZPOOL_DRIVER.register(c_str!("zblock_rust"), _module); };
        Ok( RUSTY_BLOCK )
    }
}

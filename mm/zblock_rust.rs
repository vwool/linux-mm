// SPDX-License-Identifier: GPL-2.0

//! Rust zblock driver
//!
use core::ffi::{c_void,c_int};
use core::format_args;
use core::mem;
use core::ptr::{copy_nonoverlapping, null_mut};
use core::sync::atomic::{AtomicU16,Ordering};
use kernel::alloc::{Flags,KVec};
use kernel::bindings::{vmalloc_node,spinlock,__spin_lock_init,spin_lock,spin_unlock};
use kernel::bindings::{rcu_read_lock,rcu_read_unlock,kvfree_call_rcu,callback_head};
use kernel::c_str;
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

const SLOT_BITS: usize = PAGE_SHIFT - 6; // reserve 6 bits for the table
const MAX_SLOTS: usize = 1 << SLOT_BITS;
const SLOT_MASK: usize = (1 << SLOT_BITS) - 1;
const NUM_BLOCK_DESC: usize = 61; //37;

macro_rules! round_up {
    ($n: expr, $o: expr) => ((($n + $o - 1) / $o) * $o)
}

macro_rules! round_down {
    ($n: expr, $o: expr) => (($n / $o) * $o)
}

macro_rules! ZBLOCK_HEADER_SIZE { () => (round_up!(mem::size_of::<ZblockBlock>(), 32)) }
macro_rules! BLOCK_DATA_SIZE {
    ($o: expr) => ((PAGE_SIZE * $o) - ZBLOCK_HEADER_SIZE!())
}

macro_rules! SLOT_SIZE {
    ($n: expr, $o: expr) => (round_down!(BLOCK_DATA_SIZE!($o) / $n, 16))
}

//#[derive(Copy, Clone)]
struct SlotInfo {
    _s: [u8; MAX_SLOTS >> 3],
    m: AtomicU16, 
}

impl SlotInfo {
    #[allow(dead_code)]
    fn init(&mut self) {
        for i in 0..(MAX_SLOTS >> 3) {
            self._s[i] = 0
        }
        self.m = AtomicU16::new(0);
    }
    fn lock_internal(&mut self) {
        loop {
            if !self.m.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                break;
            }
        }
    }
    fn unlock_internal(&mut self) {
        self.m.store(0, Ordering::SeqCst);
    }
    fn set(&mut self, slot: u16) {
        self.lock_internal();
        let rem = slot & 7;
        self._s[(slot >> 3) as usize] |= 1 << rem;
        self.unlock_internal();
    }
    fn find_and_set(&mut self, max_slots: u16) -> u16 {
        self.lock_internal();
        let i_max = (max_slots + 7) >> 3;
        for i in 0..i_max {
            let mut v = self._s[i as usize];
            let mut mask = 0xFF;
            for j in 0..8 {
                if v == mask {
                    break;
                }
                if v & 1 == 0 {
                    self._s[i as  usize] |= 1 << j;
                    self.unlock_internal();
                    return (i << 3) | (j as u16);
                }
                v >>= 1; mask >>= 1;
            }
        }
        self.unlock_internal();
        MAX_SLOTS as u16
    }
    fn clear(&mut self, slot: u16) {
        self.lock_internal();
        let rem = slot & 7;
        self._s[(slot >> 3) as usize] &= !(1 << rem);
        self.unlock_internal();
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

#[pin_data]
struct ZblockBlock {
    slot_info: SlotInfo,
    rcu_head: callback_head,
    #[pin]
    links: ListLinks,
    free_slots: AtomicU16,
}

impl ZblockBlock {
    #[inline]
    fn as_raw(&self) -> *const ZblockBlock {
        self
    }
}

kernel::list::impl_has_list_links! {
    impl HasListLinks<0> for ZblockBlock { self.links }
}
kernel::list::impl_list_arc_safe! {
    impl ListArcSafe<0> for ZblockBlock { untracked; }
}
kernel::list::impl_list_item! {
    impl ListItem<0> for ZblockBlock { using ListLinks; }
}

struct BlockList {
    block_count: usize,
    lock: spinlock,
    block_list: List<ZblockBlock>,
}

impl BlockList {
    fn declare_spinlock() -> spinlock {
        let mut lock: spinlock = <_>::default();

        unsafe {
            __spin_lock_init(&mut lock, "pool_lock".as_ptr() as *const u8, null_mut())
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

impl ZblockPool {
    fn new() -> Self {
        Self {
            block_lists: core::array::from_fn(|_i| BlockList::new()),
            tree: RBTree::new(),
        }
    }
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

fn atomic_op_if(a: &AtomicU16, op: impl Fn(u16) -> u16, pred: impl Fn(u16) -> bool)
                -> Option<u16> {
    loop {
        let x = a.load(Ordering::SeqCst);
        if !pred(x) {
            return None;
        } else {
            if a.compare_exchange(x, op(x), Ordering::SeqCst, Ordering::SeqCst).is_err() {
                continue;
            }
        }
        return Some(x);
    }
}

fn cache_insert_block(block: *mut ZblockBlock, list: &mut BlockList)
{
    unsafe {
        list.block_list.push_front(ListArc::from_raw(block));
    }
}

fn cache_append_block(block: *mut ZblockBlock, list: &mut BlockList)
{
    unsafe {
        list.block_list.push_back(ListArc::from_raw(block));
    }
}

fn cache_find_block(list: &mut BlockList, block_type: usize) ->
                    Result<(*const ZblockBlock, u16), Error> {
    unsafe { rcu_read_lock(); }
    let mut cursor = list.block_list.cursor_front();
    loop {
        let peeker = cursor.peek_next();

        if peeker.is_none() {
            unsafe { rcu_read_unlock(); }
            return Err(Error::from_errno(-1)); // TODO
        }
        let block: *mut ZblockBlock = (*peeker.unwrap()).as_raw() as *mut ZblockBlock;
        let slot: u16;
        let slots_per_block = BLOCK_DESC[block_type].slots_per_block;

        unsafe {
            let prev_free_slots = atomic_op_if(&(*block).free_slots,
                                  |x| x - 1, |x| x > 0 && x < slots_per_block);

            if prev_free_slots.is_none() {
                cursor.move_next();
                continue;
            } else if prev_free_slots == Some(1) {
                c_spin_lock(&mut list.lock);
                if (*block).free_slots.load(Ordering::SeqCst) == 0 {
                    let o = list.block_list.remove(&*block);
                    let _item = o.unwrap().into_raw();
                }
                c_spin_unlock(&mut list.lock);
            }
            slot = (*block).slot_info.find_and_set(slots_per_block);
        }
        pr_debug!("slot {} / {}\n", slot, BLOCK_DESC[block_type].slots_per_block);
        unsafe { rcu_read_unlock(); }
        return Ok((block,slot));
    }
    // can't really get here
}

fn alloc_block(pool: &mut ZblockPool, block_type: usize, gfp: GfpT, nid: c_int, handle: *mut usize)
                -> *mut ZblockBlock
{
    let block: *mut ZblockBlock;
    let list = &mut pool.block_lists[block_type];
    unsafe {
        block = vmalloc_node(PAGE_SIZE * BLOCK_DESC[block_type].n_pages, PAGE_SIZE,
                             gfp | 0x100 /* GFP_ZERO */, nid, null_mut()) as *mut ZblockBlock;
        if block.is_null() {
            return block;
        }
        (*block).slot_info.set(0);
        let free_slots = BLOCK_DESC[block_type].slots_per_block - 1;
        (*block).free_slots = AtomicU16::new(free_slots);
        *handle = metadata_to_handle!(block, block_type, 0);
    }
    c_spin_lock(&mut list.lock);
    cache_insert_block(block as *mut ZblockBlock, list);
    c_spin_unlock(&mut list.lock);
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
        let pool = KBox::new(ZblockPool::new(), Flags::new(gfp));
        if pool.is_err() {
            return null_mut();
        }
        let pool = unsafe { Box::into_raw(pool.unwrap_unchecked()) };
        unsafe {
            for i in 0..NUM_BLOCK_DESC {
                let t = (*pool).tree.try_create_and_insert(BLOCK_DESC[i].slot_size, i,
                                                           Flags::new(gfp));
                if t.is_err() {
                    let unboxed_zpool = KBox::into_inner(KBox::from_raw(pool));
                    drop(unboxed_zpool.tree);
                    return null_mut();
                }
            }
        }
        pool as *mut c_void
    }
    fn Destroy(pool: *mut c_void) {
        let zpool = pool as *mut ZblockPool;
        unsafe {
            let unboxed_zpool = KBox::into_inner(KBox::from_raw(zpool));
            drop(unboxed_zpool.tree);
            // TODO drop block lists
        }
    }

    fn Malloc(p: *mut c_void, size: usize, gfp: GfpT, handle: *mut usize, nid: c_int) -> c_int {
        if size == 0 || size > PAGE_SIZE {
            return -22; // EINVAL
        }

        let pool = p as *mut ZblockPool;
        let cursor = unsafe { (*pool).tree.cursor_lower_bound(&size) };
        if cursor.is_none() { // TODO?
            return -28; // ENOSPC
        }
        let binding = cursor.unwrap();
        let (_k, v) = binding.current();
        let block_type = *v;

        let list = unsafe { &mut (*pool).block_lists[block_type] };
        let result = cache_find_block(list, block_type);
        if !result.is_err() {
            let (block,slot) = result.unwrap();
            unsafe { *handle = metadata_to_handle!(block, block_type, slot) };
            return 0;
        }

        let block = unsafe { alloc_block(&mut *pool, block_type, gfp, nid, handle) };
        if block.is_null() {
            return -1; // TODO
        }
        return 0;
    }
    fn Free(p: *mut c_void, handle: usize) {
        let block: *mut ZblockBlock = handle_to_block!(handle);
        let block_type = handle_to_block_type!(handle);
        let slot = handle_to_slot!(handle);
        let pool = p as *mut ZblockPool;
        let list = unsafe { &mut (*pool).block_lists[block_type] };

        c_spin_lock(&mut list.lock);
        unsafe { (*block).slot_info.clear(slot) };
        let prev_free_slots = unsafe { (*block).free_slots.fetch_add(1, Ordering::SeqCst) };
        if prev_free_slots + 1 == BLOCK_DESC[block_type].slots_per_block {
            list.block_count -= 1;
            unsafe {
                let o = list.block_list.remove(&*block);
                let _item = o.unwrap().into_raw();
                c_spin_unlock(&mut list.lock);
                kvfree_call_rcu(&mut (*block).rcu_head as *mut callback_head, block as *mut c_void);
                return;
            };
        } else if prev_free_slots == 0 {
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

        let map_addr = (block as u64) + (ZBLOCK_HEADER_SIZE!() as u64) +
            (slot as u64) * (BLOCK_DESC[block_type].slot_size as u64);
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
        unsafe { let _ = ZPOOL_DRIVER.register(c_str!("zblock_rust"), _module); };
        Ok( RUSTY_BLOCK )
    }
}

// SPDX-License-Identifier: GPL-2.0

//! Rust zblock driver
//!
use core::format_args;
use core::mem;
use core::ptr::{copy_nonoverlapping, null_mut};
use core::sync::atomic::{AtomicU16,Ordering};
use kernel::alloc::{Flags,KVec};
use kernel::bindings::{vmalloc_node,vfree_atomic,spinlock,__spin_lock_init,spin_lock,spin_unlock};
use kernel::bindings::__GFP_ZERO;
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

macro_rules! DescriptorArray {
    ($n: expr) => ({
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
    })
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
    block_descs: KVec<BlockDesc>,
    block_lists: KVec<BlockList>,
    tree: RBTree<usize,usize>
}

impl ZblockPool {
    fn new(page_size: usize) -> Result<Self> {
        Ok(Self {
            block_descs: DescriptorArray!(page_size)?,
            block_lists: KVec::new(),
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
}

// Helpers

#[allow(invalid_reference_casting)]
fn c_pool_as_mutable(pool: &ZblockPool) -> &mut ZblockPool {
    // SAFETY: A temporary measure until incorrect usage of `&mut T` is removed.
    unsafe { &mut *(pool as *const ZblockPool as *mut ZblockPool) }
}

fn from_c_block(block: *mut ZblockBlock) -> &'static mut ZblockBlock {
    let the_block: &mut ZblockBlock = unsafe {&mut *(block as *mut ZblockBlock) };
    the_block
}

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
    let mut x = a.load(Ordering::SeqCst);
    loop {
        if !pred(x) {
            return None;
        }
        match a.compare_exchange_weak(x, op(x), Ordering::SeqCst, Ordering::Relaxed) {
            Ok(y) => return Some(y),
            Err(z) => x = z,
        }
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

fn cache_find_block(list: &mut BlockList, block_desc: &BlockDesc) ->
                    Result<(*const ZblockBlock, u16), Error> {
    let slots_per_block = block_desc.slots_per_block;
    c_spin_lock(&mut list.lock);
    loop {
        let mut cursor = list.block_list.cursor_front();
        let peeker = cursor.peek_next();

        if peeker.is_none() {
            c_spin_unlock(&mut list.lock);
            return Err(ENOENT);
        }
        let block: *mut ZblockBlock = (*peeker.unwrap()).as_raw() as *mut ZblockBlock;
        let the_block = from_c_block(block);
        let slot: u16;
        let prev_free_slots = atomic_op_if(&the_block.free_slots,
                                           |x| x - 1, |x| x > 0 && x < slots_per_block);
        match prev_free_slots {
            None => continue,
            Some (1) => {
                let o = unsafe { list.block_list.remove(the_block) };
                match o {
                    None => { pr_info!("block already removed 1\n");},
                    Some(item) => { let _item = item.into_raw(); },
                }
            },
            Some (_) => {}
            }
        slot = the_block.slot_info.find_and_set(slots_per_block);
        pr_debug!("slot {} / {}\n", slot, block_desc.slots_per_block);
        c_spin_unlock(&mut list.lock);
        return Ok((block,slot));
    }
    // can't really get here
}

fn alloc_block(pool: &mut ZblockPool, block_type: usize, gfp: Flags, nid: i32) -> Result<usize, Error> {
    let block: *mut ZblockBlock;
    unsafe {
        block = vmalloc_node(PAGE_SIZE * pool.block_desc(block_type).n_pages, PAGE_SIZE,
                             gfp.as_raw() | __GFP_ZERO, nid, null_mut()) as *mut ZblockBlock;
        if block.is_null() {
            return Err(ENOMEM);
        }
        (*block).slot_info.set(0);
        let free_slots = pool.block_desc(block_type).slots_per_block - 1;
        (*block).free_slots = AtomicU16::new(free_slots);
    }
    let list = &mut pool.block_lists[block_type];
    c_spin_lock(&mut list.lock);
    cache_insert_block(block, list);
    c_spin_unlock(&mut list.lock);
    list.block_count += 1;

    Ok(metadata_to_handle!(block, block_type, 0))
}

#[derive(Copy,Clone)]
struct ZblockRust {
    name: &'static CStr,
}

impl ZblockRust {
    const fn new(mod_name: &'static CStr) -> Self {
        Self {
            name: mod_name,
        }
    }
    const fn get_name(&self) -> &'static CStr {
        self.name
    }
}

static RUSTY_BLOCK: ZblockRust = ZblockRust::new(c_str!("zblock_rust"));
static ZPOOL_DRIVER: ZpoolDriver<ZblockRust> = ZpoolDriver::new(RUSTY_BLOCK);

impl Zpool for ZblockRust {
    type Pool = KBox<ZblockPool>;

    fn create(_name: *const u8, gfp: Flags) -> Result<KBox<ZblockPool>, Error> {
        let mut pool = KBox::new(ZblockPool::new(PAGE_SIZE)?, gfp)?;
        for i in 0..pool.num_block_desc() {
            pool.block_lists.push(BlockList::new(), gfp)?;
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

    fn malloc(the_pool: &ZblockPool, size: usize, gfp: Flags, nid: i32) -> Result<usize,Error> {
        if size == 0 || size > PAGE_SIZE {
            return Err(EINVAL);
        }

        let the_pool = c_pool_as_mutable(the_pool);

        let block_type: usize;
        let cursor = the_pool.tree.cursor_lower_bound(&size);
        match cursor {
            None => {
                return Err(ENOSPC);
            },
            Some(binding) => {
                let (_k, v) = binding.current();
                block_type = *v;
            }
        }

        let list = &mut the_pool.block_lists[block_type];
        let result = cache_find_block(list, &the_pool.block_descs[block_type]);
        match result {
            Err(_) => alloc_block(the_pool, block_type, gfp, nid),
            Ok((block,slot)) => Ok(metadata_to_handle!(block, block_type, slot))
        }
    }
    fn free(the_pool: &ZblockPool, handle: usize) {
        let the_pool = c_pool_as_mutable(the_pool);
        let block: *mut ZblockBlock = handle_to_block!(handle);
        let block_type = handle_to_block_type!(handle);
        let slot = handle_to_slot!(handle);
        let the_block = from_c_block(block);
        let slots_per_block = the_pool.block_desc(block_type).slots_per_block;

        the_block.slot_info.clear(slot);

        let list = &mut the_pool.block_lists[block_type];
        c_spin_lock(&mut list.lock);
        let prev_free_slots = the_block.free_slots.fetch_add(1, Ordering::SeqCst);
        match prev_free_slots {
            val if val == slots_per_block - 1 => {
                list.block_count -= 1;
                let o = unsafe { list.block_list.remove(the_block) };
                match o {
                    None => { pr_warn!("block already removed\n");},
                    Some(item) => { let _item = item.into_raw(); },
                }
                unsafe { vfree_atomic(block as *mut c_void) };
            },
            0 => { cache_append_block(block, list); },
            _ => {},
        }
        c_spin_unlock(&mut list.lock);
    }

    fn read_begin(the_pool: &ZblockPool, handle: usize) -> usize {
        let block: *mut ZblockBlock = handle_to_block!(handle);
        let block_type = handle_to_block_type!(handle);
        let slot = handle_to_slot!(handle);

        let map_addr = (block as usize) + ZBLOCK_HEADER_SIZE!() +
            (slot as usize) * the_pool.block_desc(block_type).slot_size;
        map_addr
    }

    fn read_end(_pool: &ZblockPool, _handle: usize, _handle_mem: *mut c_void) {
    }

    fn write(the_pool: &ZblockPool, handle: usize, handle_mem: *mut c_void, mem_len: usize) {
        let block: *mut ZblockBlock = handle_to_block!(handle);
        let block_type = handle_to_block_type!(handle);
        let slot = handle_to_slot!(handle);
        pr_debug!("write: handle {:x}, slot {}, type {}\n", handle, slot, block_type);

        let map_addr = (block as usize) + ZBLOCK_HEADER_SIZE!() +
            (slot as usize) * the_pool.block_desc(block_type).slot_size;
        unsafe { copy_nonoverlapping(handle_mem, map_addr as *mut c_void, mem_len); }
    }

    fn total_pages(the_pool: &ZblockPool,) -> u64 {
        let mut total_pages: usize = 0;

        for i in 0..the_pool.num_block_desc() {
            total_pages += the_pool.block_lists[i].block_count * the_pool.block_desc(i).n_pages;
        }
        total_pages as u64
    }
}

impl kernel::Module for ZblockRust {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        unsafe { let _ = ZPOOL_DRIVER.register(RUSTY_BLOCK.get_name(), _module); };
        Ok( RUSTY_BLOCK )
    }
}

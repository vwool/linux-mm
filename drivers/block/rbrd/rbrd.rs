// SPDX-License-Identifier: GPL-2.0

//! A RAM backed block device driver written in Rust.
//!
//! The driver is based on the Rust null block driver and works like the C
//! `brd` driver: every device stores its contents in pages that are allocated
//! on the first write to them. Unlike `brd`, the pages are tracked in a flat
//! array with one slot per page of the device, allocated when the device is
//! created, instead of in an XArray. Reads of never written areas return
//! zeroes. Discards free whole pages.
//!
//! Devices are created through configfs:
//!
//! ```text
//! mkdir /sys/kernel/config/rbrd/rram0
//! echo 512 > /sys/kernel/config/rbrd/rram0/size     # MiB
//! echo 1 > /sys/kernel/config/rbrd/rram0/power      # creates /dev/rram0
//! ```
//!
//! The contents of a device are lost when it is powered off.

mod configfs;

use kernel::{
    bindings,
    block::{
        self,
        bio::Segment,
        error::{
            code::BLK_STS_NOTSUPP,
            BlkError,
            BlkResult, //
        },
        mq::{
            self,
            gen_disk::{
                self,
                GenDisk, //
            },
            Command,
            IdleRequest,
            Operations,
            TagSet, //
        }, //
    },
    numa::NumaNode,
    page::{
        Exclusive,
        Page,
        PagePrivateBitGuard,
        PAGE_SHIFT,
        PAGE_SIZE, //
    },
    prelude::*,
    sync::{
        aref::ARef,
        atomic::{
            Acquire,
            Atomic,
            Full,
            Relaxed, //
        },
        Arc, //
    },
    types::Owned, //
};

use core::ptr::{
    self,
    NonNull, //
};

module! {
    type: RamDiskModule,
    name: "rbrd",
    authors: ["Vitaly Wool"],
    description: "Rust RAM backed block device driver",
    license: "GPL v2",
}

#[pin_data]
struct RamDiskModule {
    #[pin]
    configfs_subsystem: kernel::configfs::Subsystem<configfs::Config>,
}

impl kernel::InPlaceModule for RamDiskModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        pr_info!("Rust RAM block driver loaded\n");

        try_pin_init!(Self {
            configfs_subsystem <- configfs::subsystem(),
        })
    }
}

/// Maximum size of a single discard request.
///
/// Discards are processed in atomic context, page by page. Bound the amount of
/// work done per request; larger discards are split by the block layer.
const MAX_DISCARD_SECTORS: u32 = (128 << 20) >> block::SECTOR_SHIFT;

/// GFP flags for allocations in the I/O path, which must not sleep.
fn io_gfp() -> kernel::alloc::Flags {
    GFP_NOWAIT | __GFP_NOWARN
}

struct RamDisk;

impl RamDisk {
    fn new(name: &CStr, block_size: u32, capacity_mib: u64) -> Result<Arc<GenDisk<Self>>> {
        if capacity_mib == 0 {
            return Err(EINVAL);
        }

        let capacity_sectors = capacity_mib
            .checked_mul(1 << (20 - block::SECTOR_SHIFT))
            .ok_or(EINVAL)?;
        let nr_pages = usize::try_from(capacity_mib)?
            .checked_mul((1 << 20) / PAGE_SIZE)
            .ok_or(EINVAL)?;

        // One hardware queue per CPU. Besides avoiding contention on a single
        // hardware context, this keeps blk-mq from attaching the mq-deadline
        // scheduler, which it does by default for single queue devices.
        //
        // Requests are completed within `queue_rq()`, which releases their tag
        // right away, so only a few tags per queue are ever in use at once. A
        // small depth keeps the requests preallocated for every queue cheap.
        let tagset = Arc::pin_init(
            TagSet::new(
                kernel::cpu::nr_cpu_ids(),
                (),
                32,
                1,
                NumaNode::NO_NODE,
                mq::tag_set::Flags::default(),
                // Requests complete in `queue_rq()` and never time out; keep
                // the block layer default.
                0,
            ),
            GFP_KERNEL,
        )?;
        let storage = KBox::try_pin_init(Storage::new(nr_pages), GFP_KERNEL)?;

        gen_disk::GenDiskBuilder::new()
            .capacity_sectors(capacity_sectors)
            .logical_block_size(block_size)?
            .physical_block_size(block_size)?
            .max_hw_discard_sectors(MAX_DISCARD_SECTORS)
            .build(fmt!("{}", name.to_str()?), tagset, storage)
    }
}

/// A flat array of page slots, one per page of the device.
///
/// Each slot is either null or holds a pointer obtained from
/// [`ARef::into_raw`], i.e. owns one reference to that page.
struct PageArray(KVVec<Atomic<*mut Page>>);

impl PageArray {
    fn new(nr_pages: usize) -> Result<Self> {
        let mut slots = KVVec::with_capacity(nr_pages, GFP_KERNEL)?;
        for _ in 0..nr_pages {
            // Cannot fail: the capacity was reserved above.
            slots.push(Atomic::new(ptr::null_mut()), GFP_KERNEL)?;
        }
        Ok(Self(slots))
    }

    fn slot(&self, index: usize) -> Result<&Atomic<*mut Page>> {
        self.0.get(index).ok_or(EIO)
    }
}

impl Drop for PageArray {
    fn drop(&mut self) {
        for slot in self.0.iter() {
            if let Some(ptr) = NonNull::new(slot.xchg(ptr::null_mut(), Relaxed)) {
                // SAFETY: Non-null slots hold pointers from `ARef::into_raw`
                // and own the reference they stand for, which we take back.
                drop(unsafe { ARef::from_raw(ptr) });
            }
        }
    }
}

/// The backing store of a RAM disk.
///
/// Slot `n` of `pages` holds the page for bytes `n * PAGE_SIZE .. (n + 1) *
/// PAGE_SIZE` of the device, or null if it was never written or since
/// discarded.
///
/// The slot array is allocated up front and lives as long as the device, so,
/// unlike the nodes of an XArray, it never needs RCU protection, and no lock is
/// taken to look up, insert or remove a page: [`Self::lookup_page`] is an
/// atomic load followed by a speculative reference (see [`Page::try_get_raw`]),
/// [`Self::try_insert_page`] a compare-and-exchange on an empty slot, and
/// [`Self::discard`] an exchange with null. The price is 8 bytes of slot per
/// page of capacity, whether or not it is ever written.
///
/// Copies to and from a backing page are serialized by a bit spinlock in its
/// `page->private` (see [`Storage::lock_copy`]), which also gives access to the
/// data of the page as a slice. Unlike the C `brd` driver, overlapping I/O thus
/// never observes a partially written block. The lock is held only for the
/// duration of a single copy, never while looking up, allocating or removing a
/// page.
#[pin_data]
struct Storage {
    pages: PageArray,
    /// A zeroed page, the source for reads of pages that are not allocated.
    zero_page: Owned<Page<Exclusive>>,
}

/// The bit of `page->private` that serializes copies to and from a backing
/// page.
const PAGE_COPY_LOCK_BIT: u32 = 0;

impl Storage {
    /// Locks the copy lock of a backing page.
    fn lock_copy(page: &Page) -> PagePrivateBitGuard<'_, PAGE_COPY_LOCK_BIT> {
        // SAFETY: Backing pages are allocated by this driver with
        // `Page::alloc_page` and never handed to anybody else, their `private`
        // field is only used for this lock, and their data is only accessed
        // while holding it.
        unsafe { page.lock_private_bit::<PAGE_COPY_LOCK_BIT>() }
    }

    fn new(nr_pages: usize) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            pages: PageArray::new(nr_pages)?,
            zero_page: Page::alloc_exclusive(GFP_KERNEL)?,
        })
    }

    /// Looks up the page in `slot`, without taking any lock.
    ///
    /// Takes a reference on the page in the slot with an operation that fails
    /// if the page's reference count has already reached zero, i.e. if a
    /// concurrent [`Self::discard`] already released it, and then re-reads the
    /// slot to confirm it still holds the same page, retrying otherwise:
    /// without that check, a page that was concurrently discarded and whose
    /// memory was reused for something else in the meantime could be mistaken
    /// for one that is still ours. See [`Page::try_get_raw`] for more on why
    /// this is safe.
    fn lookup_page(slot: &Atomic<*mut Page>) -> Option<ARef<Page>> {
        loop {
            let ptr = NonNull::new(slot.load(Acquire))?;

            // SAFETY: Every non-null pointer stored in a slot came from
            // `ARef::into_raw`, i.e. is a `struct page` pointer; `struct page`
            // objects are never freed or reused for anything else, so `ptr`
            // always points at a valid one, whether or not it is (still)
            // actually owned by this slot.
            let page = unsafe { Page::try_get_raw(ptr) }?;

            if slot.load(Relaxed) == ptr.as_ptr() {
                return Some(page);
            }

            // The slot was concurrently emptied, or now holds a different
            // page; `page` is not (or no longer) ours to use. Drop our
            // reference and retry.
            drop(page);
        }
    }

    /// Allocates a page and installs it in `slot` if the slot is still empty.
    ///
    /// Returns `None` if another writer installed a page there first, in which
    /// case the caller looks it up again.
    fn try_insert_page(slot: &Atomic<*mut Page>) -> Result<Option<ARef<Page>>> {
        // The page is always zeroed.
        let page = Page::alloc_page(io_gfp() | __GFP_HIGHMEM)?;
        // Take our own reference before handing the other one to the slot.
        let ours = page.clone();
        let ptr = ARef::into_raw(page);

        // `Full` ordering publishes the zeroed page contents along with the
        // pointer, pairing with the `Acquire` load in `lookup_page()`.
        if slot.cmpxchg(ptr::null_mut(), ptr.as_ptr(), Full).is_ok() {
            return Ok(Some(ours));
        }

        drop(ours);
        // SAFETY: `ptr` came from `into_raw` above and was not stored, so we
        // still own the reference it stands for.
        drop(unsafe { ARef::from_raw(ptr) });
        Ok(None)
    }

    /// Returns the page in `slot`, allocating it if needed.
    fn get_or_insert_page(slot: &Atomic<*mut Page>) -> Result<ARef<Page>> {
        loop {
            if let Some(page) = Self::lookup_page(slot) {
                return Ok(page);
            }
            if let Some(page) = Self::try_insert_page(slot)? {
                return Ok(page);
            }
        }
    }

    /// Returns the range of page indices covered by `bytes` bytes at `sector`.
    fn page_range(&self, sector: u64, bytes: u32) -> Result<core::ops::Range<usize>> {
        let start = sector << block::SECTOR_SHIFT;
        let end = start + u64::from(bytes);
        let range =
            usize::try_from(start >> PAGE_SHIFT)?..usize::try_from(end.div_ceil(PAGE_SIZE as u64))?;

        // The block layer never issues I/O beyond the capacity of the device,
        // which the array covers in full.
        if range.end > self.pages.0.len() {
            return Err(EIO);
        }
        Ok(range)
    }

    /// Allocates the backing pages a write of `bytes` bytes at `sector` needs.
    ///
    /// This is done before the request is started, so that an allocation
    /// failure can be reported to the block layer as `BLK_STS_RESOURCE`, which
    /// makes it retry the request later.
    fn populate(&self, sector: u64, bytes: u32) -> Result {
        for index in self.page_range(sector, bytes)? {
            let slot = self.pages.slot(index)?;
            if slot.load(Relaxed).is_null() {
                Self::get_or_insert_page(slot)?;
            }
        }
        Ok(())
    }

    /// Transfer all data of `rq` between the request buffers and the backing
    /// store.
    fn transfer(&self, rq: &mut Owned<mq::Request<RamDisk>>, write: bool) -> Result {
        let mut pos = rq.sector() << block::SECTOR_SHIFT;
        self.page_range(rq.sector(), rq.bytes())?;

        for bio in rq.bio_iter_mut() {
            for mut segment in bio.segment_iter() {
                // Each copy stops at the next page boundary of both the
                // segment and the backing store.
                while !segment.at_end() {
                    let slot = self.pages.slot(usize::try_from(pos >> PAGE_SHIFT)?)?;
                    let page_off = (pos as usize) & (PAGE_SIZE - 1);

                    let len = if write {
                        Self::write_chunk(&mut segment, slot, page_off)?
                    } else {
                        self.read_chunk(&mut segment, slot, page_off)
                    };

                    pos += len as u64;
                }
            }
        }

        Ok(())
    }

    fn read_chunk(&self, segment: &mut Segment<'_>, slot: &Atomic<*mut Page>, off: usize) -> usize {
        match Self::lookup_page(slot) {
            Some(page) => Self::lock_copy(&page).with_slice(|data| segment.write(&data[off..])),
            // Never written; reads as zeroes.
            None => segment.write(&self.zero_page.as_slice()[off..]),
        }
    }

    fn write_chunk(
        segment: &mut Segment<'_>,
        slot: &Atomic<*mut Page>,
        off: usize,
    ) -> Result<usize> {
        // The page was allocated by `populate()`, unless a concurrent discard
        // freed it again since.
        let page = Self::get_or_insert_page(slot)?;
        let mut guard = Self::lock_copy(&page);
        Ok(guard.with_mut_slice(|data| segment.read(&mut data[off..])))
    }

    /// Free all backing pages that are entirely covered by the range.
    fn discard(&self, sector: u64, bytes: u32) {
        let start = sector << block::SECTOR_SHIFT;
        let end = start + u64::from(bytes);
        let first = start.div_ceil(PAGE_SIZE as u64);
        let last = end >> PAGE_SHIFT;

        for index in first..last {
            let Some(slot) = usize::try_from(index)
                .ok()
                .and_then(|index| self.pages.0.get(index))
            else {
                break;
            };

            if let Some(ptr) = NonNull::new(slot.xchg(ptr::null_mut(), Full)) {
                // SAFETY: Non-null slots hold pointers from `ARef::into_raw`
                // and own the reference they stand for, which we just took
                // back by emptying the slot. A concurrent `lookup_page()` that
                // already took its own reference keeps the page alive until
                // that reference is dropped too.
                drop(unsafe { ARef::from_raw(ptr) });
            }
        }
    }
}

#[vtable]
impl Operations for RamDisk {
    type RequestData = ();
    type QueueData = Pin<KBox<Storage>>;
    type HwData = ();
    type TagSetData = ();

    fn new_request_data() -> impl PinInit<Self::RequestData> {
        Ok(())
    }

    fn queue_rq(
        _hw_data: (),
        storage: Pin<&Storage>,
        rq: Owned<IdleRequest<Self>>,
        _is_last: bool,
    ) -> BlkResult {
        // Errors returned before the request is started end it with that
        // status, or, for `BLK_STS_RESOURCE`, make the block layer retry it.
        match rq.command() {
            Command::Read | Command::Discard | Command::Flush => {}
            Command::Write => {
                if storage.populate(rq.sector(), rq.bytes()).is_err() {
                    return Err(BlkError::from_blk_status(bindings::BLK_STS_RESOURCE));
                }
            }
            _ => return Err(BLK_STS_NOTSUPP),
        }

        let mut rq = rq.start();

        let status = match rq.command() {
            Command::Read => storage.transfer(&mut rq, false),
            Command::Write => storage.transfer(&mut rq, true),
            Command::Discard => {
                storage.discard(rq.sector(), rq.bytes());
                Ok(())
            }
            // There is no volatile cache; data is in RAM once written.
            _ => Ok(()),
        };

        match status {
            Ok(()) => rq.end_ok(),
            Err(_) => rq.end(bindings::BLK_STS_IOERR),
        }

        Ok(())
    }

    fn commit_rqs(_hw_data: (), _storage: Pin<&Storage>) {}

    fn init_hctx(_tagset_data: (), _hctx_idx: u32) -> Result<Self::HwData> {
        Ok(())
    }

    fn complete(_rq: ARef<mq::Request<Self>>) {
        // All requests are completed synchronously in `queue_rq`.
    }
}

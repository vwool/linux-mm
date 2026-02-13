// SPDX-License-Identifier: GPL-2.0

use kernel::{
    alloc::scoped::{
        NoIo,
        ScopeKind, //
    },
    block::{
        PAGE_SECTOR_MASK,
        SECTOR_SHIFT, //
    },
    page::{
        Exclusive,
        Page,
        PAGE_SIZE, //
    },
    prelude::*,
    types::Owned,
    uapi::PAGE_SECTORS, //
};

// TODO: Use rust bitmap
static_assert!((PAGE_SIZE >> SECTOR_SHIFT) <= 64);

pub(crate) struct NullBlockPage {
    page: Owned<Page<Exclusive>>,
    status: u64,
    block_size: u32,
}

impl NullBlockPage {
    pub(crate) fn new(block_size: u32) -> Result<KBox<Self>> {
        NoIo::with(|| {
            Ok(KBox::new(
                Self {
                    page: Page::alloc_exclusive(GFP_KERNEL)?,
                    status: 0,
                    block_size,
                },
                GFP_KERNEL,
            )?)
        })
    }

    pub(crate) fn set_occupied(&mut self, sector: u64) {
        let idx = sector & u64::from(PAGE_SECTOR_MASK);
        self.status |= 1 << idx;
    }

    pub(crate) fn set_free(&mut self, sector: u64) {
        let idx = sector & u64::from(PAGE_SECTOR_MASK);
        self.status &= !(1 << idx);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.status == 0
    }

    pub(crate) fn reset(&mut self) {
        self.status = 0;
    }

    pub(crate) fn is_full(&self) -> bool {
        let blocks_per_page = PAGE_SIZE >> self.block_size.trailing_zeros();
        let shift = PAGE_SECTORS as usize / blocks_per_page;

        for i in 0..blocks_per_page {
            if self.status & (1 << (i * shift)) == 0 {
                return false;
            }
        }

        true
    }

    pub(crate) fn page_mut(&mut self) -> &mut Owned<Page<Exclusive>> {
        &mut self.page
    }

    pub(crate) fn page(&self) -> &Owned<Page<Exclusive>> {
        &self.page
    }
}

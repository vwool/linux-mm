// SPDX-License-Identifier: GPL-2.0

//! Fault injection capabilities infrastructure.
//!
//! This module provides a Rust API for the kernel fault injection framework. Fault injection allows
//! simulation of failures in kernel code paths to test error handling.
//!
//! [`FaultConfig`] represents a fault injection control point that can be:
//!
//! - Attached to a configfs tree as a default group, allowing userspace control of fault injection
//!   parameters. Wrap it in an [`UnattachedGroup`] and pass that to [`Group::new`].
//! - Queried via [`FaultConfig::should_fail`] to determine if an operation should be simulated as
//!   failing.
//!
//! Please see the [fault injection documentation] for details on configuring and using fault
//! injection from userspace.
//!
//! C header: [`include/linux/fault-inject.h`](srctree/include/linux/fault-inject.h)
//!
//! # Examples
//!
//! ```
//! use kernel::configfs::UnattachedGroup;
//! use kernel::fault_injection::FaultConfig;
//!
//! // The token grants permission to attach the control point to a `configfs::Group` as a
//! // default group. Pass it to `configfs::Group::new`.
//! let control_point = UnattachedGroup::new(FaultConfig::new(c"timeout_inject"), GFP_KERNEL)?;
//!
//! // Keep a handle for querying the control point from the code path under test.
//! let timeout_inject = control_point.clone_arc();
//!
//! // A control point does not inject failures until userspace sets a non-zero probability.
//! assert!(!timeout_inject.should_fail(1));
//! # Ok::<(), Error>(())
//! ```
//!
//! [fault injection documentation]: srctree/Documentation/fault-injection/fault-injection.rst
//! [`UnattachedGroup`]: kernel::configfs::UnattachedGroup
//! [`Group::new`]: kernel::configfs::Group::new

use crate::{prelude::*, types::Opaque};

/// A fault injection control point.
///
/// This type wraps a `struct fault_config` from the C fault injection framework. It provides a way
/// to create controllable fault injection points that can be configured via configfs.
///
/// When attached to a configfs subsystem as a default group, userspace can configure fault
/// injection parameters through the configfs interface. The kernel code can then query
/// [`FaultConfig::should_fail`] to determine whether to simulate a failure.
///
/// # Invariants
///
/// - `self.inner` is always a valid `struct fault_config`.
/// - `self` owns the reference on the `struct config_item` embedded in `self.inner.group` that
///   `fault_config_init` acquired.
#[pin_data(PinnedDrop)]
pub struct FaultConfig {
    #[pin]
    inner: Opaque<bindings::fault_config>,
}

#[pinned_drop]
impl PinnedDrop for FaultConfig {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: By type invariant, `self.inner` is a valid `struct fault_config`, so the embedded
        // `struct config_item` is initialized, and `self` owns the reference that
        // `fault_config_init` acquired on it.
        //
        // `fault_config_type` does not install a `release` operation, so this does not free the
        // allocation backing `self`. It only releases the resources that configfs associated with
        // the item.
        unsafe { bindings::config_item_put(&raw mut (*self.inner.get()).group.cg_item) };
    }
}

impl FaultConfig {
    /// Create a new [`FaultConfig`].
    ///
    /// If attached to a configfs group, this [`FaultConfig`] will appear as a directory named
    /// `name`.
    pub fn new(name: &CStr) -> impl PinInit<Self> + use<'_> {
        pin_init!(Self {
            // INVARIANT: The allocation is zeroed and `fault_config_init` initializes the
            // embedded `struct config_group`, so `self.inner` is a valid `struct fault_config`.
            inner <- Opaque::zeroed().chain(|inner| {
                let ptr = inner.get();
                // SAFETY: `ptr` points to a zeroed allocation and the second argument is null
                // terminated string.
                unsafe { bindings::fault_config_init(ptr, name.as_char_ptr()) };
                Ok(())
            }),
        })
    }

    /// Query for failure.
    ///
    /// Returns [`true`] if the operation should fail.
    ///
    /// `size` is the amount of the resource consumed by the operation. It is subtracted from the
    /// configured `space` budget on each call, and failure injection is suppressed while `space` is
    /// greater than `size`. For allocation-style users this is typically the number of bytes; users
    /// that inject based on the number of operations performed pass `1`. A negative `size`
    /// replenishes the `space` budget by `-size` (i.e. grows the budget) and suppresses the failure
    /// for that call.
    ///
    /// See the `space` field in the [fault injection documentation] for
    /// details.
    ///
    /// [fault injection documentation]: srctree/Documentation/fault-injection/fault-injection.rst
    #[inline]
    pub fn should_fail(&self, size: isize) -> bool {
        // SAFETY: By type invariant, `self` is always valid.
        let attr = unsafe { &raw mut (*self.inner.get()).attr };

        // SAFETY: By type invariant, `self` is always valid.
        unsafe { bindings::should_fail(attr, size) }
    }
}

// SAFETY: `fault_config_init` initializes the embedded `struct config_group` with
// `config_group_init_type_name`, and by type invariant `self.inner` stays a valid `struct
// fault_config` in place for as long as `self` is live. `group_ptr` returns a pointer to a field of
// `self.inner`, so it returns the same pointer on every call. By type invariant, `self` owns the
// reference on the embedded `struct config_item` and releases it when dropped. No method of
// `FaultConfig` adds the group as a default group of any group.
unsafe impl kernel::configfs::CDefaultGroup for FaultConfig {
    fn group_ptr(&self) -> *mut bindings::config_group {
        // SAFETY: By type invariant, `self.inner` is valid.
        unsafe { &raw mut (*self.inner.get()).group }
    }
}

// SAFETY: `FaultConfig` has no task affinity. The only operation it performs outside of
// `should_fail` is the `config_item_put` in `PinnedDrop`, which may run in any task.
unsafe impl Send for FaultConfig {}

// SAFETY: The only method taking `&self` is `should_fail`, which the C fault injection framework
// supports calling concurrently from any task. The `times` and `space` counters it updates are
// atomics, and the verbose reporting path is serialized by `attr.ratelimit_state`. The remaining
// fields of `struct fault_attr` are plain integers that C races against concurrent configfs
// stores by design: they are statistical knobs and an inexact call counter.
unsafe impl Sync for FaultConfig {}

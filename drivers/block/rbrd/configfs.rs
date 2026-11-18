// SPDX-License-Identifier: GPL-2.0

use super::RamDisk;
use kernel::{
    block::mq::gen_disk::{
        GenDisk,
        GenDiskBuilder, //
    },
    configfs::{
        self,
        AttributeOperations, //
    },
    configfs_attrs,
    fmt::Write as _,
    new_mutex,
    page::PAGE_SIZE,
    prelude::*,
    str::{
        kstrtobool_bytes,
        CString, //
    },
    sync::{
        Arc,
        Mutex, //
    }, //
};

pub(crate) fn subsystem() -> impl PinInit<kernel::configfs::Subsystem<Config>, Error> {
    let item_type = configfs_attrs! {
        container: configfs::Subsystem<Config>,
        data: Config,
        child: DeviceConfig,
        attributes: [
            features: 0,
        ],
    };

    kernel::configfs::Subsystem::new(c"rbrd", item_type, try_pin_init!(Config {}))
}

#[pin_data]
pub(crate) struct Config {}

#[vtable]
impl AttributeOperations<0> for Config {
    type Data = Config;

    fn show(_this: &Config, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let mut writer = kernel::str::Formatter::new(page);
        writer.write_str("blocksize,size,power\n")?;
        Ok(writer.bytes_written())
    }
}

#[vtable]
impl configfs::GroupOperations for Config {
    type Child = DeviceConfig;

    fn make_group(
        &self,
        name: &CStr,
    ) -> Result<impl PinInit<configfs::Group<DeviceConfig>, Error>> {
        let item_type = configfs_attrs! {
            container: configfs::Group<DeviceConfig>,
            data: DeviceConfig,
            attributes: [
                power: 0,
                blocksize: 1,
                size: 2,
            ],
        };

        Ok(configfs::Group::new(
            name.try_into()?,
            item_type,
            try_pin_init!(DeviceConfig {
                data <- new_mutex!(DeviceConfigInner {
                    powered: false,
                    block_size: 512,
                    disk: None,
                    capacity_mib: 64,
                    name: name.try_into()?,
                }),
            }),
            core::iter::empty(),
        ))
    }
}

#[pin_data]
pub(crate) struct DeviceConfig {
    #[pin]
    data: Mutex<DeviceConfigInner>,
}

#[pin_data]
struct DeviceConfigInner {
    powered: bool,
    name: CString,
    block_size: u32,
    capacity_mib: u64,
    disk: Option<Arc<GenDisk<RamDisk>>>,
}

#[vtable]
impl configfs::AttributeOperations<0> for DeviceConfig {
    type Data = DeviceConfig;

    fn show(this: &DeviceConfig, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let mut writer = kernel::str::Formatter::new(page);

        if this.data.lock().powered {
            writer.write_str("1\n")?;
        } else {
            writer.write_str("0\n")?;
        }

        Ok(writer.bytes_written())
    }

    fn store(this: &DeviceConfig, page: &[u8]) -> Result {
        let power_op = kstrtobool_bytes(page)?;
        let mut guard = this.data.lock();

        if !guard.powered && power_op {
            guard.disk = Some(RamDisk::new(
                &guard.name,
                guard.block_size,
                guard.capacity_mib,
            )?);
            guard.powered = true;
        } else if guard.powered && !power_op {
            // Removes the disk and frees all of its contents.
            drop(guard.disk.take());
            guard.powered = false;
        }

        Ok(())
    }
}

#[vtable]
impl configfs::AttributeOperations<1> for DeviceConfig {
    type Data = DeviceConfig;

    fn show(this: &DeviceConfig, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let mut writer = kernel::str::Formatter::new(page);
        writer.write_fmt(fmt!("{}\n", this.data.lock().block_size))?;
        Ok(writer.bytes_written())
    }

    fn store(this: &DeviceConfig, page: &[u8]) -> Result {
        let mut guard = this.data.lock();
        if guard.powered {
            return Err(EBUSY);
        }

        let text = core::str::from_utf8(page)?.trim();
        let value = text.parse::<u32>().map_err(|_| EINVAL)?;

        GenDiskBuilder::<RamDisk>::validate_block_size(value)?;
        guard.block_size = value;
        Ok(())
    }
}

#[vtable]
impl configfs::AttributeOperations<2> for DeviceConfig {
    type Data = DeviceConfig;

    fn show(this: &DeviceConfig, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let mut writer = kernel::str::Formatter::new(page);
        writer.write_fmt(fmt!("{}\n", this.data.lock().capacity_mib))?;
        Ok(writer.bytes_written())
    }

    fn store(this: &DeviceConfig, page: &[u8]) -> Result {
        let mut guard = this.data.lock();
        if guard.powered {
            return Err(EBUSY);
        }

        let text = core::str::from_utf8(page)?.trim();
        let value = text.parse::<u64>().map_err(|_| EINVAL)?;
        if value == 0 {
            return Err(EINVAL);
        }

        guard.capacity_mib = value;
        Ok(())
    }
}

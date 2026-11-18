// SPDX-License-Identifier: GPL-2.0

#include <linux/bit_spinlock.h>

__rust_helper void rust_helper_bit_spin_lock(int bitnum, unsigned long *addr)
{
	bit_spin_lock(bitnum, addr);
}

__rust_helper void rust_helper_bit_spin_unlock(int bitnum, unsigned long *addr)
{
	bit_spin_unlock(bitnum, addr);
}

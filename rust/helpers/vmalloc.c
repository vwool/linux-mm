// SPDX-License-Identifier: GPL-2.0

#include <linux/vmalloc.h>

void * __must_check __realloc_size(2)
rust_helper_vrealloc(const void *p, size_t size, gfp_t flags)
{
	return vrealloc(p, size, flags);
}

void * __must_check
rust_helper_vmalloc(size_t size)
{
	return vmalloc(size);
}

void
rust_helper_vfree(void *ptr)
{
	vfree(ptr);
}

void
rust_helper_vfree_atomic(void *ptr)
{
	vfree_atomic(ptr);
}

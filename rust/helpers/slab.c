// SPDX-License-Identifier: GPL-2.0

#include <linux/slab.h>

void * __must_check __realloc_size(2)
rust_helper_krealloc(const void *objp, size_t new_size, gfp_t flags)
{
	return krealloc(objp, new_size, flags);
}

void * __must_check
rust_helper_kmalloc(size_t size, gfp_t flags)
{
	return kmalloc(size, flags);
}

void
rust_helper_kfree(void *ptr)
{
	kfree(ptr);
}

void * __must_check __realloc_size(2)
rust_helper_kvrealloc(const void *p, size_t size, gfp_t flags)
{
	return kvrealloc(p, size, flags);
}

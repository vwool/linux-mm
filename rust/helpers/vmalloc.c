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

void * __must_check
rust_helper_vmalloc_node(size_t size, size_t align, gfp_t gfp_mask, int node, const void *caller)
{
	return __vmalloc_node(size, align, gfp_mask, node, caller);
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

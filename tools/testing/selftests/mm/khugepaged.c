#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>

#include "linux/magic.h"

#include "vm_util.h"
#include "thp_settings.h"
#include "../kselftest.h"

#define BASE_ADDR ((void *)(1UL << 30))
static unsigned long hpage_pmd_size;
static unsigned long page_size;
static int hpage_pmd_nr;
static int anon_order;

#define PID_SMAPS "/proc/self/smaps"
#define TEST_FILE "collapse_test_file"

#define MAX_LINE_LENGTH 500

enum vma_type {
	VMA_ANON,
	VMA_FILE,
	VMA_SHMEM,
};

struct mem_ops {
	void *(*setup_area)(int nr_hpages);
	void (*cleanup_area)(void *p, unsigned long size);
	void (*fault)(void *p, unsigned long start, unsigned long end);
	bool (*check_huge)(void *addr, int nr_hpages);
	const char *name;
};

static struct mem_ops *file_ops;
static struct mem_ops *anon_ops;
static struct mem_ops *shmem_ops;

struct collapse_context {
	void (*collapse)(const char *msg, char *p, int nr_hpages,
			 struct mem_ops *ops, bool expect);
	bool enforce_pte_scan_limits;
	const char *name;
};

static struct collapse_context *khugepaged_context;
static struct collapse_context *madvise_context;

struct file_info {
	const char *dir;
	char path[PATH_MAX];
	enum vma_type type;
	int fd;
	char dev_queue_read_ahead_path[PATH_MAX];
};

static struct file_info finfo;
static bool skip_settings_restore;

static void success(const char *msg)
{
	ksft_test_result_pass("%s\n", msg);
}

static void fail(const char *msg)
{
	ksft_test_result_fail("%s\n", msg);
}

static void skip(const char *msg)
{
	ksft_test_result_skip("\e%s\n", msg);
}

static void restore_settings_atexit(void)
{
	if (skip_settings_restore)
		return;

	thp_restore_settings();
	ksft_print_msg("Restored THP and khugepaged settings...\n");

	skip_settings_restore = true;
}

static void restore_settings(int sig)
{
	/* exit() will invoke the restore_settings_atexit handler. */
	ksft_finished();
}

static void save_settings(void)
{
	ksft_print_msg("Save THP and khugepaged settings...\n");
	if (file_ops && finfo.type == VMA_FILE)
		thp_set_read_ahead_path(finfo.dev_queue_read_ahead_path);
	thp_save_settings();

	success("OK");

	atexit(restore_settings_atexit);
	signal(SIGTERM, restore_settings);
	signal(SIGINT, restore_settings);
	signal(SIGHUP, restore_settings);
	signal(SIGQUIT, restore_settings);
}

static void get_finfo(const char *dir)
{
	struct stat path_stat;
	struct statfs fs;
	char buf[1 << 10];
	char path[PATH_MAX];
	char *str, *end;

	finfo.dir = dir;
	stat(finfo.dir, &path_stat);
	if (!S_ISDIR(path_stat.st_mode))
		ksft_exit_fail_msg("%s: Not a directory (%s)\n", __func__, finfo.dir);

	if (snprintf(finfo.path, sizeof(finfo.path), "%s/" TEST_FILE,
		     finfo.dir) >= sizeof(finfo.path))
		ksft_exit_fail_msg("%s: Pathname is too long\n", __func__);

	if (statfs(finfo.dir, &fs))
		ksft_exit_fail_msg("statfs(): %s\n", strerror(errno));

	finfo.type = fs.f_type == TMPFS_MAGIC ? VMA_SHMEM : VMA_FILE;
	if (finfo.type == VMA_SHMEM)
		return;

	/* Find owning device's queue/read_ahead_kb control */
	if (snprintf(path, sizeof(path), "/sys/dev/block/%d:%d/uevent",
		     major(path_stat.st_dev), minor(path_stat.st_dev)) >= sizeof(path))
		ksft_exit_fail_msg("%s: Pathname is too long\n", __func__);

	if (read_file(path, buf, sizeof(buf)) < 0)
		ksft_exit_fail_msg("read_file(read_num): %s\n", strerror(errno));

	if (strstr(buf, "DEVTYPE=disk")) {
		/* Found it */
		if (snprintf(finfo.dev_queue_read_ahead_path,
			     sizeof(finfo.dev_queue_read_ahead_path),
			     "/sys/dev/block/%d:%d/queue/read_ahead_kb",
			     major(path_stat.st_dev), minor(path_stat.st_dev))
		    >= sizeof(finfo.dev_queue_read_ahead_path))
			ksft_exit_fail_msg("%s: Pathname is too long: %s\n", __func__,
					   strerror(errno));
		return;
	}
	if (!strstr(buf, "DEVTYPE=partition"))
		ksft_exit_fail_msg("%s: Unknown device type: %s\n", __func__, path);
	/*
	 * Partition of block device - need to find actual device.
	 * Using naming convention that devnameN is partition of
	 * device devname.
	 */
	str = strstr(buf, "DEVNAME=");
	if (!str)
		ksft_exit_fail_msg("%s: Could not read: %s", __func__, path);

	str += 8;
	end = str;
	while (*end) {
		if (isdigit(*end)) {
			*end = '\0';
			if (snprintf(finfo.dev_queue_read_ahead_path,
				     sizeof(finfo.dev_queue_read_ahead_path),
				     "/sys/block/%s/queue/read_ahead_kb",
				     str) >= sizeof(finfo.dev_queue_read_ahead_path))
				ksft_exit_fail_msg("%s: Pathname is too long\n", __func__);

			return;
		}
		++end;
	}
	ksft_exit_fail_msg("%s: Could not read: %s\n", __func__, path);
}

static bool check_swap(void *addr, unsigned long size)
{
	bool swap = false;
	int ret;
	FILE *fp;
	char buffer[MAX_LINE_LENGTH];
	char addr_pattern[MAX_LINE_LENGTH];

	ret = snprintf(addr_pattern, MAX_LINE_LENGTH, "%08lx-",
		       (unsigned long) addr);
	if (ret >= MAX_LINE_LENGTH)
		ksft_exit_fail_msg("%s: Pattern is too long\n", __func__);

	fp = fopen(PID_SMAPS, "r");
	if (!fp)
		ksft_exit_fail_msg("%s: Failed to open file %s\n", __func__, PID_SMAPS);

	if (!check_for_pattern(fp, addr_pattern, buffer, sizeof(buffer)))
		goto err_out;

	ret = snprintf(addr_pattern, MAX_LINE_LENGTH, "Swap:%19ld kB",
		       size >> 10);
	if (ret >= MAX_LINE_LENGTH)
		ksft_exit_fail_msg("%s: Pattern is too long\n", __func__);

	/*
	 * Fetch the Swap: in the same block and check whether it got
	 * the expected number of hugeepages next.
	 */
	if (!check_for_pattern(fp, "Swap:", buffer, sizeof(buffer)))
		goto err_out;

	if (strncmp(buffer, addr_pattern, strlen(addr_pattern)))
		goto err_out;

	swap = true;
err_out:
	fclose(fp);
	return swap;
}

static void *alloc_mapping(int nr)
{
	void *p;

	p = mmap(BASE_ADDR, nr * hpage_pmd_size, PROT_READ | PROT_WRITE,
		 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (p != BASE_ADDR)
		ksft_exit_fail_msg("Failed to allocate VMA at %p\n", BASE_ADDR);

	return p;
}

static void fill_memory(int *p, unsigned long start, unsigned long end)
{
	int i;

	for (i = start / page_size; i < end / page_size; i++)
		p[i * page_size / sizeof(*p)] = i + 0xdead0000;
}

/*
 * MADV_COLLAPSE is a best-effort request and may fail if an internal
 * resource is temporarily unavailable, in which case it will set errno to
 * EAGAIN.  In such a case, immediately reattempt the operation one more
 * time.
 */
static int madvise_collapse_retry(void *p, unsigned long size)
{
	bool retry = true;
	int ret;

retry:
	ret = madvise(p, size, MADV_COLLAPSE);
	if (ret && errno == EAGAIN && retry) {
		retry = false;
		goto retry;
	}
	return ret;
}

/*
 * Returns pmd-mapped hugepage in VMA marked VM_HUGEPAGE, filled with
 * validate_memory()'able contents.
 */
static void *alloc_hpage(struct mem_ops *ops)
{
	void *p = ops->setup_area(1);

	ops->fault(p, 0, hpage_pmd_size);

	/*
	 * VMA should be neither VM_HUGEPAGE nor VM_NOHUGEPAGE.
	 * The latter is ineligible for collapse by MADV_COLLAPSE
	 * while the former might cause MADV_COLLAPSE to race with
	 * khugepaged on low-load system (like a test machine), which
	 * would cause MADV_COLLAPSE to fail with EAGAIN.
	 */
	ksft_print_msg("Allocate huge page...\n");
	if (madvise_collapse_retry(p, hpage_pmd_size))
		ksft_exit_fail_msg("madvise(MADV_COLLAPSE): %s\n", strerror(errno));

	if (!ops->check_huge(p, 1))
		ksft_exit_fail_msg("madvise(MADV_COLLAPSE): %s\n", strerror(errno));

	if (madvise(p, hpage_pmd_size, MADV_HUGEPAGE))
		ksft_exit_fail_msg("madvise(MADV_HUGEPAGE): %s\n", strerror(errno));

	success("OK");
	return p;
}

static void validate_memory(int *p, unsigned long start, unsigned long end)
{
	int i;

	for (i = start / page_size; i < end / page_size; i++)
		if (p[i * page_size / sizeof(*p)] != i + 0xdead0000)
			ksft_print_msg("Page %d is corrupted: %#x\n",
				       i, p[i * page_size / sizeof(*p)]);

	ksft_test_result(i == end/page_size, "Validated memory\n");
}

static void *anon_setup_area(int nr_hpages)
{
	return alloc_mapping(nr_hpages);
}

static void anon_cleanup_area(void *p, unsigned long size)
{
	munmap(p, size);
}

static void anon_fault(void *p, unsigned long start, unsigned long end)
{
	fill_memory(p, start, end);
}

static bool anon_check_huge(void *addr, int nr_hpages)
{
	return check_huge_anon(addr, nr_hpages, hpage_pmd_size);
}

static void *file_setup_area(int nr_hpages)
{
	int fd;
	void *p;
	unsigned long size;

	unlink(finfo.path);  /* Cleanup from previous failed tests */
	ksft_print_msg("Creating %s for collapse%s...\n", finfo.path,
		       finfo.type == VMA_SHMEM ? " (tmpfs)" : "");
	fd = open(finfo.path, O_DSYNC | O_CREAT | O_RDWR | O_TRUNC | O_EXCL,
		  777);
	if (fd < 0)
		ksft_exit_fail_msg("open(): %s\n", strerror(errno));

	size = nr_hpages * hpage_pmd_size;
	p = alloc_mapping(nr_hpages);
	fill_memory(p, 0, size);
	write(fd, p, size);
	close(fd);
	munmap(p, size);
	success("OK");

	ksft_print_msg("Opening %s read only for collapse...\n", finfo.path);
	finfo.fd = open(finfo.path, O_RDONLY, 777);
	if (finfo.fd < 0)
		ksft_exit_fail_msg("open(): %s\n", strerror(errno));

	p = mmap(BASE_ADDR, size, PROT_READ | PROT_EXEC,
		 MAP_PRIVATE, finfo.fd, 0);
	if (p == MAP_FAILED || p != BASE_ADDR)
		ksft_exit_fail_msg("mmap(): %s\n", strerror(errno));

	/* Drop page cache */
	write_file("/proc/sys/vm/drop_caches", "3", 2);
	success("OK");
	return p;
}

static void file_cleanup_area(void *p, unsigned long size)
{
	munmap(p, size);
	close(finfo.fd);
	unlink(finfo.path);
}

static void file_fault(void *p, unsigned long start, unsigned long end)
{
	if (madvise(((char *)p) + start, end - start, MADV_POPULATE_READ))
		ksft_exit_fail_msg("madvise(MADV_POPULATE_READ: %s\n", strerror(errno));
}

static bool file_check_huge(void *addr, int nr_hpages)
{
	switch (finfo.type) {
	case VMA_FILE:
		return check_huge_file(addr, nr_hpages, hpage_pmd_size);
	case VMA_SHMEM:
		return check_huge_shmem(addr, nr_hpages, hpage_pmd_size);
	default:
		ksft_exit_fail_msg("Wrong type\n");
		return false;
	}
}

static void *shmem_setup_area(int nr_hpages)
{
	void *p;
	unsigned long size = nr_hpages * hpage_pmd_size;

	finfo.fd = memfd_create("khugepaged-selftest-collapse-shmem", 0);
	if (finfo.fd < 0)
		ksft_exit_fail_msg("memfd_create(): %s\n", strerror(errno));

	if (ftruncate(finfo.fd, size))
		ksft_exit_fail_msg("ftruncate(): %s\n", strerror(errno));

	p = mmap(BASE_ADDR, size, PROT_READ | PROT_WRITE, MAP_SHARED, finfo.fd, 0);
	if (p != BASE_ADDR)
		ksft_exit_fail_msg("mmap(): %s\n", strerror(errno));

	return p;
}

static void shmem_cleanup_area(void *p, unsigned long size)
{
	munmap(p, size);
	close(finfo.fd);
}

static bool shmem_check_huge(void *addr, int nr_hpages)
{
	return check_huge_shmem(addr, nr_hpages, hpage_pmd_size);
}

static struct mem_ops __anon_ops = {
	.setup_area = &anon_setup_area,
	.cleanup_area = &anon_cleanup_area,
	.fault = &anon_fault,
	.check_huge = &anon_check_huge,
	.name = "anon",
};

static struct mem_ops __file_ops = {
	.setup_area = &file_setup_area,
	.cleanup_area = &file_cleanup_area,
	.fault = &file_fault,
	.check_huge = &file_check_huge,
	.name = "file",
};

static struct mem_ops __shmem_ops = {
	.setup_area = &shmem_setup_area,
	.cleanup_area = &shmem_cleanup_area,
	.fault = &anon_fault,
	.check_huge = &shmem_check_huge,
	.name = "shmem",
};

static void __madvise_collapse(const char *msg, char *p, int nr_hpages,
			       struct mem_ops *ops, bool expect)
{
	int ret;
	struct thp_settings settings = *thp_current_settings();

	ksft_print_msg("%s...\n", msg);

	/*
	 * Prevent khugepaged interference and tests that MADV_COLLAPSE
	 * ignores /sys/kernel/mm/transparent_hugepage/enabled
	 */
	settings.thp_enabled = THP_NEVER;
	settings.shmem_enabled = SHMEM_NEVER;
	thp_push_settings(&settings);

	/* Clear VM_NOHUGEPAGE */
	madvise(p, nr_hpages * hpage_pmd_size, MADV_HUGEPAGE);
	ret = madvise_collapse_retry(p, nr_hpages * hpage_pmd_size);
	if (((bool)ret) == expect)
		fail("Fail: Bad return value");
	else if (!ops->check_huge(p, expect ? nr_hpages : 0))
		fail("Fail: check_huge()");
	else
		success("OK");

	thp_pop_settings();
}

static void madvise_collapse(const char *msg, char *p, int nr_hpages,
			     struct mem_ops *ops, bool expect)
{
	/* Sanity check */
	if (!ops->check_huge(p, 0))
		ksft_exit_fail_msg("Unexpected huge page\n");

	__madvise_collapse(msg, p, nr_hpages, ops, expect);
}

#define TICK 500000
static bool wait_for_scan(const char *msg, char *p, int nr_hpages,
			  struct mem_ops *ops)
{
	int full_scans;
	int timeout = 6; /* 3 seconds */

	/* Sanity check */
	if (!ops->check_huge(p, 0))
		ksft_exit_fail_msg("Unexpected huge page\n");

	madvise(p, nr_hpages * hpage_pmd_size, MADV_HUGEPAGE);

	/* Wait until the second full_scan completed */
	full_scans = thp_read_num("khugepaged/full_scans") + 2;

	ksft_print_msg("%s...\n", msg);
	while (timeout--) {
		if (ops->check_huge(p, nr_hpages))
			break;
		if (thp_read_num("khugepaged/full_scans") >= full_scans)
			break;
		usleep(TICK);
	}

	madvise(p, nr_hpages * hpage_pmd_size, MADV_NOHUGEPAGE);

	return timeout == -1;
}

static void khugepaged_collapse(const char *msg, char *p, int nr_hpages,
				struct mem_ops *ops, bool expect)
{
	if (wait_for_scan(msg, p, nr_hpages, ops)) {
		if (expect)
			fail("Timeout");
		else
			success("OK");
		return;
	}

	/*
	 * For file and shmem memory, khugepaged only retracts pte entries after
	 * putting the new hugepage in the page cache. The hugepage must be
	 * subsequently refaulted to install the pmd mapping for the mm.
	 */
	if (ops != &__anon_ops)
		ops->fault(p, 0, nr_hpages * hpage_pmd_size);

	if (ops->check_huge(p, expect ? nr_hpages : 0))
		success("OK");
	else
		fail("Fail");
}

static struct collapse_context __khugepaged_context = {
	.collapse = &khugepaged_collapse,
	.enforce_pte_scan_limits = true,
	.name = "khugepaged",
};

static struct collapse_context __madvise_context = {
	.collapse = &madvise_collapse,
	.enforce_pte_scan_limits = false,
	.name = "madvise",
};

static bool is_tmpfs(struct mem_ops *ops)
{
	return ops == &__file_ops && finfo.type == VMA_SHMEM;
}

static bool is_anon(struct mem_ops *ops)
{
	return ops == &__anon_ops;
}

static void alloc_at_fault(void)
{
	struct thp_settings settings = *thp_current_settings();
	char *p;

	settings.thp_enabled = THP_ALWAYS;
	thp_push_settings(&settings);

	p = alloc_mapping(1);
	*p = 1;
	ksft_print_msg("Allocate huge page on fault...\n");
	if (check_huge_anon(p, 1, hpage_pmd_size))
		success("OK");
	else
		fail("Fail");

	thp_pop_settings();

	madvise(p, page_size, MADV_DONTNEED);
	ksft_print_msg("Split huge PMD on MADV_DONTNEED...\n");
	if (check_huge_anon(p, 0, hpage_pmd_size))
		success("OK");
	else
		fail("Fail");
	munmap(p, hpage_pmd_size);
}

static void collapse_full(struct collapse_context *c, struct mem_ops *ops)
{
	void *p;
	int nr_hpages = 4;
	unsigned long size = nr_hpages * hpage_pmd_size;

	p = ops->setup_area(nr_hpages);
	ops->fault(p, 0, size);
	c->collapse("Collapse multiple fully populated PTE table", p, nr_hpages,
		    ops, true);
	validate_memory(p, 0, size);
	ops->cleanup_area(p, size);
}

static void collapse_empty(struct collapse_context *c, struct mem_ops *ops)
{
	void *p;

	p = ops->setup_area(1);
	c->collapse("Do not collapse empty PTE table", p, 1, ops, false);
	ops->cleanup_area(p, hpage_pmd_size);
}

static void collapse_single_pte_entry(struct collapse_context *c, struct mem_ops *ops)
{
	void *p;

	p = ops->setup_area(1);
	ops->fault(p, 0, page_size);
	c->collapse("Collapse PTE table with single PTE entry present", p,
		    1, ops, true);
	ops->cleanup_area(p, hpage_pmd_size);
}

static void collapse_max_ptes_none(struct collapse_context *c, struct mem_ops *ops)
{
	int max_ptes_none = hpage_pmd_nr / 2;
	struct thp_settings settings = *thp_current_settings();
	void *p;
	int fault_nr_pages = is_anon(ops) ? 1 << anon_order : 1;

	settings.khugepaged.max_ptes_none = max_ptes_none;
	thp_push_settings(&settings);

	p = ops->setup_area(1);

	if (is_tmpfs(ops)) {
		/* shmem pages always in the page cache */
		ksft_print_msg("tmpfs...\n");
		skip("Skip");
		goto skip;
	}

	ops->fault(p, 0, (hpage_pmd_nr - max_ptes_none - fault_nr_pages) * page_size);
	c->collapse("Maybe collapse with max_ptes_none exceeded", p, 1,
		    ops, !c->enforce_pte_scan_limits);
	validate_memory(p, 0, (hpage_pmd_nr - max_ptes_none - fault_nr_pages) * page_size);

	if (c->enforce_pte_scan_limits) {
		ops->fault(p, 0, (hpage_pmd_nr - max_ptes_none) * page_size);
		c->collapse("Collapse with max_ptes_none PTEs empty", p, 1, ops,
			    true);
		validate_memory(p, 0,
				(hpage_pmd_nr - max_ptes_none) * page_size);
	}
skip:
	ops->cleanup_area(p, hpage_pmd_size);
	thp_pop_settings();
}

static void collapse_swapin_single_pte(struct collapse_context *c, struct mem_ops *ops)
{
	void *p;

	p = ops->setup_area(1);
	ops->fault(p, 0, hpage_pmd_size);

	ksft_print_msg("Swapout one page...\n");
	if (madvise(p, page_size, MADV_PAGEOUT))
		ksft_exit_fail_msg("madvise(MADV_PAGEOUT): %s\n", strerror(errno));

	if (check_swap(p, page_size)) {
		success("OK");
	} else {
		fail("Fail");
		goto out;
	}

	c->collapse("Collapse with swapping in single PTE entry", p, 1, ops,
		    true);
	validate_memory(p, 0, hpage_pmd_size);
out:
	ops->cleanup_area(p, hpage_pmd_size);
}

static void collapse_max_ptes_swap(struct collapse_context *c, struct mem_ops *ops)
{
	int max_ptes_swap = thp_read_num("khugepaged/max_ptes_swap");
	void *p;

	p = ops->setup_area(1);
	ops->fault(p, 0, hpage_pmd_size);

	ksft_print_msg("Swapout %d of %d pages...\n", max_ptes_swap + 1, hpage_pmd_nr);
	if (madvise(p, (max_ptes_swap + 1) * page_size, MADV_PAGEOUT))
		ksft_exit_fail_msg("madvise(MADV_PAGEOUT): %s\n", strerror(errno));

	if (check_swap(p, (max_ptes_swap + 1) * page_size)) {
		success("OK");
	} else {
		fail("Fail");
		goto out;
	}

	c->collapse("Maybe collapse with max_ptes_swap exceeded", p, 1, ops,
		    !c->enforce_pte_scan_limits);
	validate_memory(p, 0, hpage_pmd_size);

	if (c->enforce_pte_scan_limits) {
		ops->fault(p, 0, hpage_pmd_size);
		ksft_print_msg("Swapout %d of %d pages...\n", max_ptes_swap,
		       hpage_pmd_nr);
		if (madvise(p, max_ptes_swap * page_size, MADV_PAGEOUT))
			ksft_exit_fail_msg("madvise(MADV_PAGEOUT): %s\n", strerror(errno));

		if (check_swap(p, max_ptes_swap * page_size)) {
			success("OK");
		} else {
			fail("Fail");
			goto out;
		}

		c->collapse("Collapse with max_ptes_swap pages swapped out", p,
			    1, ops, true);
		validate_memory(p, 0, hpage_pmd_size);
	}
out:
	ops->cleanup_area(p, hpage_pmd_size);
}

static void collapse_single_pte_entry_compound(struct collapse_context *c, struct mem_ops *ops)
{
	void *p;

	p = alloc_hpage(ops);

	if (is_tmpfs(ops)) {
		/* MADV_DONTNEED won't evict tmpfs pages */
		ksft_print_msg("tmpfs...\n");
		skip("Skip");
		goto skip;
	}

	madvise(p, hpage_pmd_size, MADV_NOHUGEPAGE);
	ksft_print_msg("Split huge page leaving single PTE mapping compound page...\n");
	madvise(p + page_size, hpage_pmd_size - page_size, MADV_DONTNEED);
	if (ops->check_huge(p, 0))
		success("OK");
	else
		fail("Fail");

	c->collapse("Collapse PTE table with single PTE mapping compound page",
		    p, 1, ops, true);
	validate_memory(p, 0, page_size);
skip:
	ops->cleanup_area(p, hpage_pmd_size);
}

static void collapse_full_of_compound(struct collapse_context *c, struct mem_ops *ops)
{
	void *p;

	p = alloc_hpage(ops);
	ksft_print_msg("Split huge page leaving single PTE page table full of compound pages...\n");
	madvise(p, page_size, MADV_NOHUGEPAGE);
	madvise(p, hpage_pmd_size, MADV_NOHUGEPAGE);
	if (ops->check_huge(p, 0))
		success("OK");
	else
		fail("Fail");

	c->collapse("Collapse PTE table full of compound pages", p, 1, ops,
		    true);
	validate_memory(p, 0, hpage_pmd_size);
	ops->cleanup_area(p, hpage_pmd_size);
}

static void collapse_compound_extreme(struct collapse_context *c, struct mem_ops *ops)
{
	void *p;
	int i;

	p = ops->setup_area(1);
	for (i = 0; i < hpage_pmd_nr; i++) {
		ksft_print_msg("\rConstruct PTE page table full of different PTE-mapped "
			       "compound pages %3d/%d...", i + 1, hpage_pmd_nr);

		madvise(BASE_ADDR, hpage_pmd_size, MADV_HUGEPAGE);
		ops->fault(BASE_ADDR, 0, hpage_pmd_size);
		if (!ops->check_huge(BASE_ADDR, 1))
			ksft_exit_fail_msg("Failed to allocate huge page\n");

		madvise(BASE_ADDR, hpage_pmd_size, MADV_NOHUGEPAGE);

		p = mremap(BASE_ADDR - i * page_size,
				i * page_size + hpage_pmd_size,
				(i + 1) * page_size,
				MREMAP_MAYMOVE | MREMAP_FIXED,
				BASE_ADDR + 2 * hpage_pmd_size);
		if (p == MAP_FAILED)
			ksft_exit_fail_msg("mremap+unmap: %s\n", strerror(errno));

		p = mremap(BASE_ADDR + 2 * hpage_pmd_size,
				(i + 1) * page_size,
				(i + 1) * page_size + hpage_pmd_size,
				MREMAP_MAYMOVE | MREMAP_FIXED,
				BASE_ADDR - (i + 1) * page_size);
		if (p == MAP_FAILED)
			ksft_exit_fail_msg("mremap+alloc: %s\n", strerror(errno));
	}

	ksft_print_msg("\n");

	ops->cleanup_area(BASE_ADDR, hpage_pmd_size);
	ops->fault(p, 0, hpage_pmd_size);
	if (!ops->check_huge(p, 1))
		success("OK");
	else
		fail("Fail");

	c->collapse("Collapse PTE table full of different compound pages", p, 1,
		    ops, true);

	validate_memory(p, 0, hpage_pmd_size);
	ops->cleanup_area(p, hpage_pmd_size);
}

static void collapse_fork(struct collapse_context *c, struct mem_ops *ops)
{
	int wstatus;
	void *p;

	p = ops->setup_area(1);

	ksft_print_msg("Allocate small page...\n");
	ops->fault(p, 0, page_size);
	if (ops->check_huge(p, 0))
		success("OK");
	else
		fail("Fail");

	ksft_print_msg("Share small page over fork()...\n");
	if (!fork()) {
		/* Do not touch settings on child exit */
		skip_settings_restore = true;

		ksft_test_result(ops->check_huge(p, 0), "%s: child\n", __func__);

		ops->fault(p, page_size, 2 * page_size);
		c->collapse("Collapse PTE table with single page shared with parent process",
			    p, 1, ops, true);

		validate_memory(p, 0, page_size);
		ops->cleanup_area(p, hpage_pmd_size);
		exit(0);
	}

	wait(&wstatus);

	ksft_print_msg("Check if parent still has small page...\n");
	if (ops->check_huge(p, 0))
		success("OK");
	else
		fail("Fail");
	validate_memory(p, 0, page_size);
	ops->cleanup_area(p, hpage_pmd_size);
}

static void collapse_fork_compound(struct collapse_context *c, struct mem_ops *ops)
{
	void *p;

	p = alloc_hpage(ops);
	ksft_print_msg("Share huge page over fork()...\n");
	if (!fork()) {
		/* Do not touch settings on child exit */
		skip_settings_restore = true;

		ksft_test_result(ops->check_huge(p, 1), "%s: child\n", __func__);

		ksft_print_msg("Split huge page PMD in child process...\n");
		madvise(p, page_size, MADV_NOHUGEPAGE);
		madvise(p, hpage_pmd_size, MADV_NOHUGEPAGE);
		if (ops->check_huge(p, 0))
			success("OK");
		else
			fail("Fail");
		ops->fault(p, 0, page_size);

		thp_write_num("khugepaged/max_ptes_shared", hpage_pmd_nr - 1);
		c->collapse("Collapse PTE table full of compound pages in child",
			    p, 1, ops, true);
		thp_write_num("khugepaged/max_ptes_shared",
			  thp_current_settings()->khugepaged.max_ptes_shared);

		validate_memory(p, 0, hpage_pmd_size);
		ops->cleanup_area(p, hpage_pmd_size);
		exit(0);
	}

	wait(NULL);

	ksft_print_msg("Check if parent still has huge page...\n");
	if (ops->check_huge(p, 1))
		success("OK");
	else
		fail("Fail");
	validate_memory(p, 0, hpage_pmd_size);
	ops->cleanup_area(p, hpage_pmd_size);
}

static void collapse_max_ptes_shared(struct collapse_context *c, struct mem_ops *ops)
{
	int max_ptes_shared = thp_read_num("khugepaged/max_ptes_shared");
	void *p;

	p = alloc_hpage(ops);
	ksft_print_msg("Share huge page over fork()...\n");
	if (!fork()) {
		/* Do not touch settings on child exit */
		skip_settings_restore = true;

		ksft_test_result(ops->check_huge(p, 1), "%s: child\n", __func__);

		ksft_print_msg("Trigger CoW on page %d of %d...\n",
			       hpage_pmd_nr - max_ptes_shared - 1, hpage_pmd_nr);
		ops->fault(p, 0, (hpage_pmd_nr - max_ptes_shared - 1) * page_size);
		if (ops->check_huge(p, 0))
			success("OK");
		else
			fail("Fail");

		c->collapse("Maybe collapse with max_ptes_shared exceeded", p,
			    1, ops, !c->enforce_pte_scan_limits);

		if (c->enforce_pte_scan_limits) {
			ksft_print_msg("Trigger CoW on page %d of %d...\n",
				       hpage_pmd_nr - max_ptes_shared, hpage_pmd_nr);
			ops->fault(p, 0, (hpage_pmd_nr - max_ptes_shared) *
				    page_size);
			if (ops->check_huge(p, 0))
				success("OK");
			else
				fail("Fail");

			c->collapse("Collapse with max_ptes_shared PTEs shared",
				    p, 1, ops, true);
		}

		validate_memory(p, 0, hpage_pmd_size);
		ops->cleanup_area(p, hpage_pmd_size);
		exit(0);
	}

	wait(NULL);

	ksft_print_msg("Check if parent still has huge page...\n");
	if (ops->check_huge(p, 1))
		success("OK");
	else
		fail("Fail");
	validate_memory(p, 0, hpage_pmd_size);
	ops->cleanup_area(p, hpage_pmd_size);
}

static void madvise_collapse_existing_thps(struct collapse_context *c,
					   struct mem_ops *ops)
{
	void *p;

	p = ops->setup_area(1);
	ops->fault(p, 0, hpage_pmd_size);
	c->collapse("Collapse fully populated PTE table...", p, 1, ops, true);
	validate_memory(p, 0, hpage_pmd_size);

	/* c->collapse() will find a hugepage and complain - call directly. */
	__madvise_collapse("Re-collapse PMD-mapped hugepage", p, 1, ops, true);
	validate_memory(p, 0, hpage_pmd_size);
	ops->cleanup_area(p, hpage_pmd_size);
}

/*
 * Test race with khugepaged where page tables have been retracted and
 * pmd cleared.
 */
static void madvise_retracted_page_tables(struct collapse_context *c,
					  struct mem_ops *ops)
{
	void *p;
	int nr_hpages = 1;
	unsigned long size = nr_hpages * hpage_pmd_size;

	p = ops->setup_area(nr_hpages);
	ops->fault(p, 0, size);

	/* Let khugepaged collapse and leave pmd cleared */
	if (wait_for_scan("Collapse and leave PMD cleared", p, nr_hpages,
			  ops)) {
		fail("Timeout");
		return;
	}
	success("OK");
	c->collapse("Install huge PMD from page cache", p, nr_hpages, ops,
		    true);
	validate_memory(p, 0, size);
	ops->cleanup_area(p, size);
}

static void usage(void)
{
	ksft_print_msg("\nUsage: ./khugepaged [OPTIONS] <test type> [dir]\n\n");
	ksft_print_msg("\t<test type>\t: <context>:<mem_type>\n");
	ksft_print_msg("\t<context>\t: [all|khugepaged|madvise]\n");
	ksft_print_msg("\t<mem_type>\t: [all|anon|file|shmem]\n");
	ksft_print_msg("\n\t\"file,all\" mem_type requires [dir] argument\n");
	ksft_print_msg("\n\t\"file,all\" mem_type requires kernel built with\n");
	ksft_print_msg("\tCONFIG_READ_ONLY_THP_FOR_FS=y\n");
	ksft_print_msg("\n\tif [dir] is a (sub)directory of a tmpfs mount, tmpfs must be\n");
	ksft_print_msg("\tmounted with huge=madvise option for khugepaged tests to work\n");
	ksft_print_msg("\n\tSupported Options:\n");
	ksft_print_msg("\t\t-h: This help message.\n");
	ksft_print_msg("\t\t-s: mTHP size, expressed as page order.\n");
	ksft_exit_fail_msg("\t\t    Defaults to 0. Use this size for anon allocations.\n");
}

static void parse_test_type(int argc, char **argv)
{
	int opt;
	char *buf;
	const char *token;

	while ((opt = getopt(argc, argv, "s:h")) != -1) {
		switch (opt) {
		case 's':
			anon_order = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
		}
	}

	argv += optind;
	argc -= optind;

	if (argc == 0) {
		/* Backwards compatibility */
		khugepaged_context =  &__khugepaged_context;
		madvise_context =  &__madvise_context;
		anon_ops = &__anon_ops;
		return;
	}

	buf = strdup(argv[0]);
	token = strsep(&buf, ":");

	if (!strcmp(token, "all")) {
		khugepaged_context =  &__khugepaged_context;
		madvise_context =  &__madvise_context;
	} else if (!strcmp(token, "khugepaged")) {
		khugepaged_context =  &__khugepaged_context;
	} else if (!strcmp(token, "madvise")) {
		madvise_context =  &__madvise_context;
	} else {
		usage();
	}

	if (!buf)
		usage();

	if (!strcmp(buf, "all")) {
		file_ops =  &__file_ops;
		anon_ops = &__anon_ops;
		shmem_ops = &__shmem_ops;
	} else if (!strcmp(buf, "anon")) {
		anon_ops = &__anon_ops;
	} else if (!strcmp(buf, "file")) {
		file_ops =  &__file_ops;
	} else if (!strcmp(buf, "shmem")) {
		shmem_ops = &__shmem_ops;
	} else {
		usage();
	}

	if (!file_ops)
		return;

	if (argc != 2)
		usage();

	get_finfo(argv[1]);
}

int main(int argc, char **argv)
{
	int hpage_pmd_order;
	struct thp_settings default_settings = {
		.thp_enabled = THP_MADVISE,
		.thp_defrag = THP_DEFRAG_ALWAYS,
		.shmem_enabled = SHMEM_ADVISE,
		.use_zero_page = 0,
		.khugepaged = {
			.defrag = 1,
			.alloc_sleep_millisecs = 10,
			.scan_sleep_millisecs = 10,
		},
		/*
		 * When testing file-backed memory, the collapse path
		 * looks at how many pages are found in the page cache, not
		 * what pages are mapped. Disable read ahead optimization so
		 * pages don't find their way into the page cache unless
		 * we mem_ops->fault() them in.
		 */
		.read_ahead_kb = 0,
	};

	ksft_print_header();
	ksft_set_plan(65);

	parse_test_type(argc, argv);

	setbuf(stdout, NULL);

	page_size = getpagesize();
	hpage_pmd_size = read_pmd_pagesize();
	if (!hpage_pmd_size)
		ksft_exit_fail_msg("Reading PMD pagesize failed\n");
	hpage_pmd_nr = hpage_pmd_size / page_size;
	hpage_pmd_order = __builtin_ctz(hpage_pmd_nr);

	default_settings.khugepaged.max_ptes_none = hpage_pmd_nr - 1;
	default_settings.khugepaged.max_ptes_swap = hpage_pmd_nr / 8;
	default_settings.khugepaged.max_ptes_shared = hpage_pmd_nr / 2;
	default_settings.khugepaged.pages_to_scan = hpage_pmd_nr * 8;
	default_settings.hugepages[hpage_pmd_order].enabled = THP_INHERIT;
	default_settings.hugepages[anon_order].enabled = THP_ALWAYS;

	save_settings();
	thp_push_settings(&default_settings);

	alloc_at_fault();

#define TEST(t, c, o) do { \
	if (c && o) { \
		ksft_print_msg("Run test: " #t " (%s:%s)\n", c->name, o->name); \
		t(c, o); \
	} \
	} while (0)

	TEST(collapse_full, khugepaged_context, anon_ops);
	TEST(collapse_full, khugepaged_context, file_ops);
	TEST(collapse_full, khugepaged_context, shmem_ops);
	TEST(collapse_full, madvise_context, anon_ops);
	TEST(collapse_full, madvise_context, file_ops);
	TEST(collapse_full, madvise_context, shmem_ops);

	TEST(collapse_empty, khugepaged_context, anon_ops);
	TEST(collapse_empty, madvise_context, anon_ops);

	TEST(collapse_single_pte_entry, khugepaged_context, anon_ops);
	TEST(collapse_single_pte_entry, khugepaged_context, file_ops);
	TEST(collapse_single_pte_entry, khugepaged_context, shmem_ops);
	TEST(collapse_single_pte_entry, madvise_context, anon_ops);
	TEST(collapse_single_pte_entry, madvise_context, file_ops);
	TEST(collapse_single_pte_entry, madvise_context, shmem_ops);

	TEST(collapse_max_ptes_none, khugepaged_context, anon_ops);
	TEST(collapse_max_ptes_none, khugepaged_context, file_ops);
	TEST(collapse_max_ptes_none, madvise_context, anon_ops);
	TEST(collapse_max_ptes_none, madvise_context, file_ops);

	TEST(collapse_single_pte_entry_compound, khugepaged_context, anon_ops);
	TEST(collapse_single_pte_entry_compound, khugepaged_context, file_ops);
	TEST(collapse_single_pte_entry_compound, madvise_context, anon_ops);
	TEST(collapse_single_pte_entry_compound, madvise_context, file_ops);

	TEST(collapse_full_of_compound, khugepaged_context, anon_ops);
	TEST(collapse_full_of_compound, khugepaged_context, file_ops);
	TEST(collapse_full_of_compound, khugepaged_context, shmem_ops);
	TEST(collapse_full_of_compound, madvise_context, anon_ops);
	TEST(collapse_full_of_compound, madvise_context, file_ops);
	TEST(collapse_full_of_compound, madvise_context, shmem_ops);

	TEST(collapse_compound_extreme, khugepaged_context, anon_ops);
	TEST(collapse_compound_extreme, madvise_context, anon_ops);

	TEST(collapse_swapin_single_pte, khugepaged_context, anon_ops);
	TEST(collapse_swapin_single_pte, madvise_context, anon_ops);

	TEST(collapse_max_ptes_swap, khugepaged_context, anon_ops);
	TEST(collapse_max_ptes_swap, madvise_context, anon_ops);

	TEST(collapse_fork, khugepaged_context, anon_ops);
	TEST(collapse_fork, madvise_context, anon_ops);

	TEST(collapse_fork_compound, khugepaged_context, anon_ops);
	TEST(collapse_fork_compound, madvise_context, anon_ops);

	TEST(collapse_max_ptes_shared, khugepaged_context, anon_ops);
	TEST(collapse_max_ptes_shared, madvise_context, anon_ops);

	TEST(madvise_collapse_existing_thps, madvise_context, anon_ops);
	TEST(madvise_collapse_existing_thps, madvise_context, file_ops);
	TEST(madvise_collapse_existing_thps, madvise_context, shmem_ops);

	TEST(madvise_retracted_page_tables, madvise_context, file_ops);
	TEST(madvise_retracted_page_tables, madvise_context, shmem_ops);

	ksft_finished();
}

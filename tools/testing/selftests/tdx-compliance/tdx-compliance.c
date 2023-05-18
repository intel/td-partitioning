// SPDX-License-Identifier: GPL-2.0-only
#include <linux/debugfs.h>
#include <linux/module.h>

#include "asm/trapnr.h"

#include "tdx-compliance.h"
#include "tdx-compliance-cpuid.h"

MODULE_AUTHOR("Yi Sun");

/*
 * Global Variables Summary:
 * - stat_total: Count the total number of cases of TDX compliance tests.
 *
 * - stat_pass: Count the number of cases in TDX compliance tests that
 *              passed the test according to the TDX Architecture
 *              Specification.
 *
 * - stat_fail: Count the number of cases in TDX compliance tests that
 *              failed to pass the test according to the TDX Architecture
 *              Specification.
 *
 * - cnt_log: Count the length of logs.
 *
 */
int stat_total, stat_pass, stat_fail, cnt_log;
int operation;
char *buf_ret, *str_input;
static struct dentry *f_tdx_tests, *d_tdx;

#define SIZE_BUF		(PAGE_SIZE << 3)
#define pr_buf(fmt, ...)				\
	(cnt_log += sprintf(buf_ret + cnt_log, fmt, ##__VA_ARGS__))\

#define pr_tdx_tests(fmt, ...)				\
	pr_info("%s: " pr_fmt(fmt),			\
		module_name(THIS_MODULE), ##__VA_ARGS__)\

#define PROCFS_NAME		"tdx-tests"
#define OPMASK_CPUID		1
#define OPMASK_SINGLE		0x8000

#define CPUID_DUMP_PATTERN	\
	"eax(%08x) ebx(%08x) ecx(%08x) edx(%08x)\n"

static char *result_str(int ret)
{
	switch (ret) {
	case 1:
		return "PASS";
	case 0:
		return "NRUN";
	case -1:
		return "FAIL";
	}

	return "UNKNOWN";
}

static int run_cpuid(struct test_cpuid *t)
{
	t->regs.eax.val = t->leaf;
	t->regs.ecx.val = t->subleaf;
	__cpuid(&t->regs.eax.val, &t->regs.ebx.val, &t->regs.ecx.val, &t->regs.edx.val);

	return 0;
}

static int check_results_cpuid(struct test_cpuid *t)
{
	if (t->regs.eax.mask == 0 && t->regs.ebx.mask == 0 &&
	    t->regs.ecx.mask == 0 && t->regs.edx.mask == 0)
		return 0;

	if (t->regs.eax.expect == (t->regs.eax.val & t->regs.eax.mask) &&
	    t->regs.ebx.expect == (t->regs.ebx.val & t->regs.ebx.mask) &&
	    t->regs.ecx.expect == (t->regs.ecx.val & t->regs.ecx.mask) &&
	    t->regs.edx.expect == (t->regs.edx.val & t->regs.edx.mask))
		return 1;

	/*
	 * Show the detail that resutls in the failure,
	 * CPUID here focus on the fixed bit, not actual cpuid val.
	 */
	pr_buf("CPUID: %s\n", t->name);
	pr_buf("CPUID	 :" CPUID_DUMP_PATTERN,
	       (t->regs.eax.val & t->regs.eax.mask), (t->regs.ebx.val & t->regs.ebx.mask),
	       (t->regs.ecx.val & t->regs.ecx.mask), (t->regs.edx.val & t->regs.edx.mask));

	pr_buf("CPUID exp:" CPUID_DUMP_PATTERN,
	       t->regs.eax.expect, t->regs.ebx.expect,
	       t->regs.ecx.expect, t->regs.edx.expect);

	pr_buf("CPUID msk:" CPUID_DUMP_PATTERN,
	       t->regs.eax.mask, t->regs.ebx.mask,
	       t->regs.ecx.mask, t->regs.edx.mask);
	return -1;
}

static int run_all_cpuid(void)
{
	struct test_cpuid *t = cpuid_cases;
	int i = 0;

	pr_tdx_tests("Testing CPUID...\n");
	for (i = 0; i < ARRAY_SIZE(cpuid_cases) - 1; i++, t++) {
		if (operation & 0x8000 && strcmp(str_input, t->name) != 0)
			continue;

		run_cpuid(t);

		t->ret = check_results_cpuid(t);
		if (t->ret == 1)
			stat_pass++;
		else if (t->ret == -1)
			stat_fail++;

		pr_buf("%d: %s:\t %s\n", ++stat_total, t->name, result_str(t->ret));
	}
	return 0;
}

static ssize_t
tdx_tests_proc_read(struct file *file, char __user *buffer,
		    size_t count, loff_t *ppos)
{
	return simple_read_from_buffer(buffer, count, ppos, buf_ret, SIZE_BUF);
}

static ssize_t
tdx_tests_proc_write(struct file *file,
		     const char __user *buffer,
		     size_t count, loff_t *f_pos)
{
	str_input = kzalloc((count + 1), GFP_KERNEL);

	if (!str_input)
		return -ENOMEM;

	if (copy_from_user(str_input, buffer, count)) {
		kfree(str_input);
		return -EFAULT;
	}

	if (*(str_input + strlen(str_input) - 1) == '\n')
		*(str_input + strlen(str_input) - 1) = '\0';

	if (strstr(str_input, "cpuid"))
		operation |= OPMASK_CPUID;
	else if (strstr(str_input, "all"))
		operation |= OPMASK_CPUID;
	else if (str_input)
		operation |= OPMASK_SINGLE | OPMASK_CPUID;

	cnt_log = 0;
	stat_total = 0;
	stat_pass = 0;
	stat_fail = 0;

	memset(buf_ret, 0, SIZE_BUF);

	if (operation & OPMASK_CPUID)
		run_all_cpuid();

	pr_buf("Total:%d, PASS:%d, FAIL:%d, SKIP:%d\n",
	       stat_total, stat_pass, stat_fail,
	       stat_total - stat_pass - stat_fail);

	kfree(str_input);
	return count;
}

const struct file_operations data_file_fops = {
	.owner = THIS_MODULE,
	.write = tdx_tests_proc_write,
	.read = tdx_tests_proc_read,
};

static int __init tdx_tests_init(void)
{
	d_tdx = debugfs_create_dir("tdx", NULL);
	if (!d_tdx)
		return -ENOENT;

	f_tdx_tests = debugfs_create_file(PROCFS_NAME, 0644, d_tdx, NULL,
					  &data_file_fops);

	if (!f_tdx_tests) {
		debugfs_remove_recursive(d_tdx);
		return -ENOENT;
	}

	buf_ret = kzalloc(SIZE_BUF, GFP_KERNEL);
	if (!buf_ret)
		return -ENOMEM;

	initial_cpuid();

	return 0;
}

static void __exit tdx_tests_exit(void)
{
	kfree(buf_ret);
	debugfs_remove_recursive(d_tdx);
}

module_init(tdx_tests_init);
module_exit(tdx_tests_exit);
MODULE_LICENSE("GPL");

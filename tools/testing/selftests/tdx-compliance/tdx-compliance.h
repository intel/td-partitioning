/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TDX_COMPLIANCE_H
#define TDX_COMPLIANCE_H
struct cpuid_reg {
	u32 val;
	u32 expect;
	u32 mask;
};

struct cpuid_regs_ext {
	struct cpuid_reg eax;
	struct cpuid_reg ebx;
	struct cpuid_reg ecx;
	struct cpuid_reg edx;
};

struct test_cpuid {
	const char *name;
	u32 leaf;
	u32 subleaf;
	int ret;
	struct cpuid_regs_ext regs;
};

static int run_cpuid(struct test_cpuid *t);
#endif

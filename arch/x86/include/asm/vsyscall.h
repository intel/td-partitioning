/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_VSYSCALL_H
#define _ASM_X86_VSYSCALL_H

#include <linux/seqlock.h>
#include <uapi/asm/vsyscall.h>

extern bool is_vsyscall_vaddr(unsigned long vaddr);

#ifdef CONFIG_X86_VSYSCALL_EMULATION
extern void map_vsyscall(void);
extern void set_vsyscall_pgtable_user_bits(pgd_t *root);

/*
 * Called on instruction fetch fault in vsyscall page.
 * Returns true if handled.
 */
extern bool emulate_vsyscall_pf(unsigned long error_code,
				struct pt_regs *regs, unsigned long address);
extern bool emulate_vsyscall_gp(struct pt_regs *regs);
#else
static inline void map_vsyscall(void) {}
static inline bool emulate_vsyscall_pf(unsigned long error_code,
				       struct pt_regs *regs, unsigned long address)
{
	return false;
}

static inline bool emulate_vsyscall_gp(struct pt_regs *regs)
{
	return false;
}
#endif

#endif /* _ASM_X86_VSYSCALL_H */

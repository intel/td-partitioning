/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TD_PART_H
#define __KVM_X86_TD_PART_H
#include <linux/compiler.h>
#include <asm/kvm_host.h>
#include <asm/tdx.h>

#include "vmx.h"
#include "tdx_errno.h"
#include "tdx_arch.h"
#include "tdx_ops.h"
#include "trace.h"

#define TDX_TDCALL_VMCS_EXIT_MASK		0x00000000FFFFFFFFULL

#define TDG_VP_ENTER_OUTPUT_INFO_MASK		0x00000000FFFFFFFFULL
#define TDG_VP_ENTER_OUTPUT_ADDL_INFO_MASK	0xFFFFFFFF00000000ULL

extern bool enable_td_part;

#ifdef CONFIG_INTEL_TD_PART_GUEST

/* vm_id: 0 - L1; 1 - 3: L2 VMs */
#define TD_PART_MAX_NUM_VMS			4

/* TDX control structure (TDR/TDCS/TDVPS) field access codes */
#define TDG_NON_ARCH			BIT_ULL(63)
#define TDG_CLASS_SHIFT			56
#define TDG_CONTEXT_SHIFT		52
#define TDG_CONTEXT_MASK		GENMASK_ULL(2, 0)
#define TDG_FIELD_MASK			GENMASK_ULL(31, 0)

#define __BUILD_TDG_FIELD(non_arch, class, context, field)		\
	(((non_arch) ? TDG_NON_ARCH : 0) |				\
	((u64)(class) << TDG_CLASS_SHIFT) |				\
	(((u64)(context) & TDG_CONTEXT_MASK) << TDG_CONTEXT_SHIFT) |	\
	((u64)(field) & TDG_FIELD_MASK))

#define BUILD_TDG_FIELD(class, context, field)				\
	__BUILD_TDG_FIELD(false, (class), (context), (field))

#define BUILD_TDG_FIELD_NON_ARCH(class, context, field)			\
	__BUILD_TDG_FIELD(true, (class), (context), (field))

#define MD_TDVPS_VMCS_1_CLASS_CODE	36
#define MD_TDVPS_VMCS_CLASS(field)	(MD_TDVPS_VMCS_1_CLASS_CODE + (((field) >> 32)- 1) * 8)

/* @field is the VMCS field encoding */
#define TDG_TDVPS_VMCS(field)		BUILD_TDG_FIELD(MD_TDVPS_VMCS_CLASS(field), 2, (field))
#define TDG_TDVPS_GPR(gpr)		BUILD_TDG_FIELD(16, 2, (gpr))

static u64 guest_tdcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
			struct tdx_module_output *out)
{
	struct tdx_module_output dummy_out;
	u64 err, ret, retries = 0;

	if (!out)
		out = &dummy_out;

	do {
		ret = __tdx_module_call(fn, rcx, rdx, r8, r9, 0, 0, 0, 0, out);
		if (retries++ > TDX_TDCALL_RETRY_MAX)
			break;

		err = ret & TDX_TDCALL_STATUS_MASK;
	} while (TDX_TDCALL_ERR_RECOVERABLE(err));

	/* Looks TRACE_EVENT can only take maximum 12 parameters,
	 * so out->r12 and out->r13 (not used in current code) are not logged for now!
	 */
	trace_kvm_td_part_guest_tdcall(fn, rcx, rdx, r8, r9,
		out->rcx, out->rdx, out->r8, out->r9,
		out->r10, out->r11, ret);

	return ret;
}

static inline u64 tdg_vm_read(u64 field_id, struct tdx_module_output *out)
{
	return guest_tdcall(TDG_VM_RD, 0, field_id, 0, 0, out);
}

static inline u64 tdg_vm_write(u64 field_id, u64 data, u64 mask,
		struct tdx_module_output *out)
{
	return guest_tdcall(TDG_VM_WR, 0, field_id, data, mask, out);
}

static inline u64 tdg_vp_read(u64 field_id, struct tdx_module_output *out)
{
	return guest_tdcall(TDG_VP_RD, 0, field_id, 0, 0, out);
}

static inline u64 tdg_vp_write(u64 field_id, u64 data, u64 mask,
		struct tdx_module_output *out)
{
	return guest_tdcall(TDG_VP_WR, 0, field_id, data, mask, out);
}

static inline u64 tdg_vp_enter(u64 vm_flags, u64 guest_state_gpa,
		struct tdx_module_output *out)
{
	return guest_tdcall(TDG_VP_ENTER, vm_flags, guest_state_gpa, 0, 0, out);
}

static inline u64 tdg_mem_page_accept(u64 ept_map_info, struct tdx_module_output *out)
{
	return guest_tdcall(TDG_MEM_PAGE_ACCEPT, ept_map_info, 0, 0, 0, out);
}

static inline u64 tdg_mem_page_attr_read(gpa_t gpa,
					 struct tdx_module_output *out)
{
	/* gpa can be anywhere within a page */
	return guest_tdcall(TDG_MEM_PAGE_ATTR_RD, gpa, 0, 0, 0, out);
}

union tdx_gpa_attr {
	u64 bits;
	struct {
		u8 read:1;
		u8 write:1;
		u8 execute_s:1;
		u8 execute_u:1;
		u8 verify_guest_paging:1;
		u8 page_write_access:1;
		u8 supervisor_shadow_stack:1;
		u8 suppress_ve:1;
		u8 :6;
		u8 unpinned:1;
		u8 valid:1;
	} fields[4];
};

union tdx_attr_flags {
	u64 bits;
	struct {
		u16 attr_mask:15;
		u16 invept:1;
	} flags[4];
};

static inline u64 tdg_mem_page_attr_write(gpa_t gpa, int level,
					  union tdx_gpa_attr gpa_attr,
					  union tdx_attr_flags attr_flags,
					  struct tdx_module_output *out)
{
	return guest_tdcall(TDG_MEM_PAGE_ATTR_WR, gpa | level, gpa_attr.bits,
			    attr_flags.bits, 0, out);
}

static inline u64 tdg_vp_invept(u64 vm_idx_bitmap, struct tdx_module_output *out)
{
	return guest_tdcall(TDG_VP_INVEPT, vm_idx_bitmap, 0, 0, 0, out);
}

union tdx_vmid_flags {
	u64 bits;
	struct {
		u64 type:1;
		u64 :51;
		u64 vm_id:2;
		u64 :10;
	};
};

union tdx_gla_list {
	u64 bits;
	struct {
		u64 last:12;
		u64 base:52;
	};
};

/*
 * Depending on the LIST flag as part of RCX, RDX can contain either
 * GLA_LIST_ENTRY or GLA_LIST_INFO
 */
static inline u64 tdg_vp_invvpid(union tdx_vmid_flags flags,
				union tdx_gla_list list,
				struct tdx_module_output *out)
{
	return guest_tdcall(TDG_VP_INVVPID, flags.bits, list.bits, 0, 0, out);
}

bool is_field_ignore_read(u32 field);
bool is_field_ignore_write(u32 field);
u64 td_part_get_vmcs_write_mask(u32 field, u32 bits);

#define TDG_BUILD_TDVPS_ACCESSORS(bits, elem_size, uclass, lclass)		\
static __always_inline u##bits tdg_##lclass##_read##bits(struct kvm_vcpu *vcpu, \
							 u64 field)		\
{										\
	struct tdx_module_output out;						\
	u64 err;								\
										\
	if (is_field_ignore_read(field))					\
		return 0;							\
	field |= ((u64)vcpu->kvm->arch.vm_id << 32);				\
	tdvps_##lclass##_check(field, bits);				\
	err = tdg_vp_read(TDG_TDVPS_##uclass(field) | ((u64)elem_size << 32), &out);	\
	if (unlikely(err)) {							\
		pr_err_ratelimited("TDG_VP_RD["#uclass".0x%llx] failed: 0x%llx\n", \
			field, err);						\
		dump_stack();							\
		return 0;							\
	}									\
	return (u##bits)out.r8;							\
}										\
static __always_inline void tdg_##lclass##_write##bits(struct kvm_vcpu *vcpu,	\
							u64 field, u##bits val)	\
{										\
	struct tdx_module_output out;						\
	u64 err;								\
										\
	if (is_field_ignore_write(field))					\
		return;								\
	field |= ((u64)vcpu->kvm->arch.vm_id << 32);				\
	tdvps_##lclass##_check(field, bits);				\
	err = tdg_vp_write(TDG_TDVPS_##uclass(field) | ((u64)elem_size << 32) | (1UL << 51),	\
			val, td_part_get_vmcs_write_mask(field, bits), &out);	\
	if (unlikely(err)) {							\
		pr_err_ratelimited("TDG_VP_WR["#uclass".0x%llx] = 0x%llx failed: 0x%llx\n", \
			field, (u64)val, err);					\
		dump_stack();							\
	}									\
}

TDG_BUILD_TDVPS_ACCESSORS(16, 1, VMCS, vmcs);
TDG_BUILD_TDVPS_ACCESSORS(32, 2, VMCS, vmcs);
TDG_BUILD_TDVPS_ACCESSORS(64, 3, VMCS, vmcs);

TDG_BUILD_TDVPS_ACCESSORS(64, 3, GPR, gpr);

#ifdef CONFIG_X86_64
#define tdg_vmcs_writel tdg_vmcs_write64
#define tdg_vmcs_readl tdg_vmcs_read64
#endif

#define TDG_BUILD_CONTROLS_SHADOW(lname, uname, bits)				\
static inline void tdg_##lname##_controls_set(struct vcpu_vmx *vmx, u##bits val) \
{										\
	tdg_vmcs_write##bits(&vmx->vcpu, uname, val);				\
	vmx->loaded_vmcs->controls_shadow.lname = val;				\
}										\
static inline u##bits __tdg_##lname##_controls_get(struct loaded_vmcs *vmcs)	\
{										\
	return vmcs->controls_shadow.lname;					\
}										\
static inline u##bits tdg_##lname##_controls_get(struct vcpu_vmx *vmx)		\
{										\
	return __tdg_##lname##_controls_get(vmx->loaded_vmcs);			\
}										\
static inline void tdg_##lname##_controls_setbit(struct vcpu_vmx *vmx, u##bits val)	\
{										\
	tdg_##lname##_controls_set(vmx, tdg_##lname##_controls_get(vmx) | val);	\
}										\
static inline void tdg_##lname##_controls_clearbit(struct vcpu_vmx *vmx, u##bits val)	\
{										\
	tdg_##lname##_controls_set(vmx, tdg_##lname##_controls_get(vmx) & ~val); \
}
TDG_BUILD_CONTROLS_SHADOW(vm_entry, VM_ENTRY_CONTROLS, 32)
TDG_BUILD_CONTROLS_SHADOW(vm_exit, VM_EXIT_CONTROLS, 32)
TDG_BUILD_CONTROLS_SHADOW(pin, PIN_BASED_VM_EXEC_CONTROL, 32)
TDG_BUILD_CONTROLS_SHADOW(exec, CPU_BASED_VM_EXEC_CONTROL, 32)
TDG_BUILD_CONTROLS_SHADOW(secondary_exec, SECONDARY_VM_EXEC_CONTROL, 32)
TDG_BUILD_CONTROLS_SHADOW(tertiary_exec, TERTIARY_VM_EXEC_CONTROL, 64)

static inline bool is_td_part(struct kvm *kvm)
{
	return kvm->arch.vm_type == KVM_X86_TD_PART_VM;
}

static inline bool is_td_part_vcpu(struct kvm_vcpu *vcpu)
{
	return is_td_part(vcpu->kvm);
}

static inline bool is_td_part_vmcs(struct loaded_vmcs *vmcs)
{
	struct vcpu_vmx *vmx;

	/*
	 * TODO: this runs into problem if CONFIG_INTEL_TD_PART_GUEST is
	 * enabled in nested setup.  Another possible approach is to add a
	 * new field in struct loaded_vmcs to help identify the VM type.
	 * But we chose the simplest implemenbttation at this moment.
	 */
	vmx = container_of(vmcs, struct vcpu_vmx, vmcs01);
	return is_td_part_vcpu(&vmx->vcpu);
}

bool td_part_is_rdpmc_required(void);
noinstr void td_part_vcpu_enter_exit(struct kvm_vcpu *vcpu,
				struct vcpu_vmx *vmx);
void td_part_intercept_msr(struct kvm_vcpu *vcpu, u32 msr, int type);
int tdg_write_msr_bitmap(struct kvm *kvm, unsigned long *msr_bitmap, u64 offset);
void td_part_update_reserved_gpa_bits(struct kvm_vcpu *vcpu);
fastpath_t td_part_exit_handlers_fastpath(struct kvm_vcpu *vcpu);
void td_part_request_immediate_exit(struct kvm_vcpu *vcpu);
int td_part_handle_tdcall(struct kvm_vcpu *vcpu);

#else /* CONFIG_INTEL_TD_PART_GUEST */

#define TDG_BUILD_TDVPS_ACCESSORS(bits, elem_size, uclass, lclass)			\
static __always_inline u##bits tdg_##lclass##_read##bits(struct kvm_vcpu *vcpu,		\
							 u64 field) { return 0; }	\
static __always_inline void tdg_##lclass##_write##bits(struct kvm_vcpu *vcpu,		\
							u64 field, u##bits val) {}

TDG_BUILD_TDVPS_ACCESSORS(16, 1, VMCS, vmcs);
TDG_BUILD_TDVPS_ACCESSORS(32, 2, VMCS, vmcs);
TDG_BUILD_TDVPS_ACCESSORS(64, 3, VMCS, vmcs);

TDG_BUILD_TDVPS_ACCESSORS(64, 3, GPR, gpr);

#define TDG_BUILD_CONTROLS_SHADOW(lname, uname, bits)					\
static inline void tdg_##lname##_controls_set(struct vcpu_vmx *vmx, u##bits val) {}	\
static inline u##bits __tdg_##lname##_controls_get(struct loaded_vmcs *vmcs) { return 0; } \
static inline u##bits tdg_##lname##_controls_get(struct vcpu_vmx *vmx) { return 0; }	\
static inline void tdg_##lname##_controls_setbit(struct vcpu_vmx *vmx, u##bits val) {}	\
static inline void tdg_##lname##_controls_clearbit(struct vcpu_vmx *vmx, u##bits val) {}

TDG_BUILD_CONTROLS_SHADOW(vm_entry, VM_ENTRY_CONTROLS, 32)
TDG_BUILD_CONTROLS_SHADOW(vm_exit, VM_EXIT_CONTROLS, 32)
TDG_BUILD_CONTROLS_SHADOW(pin, PIN_BASED_VM_EXEC_CONTROL, 32)
TDG_BUILD_CONTROLS_SHADOW(exec, CPU_BASED_VM_EXEC_CONTROL, 32)
TDG_BUILD_CONTROLS_SHADOW(secondary_exec, SECONDARY_VM_EXEC_CONTROL, 32)
TDG_BUILD_CONTROLS_SHADOW(tertiary_exec, TERTIARY_VM_EXEC_CONTROL, 64)

static inline bool is_td_part(struct kvm *kvm) { return false; }
static inline bool is_td_part_vcpu(struct kvm_vcpu *vcpu) { return false; }
static inline bool is_td_part_vmcs(struct loaded_vmcs *vmcs) { return false; }
static inline bool td_part_is_rdpmc_required(void) { return false; }
static inline void td_part_vcpu_enter_exit(struct kvm_vcpu *vcpu,
				struct vcpu_vmx *vmx) {}
static inline void td_part_intercept_msr(struct kvm_vcpu *vcpu, u32 msr, int type) {}
static inline int tdg_write_msr_bitmap(struct kvm *kvm, unsigned long *msr_bitmap, u64 offset) { return 0; }
static inline void td_part_update_reserved_gpa_bits(struct kvm_vcpu *vcpu) {}
static inline fastpath_t td_part_exit_handlers_fastpath(struct kvm_vcpu *vcpu) { return EXIT_FASTPATH_NONE; }
static inline void td_part_request_immediate_exit(struct kvm_vcpu *vcpu) {};
static inline int td_part_handle_tdcall(struct kvm_vcpu *vcpu) { return 0; }
#endif /* CONFIG_INTEL_TD_PART_GUEST */

#endif /* __KVM_X86_TD_PART_H */

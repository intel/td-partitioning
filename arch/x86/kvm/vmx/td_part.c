// SPDX-License-Identifier: GPL-2.0

#include "x86_ops.h"
#include "vmx.h"
#include "common.h"
#include "td_part.h"

static DECLARE_BITMAP(td_part_vm_id_bitmap, TD_PART_MAX_NUM_VMS);
static int num_l2_vms;

bool td_part_is_vm_type_supported(unsigned long type)
{
	return type == KVM_X86_TD_PART_VM;
}

static bool is_host_state_field(u32 field)
{
	return (((field >> 10) & 0x3) == 3);
}

static bool is_writable_field(u32 field)
{
	switch (field) {
	case 0x6:	/* HLAT prefix size */
	case GUEST_ES_SELECTOR ... GUEST_INTR_STATUS:
	case 0x814:	/* Guest UINV */
	case VIRTUAL_APIC_PAGE_ADDR ... VIRTUAL_APIC_PAGE_ADDR_HIGH:
	case EPT_POINTER ... EOI_EXIT_BITMAP3_HIGH:
	case XSS_EXIT_BITMAP ... XSS_EXIT_BITMAP_HIGH:
	case TERTIARY_VM_EXEC_CONTROL ... TERTIARY_VM_EXEC_CONTROL_HIGH:
	case 0x2040:	/* HLAT pointer */
	case GUEST_PHYSICAL_ADDRESS ... GUEST_PHYSICAL_ADDRESS_HIGH:
	case GUEST_IA32_DEBUGCTL ... GUEST_PDPTR3_HIGH:
	case GUEST_IA32_RTIT_CTL ... 0x2818:	/* IA32_GUEST_PKRS */
	case CPU_BASED_VM_EXEC_CONTROL ... CR3_TARGET_COUNT:
	case VM_ENTRY_CONTROLS:
	case VM_ENTRY_INTR_INFO_FIELD ... PLE_WINDOW:
	case VM_INSTRUCTION_ERROR ... VMX_INSTRUCTION_INFO:
	case GUEST_ES_LIMIT ... GUEST_INTERRUPTIBILITY_INFO:
	case GUEST_SYSENTER_CS:
	case CR0_GUEST_HOST_MASK ... CR3_TARGET_VALUE3:
	case EXIT_QUALIFICATION ... GUEST_LINEAR_ADDRESS:
	case GUEST_CR0 ... 0x682c:	/* GUEST_INTR_SSP_TABLE */
		return true;
	default:
		return false;
	}

	return false;
}

static bool is_readonly_field(u32 field)
{
	switch (field) {
	case POSTED_INTR_NV:	/* PI Notification Vector */
	case IO_BITMAP_A ... IO_BITMAP_B_HIGH:
	case POSTED_INTR_DESC_ADDR ... VM_FUNCTION_CONTROL_HIGH:
	case VE_INFORMATION_ADDRESS ... VE_INFORMATION_ADDRESS_HIGH:
	case ENCLS_EXITING_BITMAP ... ENCLS_EXITING_BITMAP_HIGH:
	case 0x2036:	/* ENCLV-Exiting Bitmap */
	case SHARED_EPT_POINTER:
	case PIN_BASED_VM_EXEC_CONTROL:
	case VM_EXIT_CONTROLS:
	case NOTIFY_WINDOW:
	case GUEST_ACTIVITY_STATE:
		return true;
	default:
		return false;
	}

	return false;
}

bool is_field_ignore_read(u32 field)
{
	/* quickly filter out */
	if (is_host_state_field(field))
		return true;

	if (is_writable_field(field) || is_readonly_field(field))
		return false;

	return true;
}

bool is_field_ignore_write(u32 field)
{
	/* quickly filter out */
	if (is_host_state_field(field))
		return true;

	/*
	 * These fields are passed to TDX module in tdg.vp.enter,
	 * and don't need to write them in other places.
	 */
	if ((field == GUEST_RIP) || (field == GUEST_RFLAGS)
		|| (field == GUEST_INTR_STATUS))
		return true;

	if (is_writable_field(field))
		return false;

	return true;
}

static bool is_tdg_enter_error(u64 error_code)
{
	switch (error_code & TDX_TDCALL_STATUS_MASK) {
	case TDX_SUCCESS:
	case TDX_L2_EXIT_HOST_ROUTED_ASYNC:
	case TDX_L2_EXIT_HOST_ROUTED_TDVMCALL:
	case TDX_L2_EXIT_PENDING_INTERRUPT:
	case TDX_PENDING_INTERRUPT:
	case TDX_TD_EXIT_BEFORE_L2_ENTRY:
		return false;
	default:
		return true;
	}
}

static void td_part_load_l2_gprs(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int i;

	for (i = 0; i <= VCPU_REGS_R15; i++)
		vcpu->arch.l2_guest_state.gpr_state.gprs[i] = vcpu->arch.regs[i];

	vcpu->arch.l2_guest_state.rip = vcpu->arch.regs[VCPU_REGS_RIP];
	vcpu->arch.l2_guest_state.rflags = vmx->rflags;
}

static void td_part_store_l2_gprs(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int i;

	for (i = 0; i <= VCPU_REGS_R15; i++)
		vcpu->arch.regs[i] = vcpu->arch.l2_guest_state.gpr_state.gprs[i];

	vmx->rflags = vcpu->arch.l2_guest_state.rflags;
	kvm_register_mark_available(vcpu, VCPU_EXREG_RFLAGS);

	vcpu->arch.regs[VCPU_REGS_RIP] = vcpu->arch.l2_guest_state.rip;
	kvm_register_mark_available(vcpu, VCPU_REGS_RIP);
}

static bool __td_part_vcpu_run(struct kvm_vcpu *vcpu, struct vcpu_vmx *vmx)
{
	struct tdx_module_output out;
	u64 vm_flags, ret;

	td_part_load_l2_gprs(vcpu);

	vm_flags = ((u64)vcpu->kvm->arch.vm_id << 52);
	ret = tdg_vp_enter(vm_flags, virt_to_phys(&vcpu->arch.l2_guest_state), &out);

	/* TDG.VP.ENTER has special error checking */
	if (is_tdg_enter_error(ret)) {
		pr_err_ratelimited("TDG_VP_ENTER failed: 0x%llx\n", ret);
		return 1;
	}

	/* Save all guest registers so that we can continue using
	 * kvm_xxx_read/write APIs. */
	td_part_store_l2_gprs(vcpu);

	/* For now only save useful output from TDCALL (TDG.VP.ENTER) */

	vmx->exit_reason.full = ret;

	vmx->exit_qualification = out.rcx;
	kvm_register_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_1);

	vmx->exit_intr_info = out.r9 & TDG_VP_ENTER_OUTPUT_INFO_MASK;
	kvm_register_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_2);

	return 0;
}

noinstr void td_part_vcpu_enter_exit(struct kvm_vcpu *vcpu,
				       struct vcpu_vmx *vmx)
{
	guest_state_enter_irqoff();

	if (vcpu->arch.cr2 != native_read_cr2())
		native_write_cr2(vcpu->arch.cr2);

	vmx->fail = __td_part_vcpu_run(vcpu, vmx);

	vcpu->arch.cr2 = native_read_cr2();

	guest_state_exit_irqoff();
}

int td_part_vm_init(struct kvm *kvm)
{
	u16 vm_id;

	kvm->arch.gfn_shared_mask = gpa_to_gfn(tdx_get_cc_mask());

	vm_id = find_first_zero_bit(td_part_vm_id_bitmap, TD_PART_MAX_NUM_VMS);
	if (!vm_id || (vm_id >= TD_PART_MAX_NUM_VMS) || (vm_id > num_l2_vms)) {
		pr_err("%s: no valid VM ID (%d/%d) available for L2 VM\n",
			__func__, vm_id, num_l2_vms);
		return -ENOTSUPP;
	}

	set_bit(vm_id, td_part_vm_id_bitmap);
	kvm->arch.vm_id = vm_id;

	KVM_BUG_ON(!enable_ept, kvm);
	KVM_BUG_ON(!enable_unrestricted_guest, kvm);

	if (kvm->vm_bugged)
		return -EINVAL;

	return vmx_vm_init(kvm);
}

void td_part_vm_destroy(struct kvm *kvm)
{
	clear_bit(kvm->arch.vm_id, td_part_vm_id_bitmap);
}

__init int td_part_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	struct tdx_module_output out;
	u64 ret;

	if (!is_td_partitioning_supported()) {
		pr_warn("Cannot enable TD partitioning\n");
		return -ENODEV;
	}

	ret = tdg_vm_read(TDX_MD_TDCS_NUM_L2_VMS, &out);
	if (ret != TDX_SUCCESS) {
		pr_err("%s: tdg_vm_rd failed, err=%llx\n", __func__, ret);
		return -EIO;
	}

	num_l2_vms = out.r8;
	/* reserve VM ID 0, L2 virtual machine index must be 1 or higher */
	set_bit(0, td_part_vm_id_bitmap);

	return 0;
}

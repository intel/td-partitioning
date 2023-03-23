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

u64 td_part_get_vmcs_write_mask(u32 field, u32 bits)
{
	u64 mask = GENMASK_ULL(bits - 1, 0);

	switch (field) {
	case EPT_POINTER:
		mask = 0x80;
		break;
	case VIRTUAL_APIC_PAGE_ADDR:
		mask = 0xFFFFFFFFFFFFF000;
		break;
	case 0x2040:	/* Hypervisor-managed linear-address translation pointer */
		mask = 0xFFFFFFFFFF018;
		break;
	case GUEST_IA32_DEBUGCTL:
		mask = 0xFFC1;
		break;
	case GUEST_IA32_EFER:
		mask = 0x501;
		break;
	case CPU_BASED_VM_EXEC_CONTROL:
		mask = 0x48F99A04;
		break;
	case EXCEPTION_BITMAP:
		mask = 0xFFFFFFFFFFFBFFFF;
		break;
	case VM_ENTRY_CONTROLS:
		mask = 0x200;
		break;
	case SECONDARY_VM_EXEC_CONTROL:
		mask = 0xC513F0C;
		break;
	case TERTIARY_VM_EXEC_CONTROL:
		mask = 0xE;
		break;
	case GUEST_CR0:
		mask = 0x8005001F;
		break;
	case GUEST_CR4:
		mask = 0x3FF1FBF;
		break;
	default:
		break;
	}
	return mask;
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

bool td_part_is_rdpmc_required(void)
{
	struct tdx_module_output out;

	/* CPU_BASED_RDPMC_EXITING is supposed to be set as ~TDCS.ATTRIBUTES.PERFMON */
	if (tdg_vm_read(TDX_MD_TDCS_ATTR, &out) != TDX_SUCCESS)
		return false;

	/*
	 * TODO: it seems one bug in TDX module regarding the handling of
	 * RDMSR ia32_vmx_true_pinbased_ctls from L1, we can't configure
	 * CPU_BASED_RDPMC_EXITING inside setup_vmcs_config(), otherwise
	 * adjust_vmx_controls() may returns EIO.
	 */
	return !(out.r8 & TDX_TD_ATTRIBUTE_PERFMON);
}

int td_part_handle_tdcall(struct kvm_vcpu *vcpu)
{
	struct tdx_module_output out;
	u16 leaf = kvm_rax_read(vcpu);
	unsigned long rax = TDX_SUCCESS;

	switch (leaf) {
	case TDX_GET_INFO:
		__tdx_module_call(leaf, 0, 0, 0, 0, 0, 0, 0, 0, &out);
		kvm_rcx_write(vcpu, out.rcx);
		kvm_rdx_write(vcpu, out.rdx);
		kvm_r8_write(vcpu, out.r8);
		kvm_r9_write(vcpu, out.r9);
		kvm_r10_write(vcpu, out.r10);
		kvm_r11_write(vcpu, out.r11);
		kvm_r12_write(vcpu, out.r12);
		kvm_r13_write(vcpu, out.r13);
		break;
	default:
		kvm_pr_unimpl("TD_PART: tdcall leaf %d not supported\n", leaf);
		rax = TDX_OPERAND_INVALID;
		break;
	}

	kvm_rax_write(vcpu, rax);
	return kvm_skip_emulated_instruction(vcpu);
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
	vcpu->arch.l2_guest_state.intr_status = vmx->intr_status;
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

	vmx->intr_status = vcpu->arch.l2_guest_state.intr_status;
	kvm_register_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_6);
}

static bool __td_part_vcpu_run(struct kvm_vcpu *vcpu, struct vcpu_vmx *vmx)
{
	struct tdx_module_output out;
	u64 vm_flags, ret;

	/* Prevent L1 VMM from using the predicted branch targets before switching to L2 VM. */
	indirect_branch_prediction_barrier();

	td_part_load_l2_gprs(vcpu);

	vm_flags = ((u64)vcpu->kvm->arch.vm_id << 52);
	ret = tdg_vp_enter(vm_flags, virt_to_phys(&vcpu->arch.l2_guest_state), &out);

	/* Prevent L2 VM from using the predicted branch targets before switching to L1 VMM. */
	indirect_branch_prediction_barrier();

	/* Only logs tdg_vp_enter specific stuff here: ret/rflags/qualification/rip for now
	 * Use trace_kvm_td_part_guest_tdcall() to trace tdg_vp_enter's out!
	 * Use "sudo trace-cmd stream -e kvm:kvm_td_part_tdg_vp_enter -e kvm:kvm_exit" to
	 * trace tdg_vp_enter and vmexits
	 */
	trace_kvm_td_part_tdg_vp_enter(ret, out.rcx,
		vcpu->arch.l2_guest_state.rflags,
		vcpu->arch.l2_guest_state.rip);

	/* TDG.VP.ENTER has special error checking */
	if (is_tdg_enter_error(ret)) {
		pr_err_ratelimited("TDG_VP_ENTER failed: 0x%llx\n", ret);
		return 1;
	}

	vcpu->arch.regs_avail &= ~VMX_REGS_LAZY_LOAD_SET;

	/* Save all guest registers so that we can continue using
	 * kvm_xxx_read/write APIs. */
	td_part_store_l2_gprs(vcpu);

	/* For now only save useful output from TDCALL (TDG.VP.ENTER) */

	vmx->exit_reason.full = ret;

	vmx->exit_qualification = out.rcx;
	kvm_register_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_1);

	vmx->faulting_gpa = out.r8;
	kvm_register_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_3);

	vmx->exit_intr_info = out.r9 & TDG_VP_ENTER_OUTPUT_INFO_MASK;
	kvm_register_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_2);

	vmx->idt_vectoring_info = out.r10 & TDG_VP_ENTER_OUTPUT_INFO_MASK;
	kvm_register_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_4);

	vmx->instr_len = (out.r11 & TDG_VP_ENTER_OUTPUT_ADDL_INFO_MASK) >> 32;
	kvm_register_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_5);

	return 0;
}

fastpath_t td_part_exit_handlers_fastpath(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!is_td_part_vcpu(vcpu))
		return EXIT_FASTPATH_NONE;

	if ((vmx->exit_reason.full & TDX_TDCALL_STATUS_MASK) ==
	    TDX_PENDING_INTERRUPT) {
		vmx_cancel_injection(vcpu);
		return EXIT_FASTPATH_EXIT_HANDLED;
	}

	return EXIT_FASTPATH_NONE;
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

int td_part_handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	WARN_ON_ONCE(1);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return 0;
}

void td_part_request_immediate_exit(struct kvm_vcpu *vcpu)
{
	vmx_request_immediate_exit(vcpu);

	if (kvm_cpu_has_injectable_intr(vcpu))
		vmx_enable_irq_window(vcpu);
}

int tdg_write_msr_bitmap(struct kvm *kvm, unsigned long *msr_bitmap, u64 offset)
{
	struct tdx_module_output out;
	u64 field_id, ret;

	switch (kvm->arch.vm_id)
	{
		case 1:
			field_id = TDX_MD_TDVPS_MSR_BITMAPS_1;
			break;
		case 2:
			field_id = TDX_MD_TDVPS_MSR_BITMAPS_2;
			break;
		case 3:
			field_id = TDX_MD_TDVPS_MSR_BITMAPS_2;
			break;

		default:
			return -ENODEV;
	}

	/*
	 * The field code of MSR Bitmap is the offset (8B units) from the
	 * beginning of the architectural MSR bitmaps page structure
	 */
	field_id += offset;

	/* Copy the content from KVM bitmap to TDX bitmap. */
	ret = tdg_vp_write(field_id, msr_bitmap[offset],
		TDX_MD_TDVPS_MSR_BITMAPS_WRMASK, &out);
	if (ret != TDX_SUCCESS) {
		pr_err("%s: tdg_vp_write failed, field %llx err=%llx\n",
			__func__, field_id, ret);
		return ret;
	}

	return 0;
}

void td_part_intercept_msr(struct kvm_vcpu *vcpu, u32 msr, int type)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long *msr_bitmap = vmx->vmcs01.msr_bitmap;
	struct kvm *kvm = vcpu->kvm;
	unsigned long offset;

	/*
	 * MSRs 0x00000000-0x0000:
	 * bytes 0-0x3ff for reads and 0x800-0xbff for writes
	 * MSRs 0xc0000000-0xc0001fff:
	 * bytes 0x400-0xr73ff for reads and 0xc00-0xfff for writes
	 * MSRs not covered by either of the ranges always VM-Exit.
	 */
	if ((msr >= 0x2000) && ((msr < 0xc0000000) || (msr >= 0xc0002000)))
		return;

	/* one 8-bytes word has 64 MSRs */
	offset = (msr & 0x1fff) / 64;

	if ((msr >= 0xc0000000) && (msr <= 0xc0001fff))
		offset += 0x400 / 8;

	if (type & MSR_TYPE_R)
		tdg_write_msr_bitmap(kvm, msr_bitmap, offset);

	if (type & MSR_TYPE_W) {
		offset += 0x800 / 8;
		tdg_write_msr_bitmap(kvm, msr_bitmap, offset);
	}
}

int td_part_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	/*
	 * Intel CPUs do not support 32-bit SYSCALL and writing to this MSR
	 * is ignored by the CPU.
	 *
	 * To emulate this MSR, ignoring R/W from the guests seems is the
	 * correct way, other than throw a #GP.
	 */
	if ((msr->index == MSR_CSTAR) ||
	    (msr->index == MSR_IA32_TSC))
		return 0;

	return vmx_set_msr(vcpu, msr);
}

int td_part_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	if (msr->index == MSR_CSTAR)
		return 0;

	return vmx_get_msr(vcpu, msr);
}

void td_part_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm *kvm = vcpu->kvm;
	bool already_loaded = vmx->loaded_vmcs->cpu == cpu;

	if (!already_loaded && vmx->loaded_vmcs->cpu >= 0 &&
	    refcount_read(&kvm->users_count)) {
		kvm_pr_unimpl("TD_PART: vCPU migration not supported\n");
		kvm_vm_bugged(vcpu->kvm);
		return;
	}

	vmx_vcpu_load(vcpu, cpu);
}

void td_part_flush_tlb_all(struct kvm_vcpu *vcpu)
{
	struct tdx_module_output out;
	u64 bitmap, err;

	/* Bit 0 (VMID 0) must be 0 */
	bitmap = (1ull << (num_l2_vms + 1)) - 2;
	err = tdg_vp_invept(bitmap, &out);
	WARN_ON(err);
}

void td_part_flush_tlb_current(struct kvm_vcpu *vcpu)
{
	struct tdx_module_output out;
	u8 vm_id = vcpu->kvm->arch.vm_id;
	u64 bitmap, err;

	if (!WARN_ON(!vm_id || vm_id > 3)) {
		bitmap = 1ull << vm_id;
		err = tdg_vp_invept(bitmap, &out);
		WARN_ON(err);
	}
}

void td_part_flush_tlb_gva(struct kvm_vcpu *vcpu, gva_t addr)
{
	union tdx_vmid_flags vmid_flags = { 0 };
	union tdx_gla_list gla_list = { 0 };
	struct tdx_module_output out;
	u8 vm_id = vcpu->kvm->arch.vm_id;
	u64 err;

	if (!WARN_ON(!vm_id || vm_id > 3)) {
		vmid_flags.vm_id = vm_id;
		gla_list.base = addr >> 12;
		err = tdg_vp_invvpid(vmid_flags, gla_list, &out);
		WARN_ON(err);
	}
}

void td_part_flush_tlb_guest(struct kvm_vcpu *vcpu)
{
	/*
	 * This can't be fulfilled by TDG.VP.INVVPID, as it only takes a list of
	 * GLAs and not the entire VPID context (i.e.
	 * single-context/all-contexts invalidation is not supported).
	 *
	 * Use TDG.VP.INVEPT instead, as it should invalidate a superset of our
	 * target (combined mappings).
	 *
	 * Intel SDM 28.4.2 Creating and Using Cached Translation Information:
	 *
	 * - No linear mappings are created while EPT is in use.
	 * - Combined mappings may be created while EPT is in use.
	 * - If EPT is in use, for accesses using linear addresses, it may use
	 *   combined mappings associated with the current VPID, the current
	 *   PCID, and the current EP4TA. It may also use global TLB entries
	 *   (combined mappings) associated with the current VPID, the current
	 *   EP4TA, and any PCID.
	 * - No linear mappings are used while EPT is in use.
	 *
	 * Intel SDM 28.4.3.1 Operations that Invalidate Cached Mappings:
	 *
	 * Execution of the INVEPT instruction invalidates guest-physical
	 * mappings and combined mappings.
	 */
	td_part_flush_tlb_current(vcpu);
}

static int td_part_free_private_spt(struct kvm *kvm, gfn_t gfn,
				    enum pg_level level, void *private_spt)
{
	if (KVM_BUG_ON(!is_td_part(kvm), kvm))
		return -EINVAL;

	/*
	 * Nothing to do here as we never allocate private SPTs
	 * or manage SEPTs.
	 */
	return 0;
}

static int td_part_split_private_spt(struct kvm *kvm, gfn_t gfn,
				     enum pg_level level, void *private_spt)
{
	kvm_pr_unimpl("TD_PART: %s not supported\n", __func__);
	kvm_vm_bugged(kvm);
	return -EOPNOTSUPP;
}

static int td_part_merge_private_spt(struct kvm *kvm, gfn_t gfn,
				     enum pg_level level, void *private_spt)
{
	kvm_pr_unimpl("TD_PART: %s not supported\n", __func__);
	kvm_vm_bugged(kvm);
	return -EOPNOTSUPP;
}

static int add_alias(struct kvm *kvm, gfn_t gfn, enum pg_level level,
		     bool is_writable, bool is_executable)
{
	u8 vm_id = kvm->arch.vm_id;
	gpa_t gpa = gfn_to_gpa(gfn);
	int tdx_level = pg_level_to_tdx_sept_level(level);
	union tdx_gpa_attr gpa_attr = { 0 };
	union tdx_attr_flags attr_flags = { 0 };
	struct tdx_module_output out;
	int retry = 0;
	u64 err;

	if (KVM_BUG_ON(!vm_id || vm_id > 3, kvm))
		return -EINVAL;

	gpa_attr.fields[vm_id].valid = 1;
	gpa_attr.fields[vm_id].read = 1;

	if (is_writable)
		gpa_attr.fields[vm_id].write = 1;
	if (is_executable) {
		/* TODO execute_u is not supported yet */
		gpa_attr.fields[vm_id].execute_s = 1;
	}
	attr_flags.flags[vm_id].attr_mask = 0x7;

	do {
		/* TODO clear bottom gpa bits for large leaves */
		err = tdg_mem_page_attr_write(gpa, tdx_level, gpa_attr,
					      attr_flags, &out);

		switch (err & TDX_TDCALL_STATUS_MASK) {
		case TDX_SUCCESS: break;
		case TDX_PAGE_SIZE_MISMATCH:
		case TDX_OPERAND_INVALID:
		default:
			kvm_pr_unimpl("TDG.MEM.PAGE.ATTR.WR "
				      "error: 0x%llx\n", err);
			KVM_BUG_ON(1, kvm);
			return -EPERM;
		}

		/*
		 * out.rdx indicates whether the TDG.MEM.PAGE.ATTR.WR call
		 * successfully set the attribute or not. On success, RDX
		 * returns the updated guest-visible page attributes.
		 */
		if (out.rdx == gpa_attr.bits)
			break;
		retry++;
	} while (retry < PG_LEVEL_NUM);

	if (KVM_BUG_ON(out.rdx != gpa_attr.bits, kvm))
		return -EFAULT;

	return 0;
}

static int modify_alias_w(struct kvm *kvm, gfn_t gfn, enum pg_level level,
			  bool is_writable)
{
	u8 vm_id = kvm->arch.vm_id;
	gpa_t gpa = gfn_to_gpa(gfn);
	int tdx_level = pg_level_to_tdx_sept_level(level);
	union tdx_gpa_attr gpa_attr = { 0 };
	union tdx_attr_flags attr_flags = { 0 };
	struct tdx_module_output out;
	u64 err;

	if (KVM_BUG_ON(!vm_id || vm_id > 3, kvm))
		return -EINVAL;

	gpa_attr.fields[vm_id].valid = 1;

	if (is_writable)
		gpa_attr.fields[vm_id].write = 1;
	attr_flags.flags[vm_id].attr_mask = 0x2;

	/* TODO clear bottom gpa bits for large leaves */
	err = tdg_mem_page_attr_write(gpa, tdx_level, gpa_attr,
				      attr_flags, &out);

	switch (err & TDX_TDCALL_STATUS_MASK) {
	case TDX_SUCCESS: break;
	case TDX_PAGE_SIZE_MISMATCH:
	case TDX_OPERAND_INVALID:
	default:
		kvm_pr_unimpl("TDG.MEM.PAGE.ATTR.WR "
			      "error: 0x%llx\n", err);
		KVM_BUG_ON(1, kvm);
		return -EPERM;
	}

	/*
	 * out.rdx indicates whether the TDG.MEM.PAGE.ATTR.WR call
	 * successfully set the attribute or not. On success, RDX
	 * returns the updated guest-visible page attributes.
	 */
	if (KVM_BUG_ON((out.rdx & (gpa_attr.bits | attr_flags.bits)) !=
		       gpa_attr.bits, kvm))
		return -EFAULT;

	return 0;
}

static int drop_alias(struct kvm *kvm, gfn_t gfn, enum pg_level level)
{
	u8 vm_id = kvm->arch.vm_id;
	gpa_t gpa = gfn_to_gpa(gfn);
	int tdx_level = pg_level_to_tdx_sept_level(level);
	union tdx_gpa_attr gpa_attr = { 0 };
	union tdx_attr_flags attr_flags = { 0 };
	struct tdx_module_output out;
	u64 err;

	if (KVM_BUG_ON(!vm_id || vm_id > 3, kvm))
		return -EINVAL;

	gpa_attr.fields[vm_id].valid = 1;
	attr_flags.flags[vm_id].attr_mask = 0x7;

	/* TODO clear bottom gpa bits for large leaves */
	err = tdg_mem_page_attr_write(gpa, tdx_level, gpa_attr,
				      attr_flags, &out);

	switch (err & TDX_TDCALL_STATUS_MASK) {
	case TDX_SUCCESS: break;
	case TDX_PAGE_SIZE_MISMATCH:
	case TDX_OPERAND_INVALID:
	default:
		kvm_pr_unimpl("TDG.MEM.PAGE.ATTR.WR "
			      "error: 0x%llx\n", err);
		KVM_BUG_ON(1, kvm);
		return -EPERM;
	}

	/*
	 * out.rdx indicates whether the TDG.MEM.PAGE.ATTR.WR call
	 * successfully set the attribute or not. On success, RDX
	 * returns the updated guest-visible page attributes.
	 */
	if (KVM_BUG_ON((out.rdx & (gpa_attr.bits | attr_flags.bits)) !=
		       gpa_attr.bits, kvm))
		return -EFAULT;

	return 0;
}

static int td_part_set_private_spte(struct kvm *kvm, gfn_t gfn,
				    enum pg_level level, kvm_pfn_t pfn,
				    unsigned int access)
{
	if (KVM_BUG_ON(!is_td_part(kvm), kvm))
		return -EINVAL;

	/* Must be identity mapped */
	if (KVM_BUG_ON(gfn != pfn, kvm))
		return -EFAULT;

	WARN_ON(!(access & ACC_USER_MASK));
	return add_alias(kvm, gfn, level, !!(access & ACC_WRITE_MASK),
			 !!(access & ACC_EXEC_MASK));
}

static int td_part_drop_private_spte(
	struct kvm *kvm, gfn_t gfn, enum pg_level level, kvm_pfn_t pfn)
{
	if (KVM_BUG_ON(!is_td_part(kvm), kvm))
		return -EINVAL;

	/* Must be identity mapped */
	if (KVM_BUG_ON(gfn != pfn, kvm))
		return -EFAULT;

	/* Nothing to do here as private zapped pages are already dropped */
	return 0;
}

static int td_part_remove_private_spte(struct kvm *kvm, gfn_t gfn,
				       enum pg_level level, kvm_pfn_t pfn)
{
	return td_part_drop_private_spte(kvm, gfn, level, pfn);
}

static int td_part_zap_private_spte(struct kvm *kvm, gfn_t gfn,
				    enum pg_level level)
{
	if (KVM_BUG_ON(!is_td_part(kvm), kvm))
		return -EINVAL;

	return drop_alias(kvm, gfn, level);
}

static int td_part_unzap_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level, unsigned int access)
{
	if (KVM_BUG_ON(!is_td_part(kvm), kvm))
		return -EINVAL;

	WARN_ON(!(access & ACC_USER_MASK));
	return add_alias(kvm, gfn, level, !!(access & ACC_WRITE_MASK),
			 !!(access & ACC_EXEC_MASK));
}

static int td_part_link_private_spt(struct kvm *kvm, gfn_t gfn,
				    enum pg_level level, void *private_spt)
{
	if (KVM_BUG_ON(!is_td_part(kvm), kvm))
		return -EINVAL;

	/* Not needed as SEPTs are linked by L0 VMM */
	return 0;
}

static void td_part_write_block_private_pages(struct kvm *kvm, gfn_t *gfns,
					      uint32_t num)
{
	uint32_t i;

	if (KVM_BUG_ON(!is_td_part(kvm), kvm))
		return;

	for (i = 0; i < num; i++)
		modify_alias_w(kvm, gfns[i], PG_LEVEL_4K, false);
}

static void td_part_write_unblock_private_page(struct kvm *kvm,
					       gfn_t gfn, int level)
{
	if (KVM_BUG_ON(!is_td_part(kvm), kvm))
		return;

	modify_alias_w(kvm, gfn, level, true);
}

static int td_part_restore_private_page(struct kvm *kvm, gfn_t gfn)
{
	kvm_pr_unimpl("TD_PART: %s not supported\n", __func__);
	kvm_vm_bugged(kvm);
	return -EOPNOTSUPP;
}

void td_part_update_reserved_gpa_bits(struct kvm_vcpu *vcpu)
{
	u64 shared_mask = tdx_get_cc_mask();
	int gpaw, maxphyaddr;

	if (!WARN_ON_ONCE(!shared_mask)) {
		gpaw = __ffs64(shared_mask) + 1;
		maxphyaddr = vcpu->arch.maxphyaddr;

		/* TODO allow shared bit if supported */
		vcpu->arch.maxphyaddr = min(maxphyaddr, gpaw - 1);
		vcpu->arch.reserved_gpa_bits =
			kvm_vcpu_reserved_gpa_bits_raw(vcpu);
		/*
		 * Restore the original value so that vmx_need_pf_intercept()
		 * continues to work as expected.
		 */
		vcpu->arch.maxphyaddr = maxphyaddr;
	}
}

int td_part_vcpu_create(struct kvm_vcpu *vcpu)
{
	/* Initially APIC is in xAPIC mode, mark APICv active as false (disabled) */
	vcpu->arch.apic->apicv_active = false;

	td_part_update_reserved_gpa_bits(vcpu);

	return 0;
}

static bool set_control_cond(int cpu, void *data)
{
	struct kvm *kvm = data;

	return !kvm->vm_bugged;
}

static void set_control(void *data)
{
	struct kvm *kvm = data;
	struct tdx_module_output out;
	union tdx_l2_vcpu_ctls l2_ctls = {0};
	u16 vm_id = kvm->arch.vm_id;
	u64 ret;

	/*
	 * Turn off TDVMCALL and #VE for TD partitioning guests.
	 */
	l2_ctls.enable_shared_eptp = 1;
	ret = tdg_vp_write(TDX_MD_TDVPS_L2_CTLS + vm_id, l2_ctls.full, TDX_L2_CTLS_MASK, &out);
	if (KVM_BUG_ON(ret != TDX_SUCCESS, kvm)) {
		pr_err("%s: tdg_vp_write L2 CTLS field failed, err=%llx\n",
			__func__, ret);
		kvm_vm_bugged(kvm);
	}
}

int td_part_vm_init(struct kvm *kvm)
{
	u16 vm_id;

	/* Disable APICv initially (in xAPIC mode), enable APICv only when in X2APIC mode */
	kvm_set_or_clear_apicv_inhibit(kvm, APICV_INHIBIT_REASON_DISABLE, true);

	kvm->arch.gfn_shared_mask = gpa_to_gfn(tdx_get_cc_mask());

	/* TODO large page support */
	kvm->arch.tdp_max_page_level = PG_LEVEL_4K;

	vm_id = find_first_zero_bit(td_part_vm_id_bitmap, TD_PART_MAX_NUM_VMS);
	if (!vm_id || (vm_id >= TD_PART_MAX_NUM_VMS) || (vm_id > num_l2_vms)) {
		pr_err("%s: no valid VM ID (%d/%d) available for L2 VM\n",
			__func__, vm_id, num_l2_vms);
		return -ENOTSUPP;
	}

	set_bit(vm_id, td_part_vm_id_bitmap);
	kvm->arch.vm_id = vm_id;

	/* L2 control field is per-CPU */
	on_each_cpu_cond(set_control_cond, set_control, kvm, 1);

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

	x86_ops->free_private_spt = td_part_free_private_spt;
	x86_ops->split_private_spt = td_part_split_private_spt;
	x86_ops->merge_private_spt = td_part_merge_private_spt;
	x86_ops->set_private_spte = td_part_set_private_spte;
	x86_ops->remove_private_spte = td_part_remove_private_spte;
	x86_ops->drop_private_spte = td_part_drop_private_spte;
	x86_ops->zap_private_spte = td_part_zap_private_spte;
	x86_ops->unzap_private_spte = td_part_unzap_private_spte;
	x86_ops->link_private_spt = td_part_link_private_spt;
	x86_ops->write_block_private_pages = td_part_write_block_private_pages;
	x86_ops->write_unblock_private_page = td_part_write_unblock_private_page;
	x86_ops->restore_private_page = td_part_restore_private_page;

	allow_smaller_maxphyaddr = true;

	return 0;
}

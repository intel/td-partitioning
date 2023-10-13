/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2022 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/init.h>
#include <linux/bits.h>

#include <asm/errno.h>
#include <asm/ptrace.h>
#include <asm/trapnr.h>
#include <asm/shared/tdx.h>

/*
 * SW-defined error codes.
 *
 * Bits 47:40 == 0xFF indicate Reserved status code class that never used by
 * TDX module.
 */
#define TDX_ERROR			_BITULL(63)
#define TDX_SW_ERROR			(TDX_ERROR | GENMASK_ULL(47, 40))
#define TDX_SEAMCALL_VMFAILINVALID	(TDX_SW_ERROR | _ULL(0xFFFF0000))

#define TDX_SEAMCALL_GP			(TDX_SW_ERROR | X86_TRAP_GP)
#define TDX_SEAMCALL_UD			(TDX_SW_ERROR | X86_TRAP_UD)

#define TDX_NON_RECOVERABLE_BIT		62
/*
 * Error with the non-recoverable bit cleared indicates that the error is
 * likely recoverable (e.g. due to lock busy in TDX module), and the seamcall
 * can be retried.
 */
#define TDX_SEAMCALL_ERR_RECOVERABLE(err) \
	(err >> TDX_NON_RECOVERABLE_BIT == 0x2)

/* The max number of seamcall retries */
#define TDX_SEAMCALL_RETRY_MAX	10000

#ifndef __ASSEMBLY__

enum tdx_notifier_event {
	/* Start a TDX module update */
	TDX_UPDATE_START,
	/* Update succeeded. A new module takes over */
	TDX_UPDATE_SUCCESS,
	/* Update aborted. the old module still functions */
	TDX_UPDATE_ABORT,
	/* Failed, no working TDX module */
	TDX_UPDATE_FAIL,
};

/*
 * Used by the #VE exception handler to gather the #VE exception
 * info from the TDX module. This is a software only structure
 * and not part of the TDX module/VMM ABI.
 */
struct ve_info {
	u64 exit_reason;
	u64 exit_qual;
	/* Guest Linear (virtual) Address */
	u64 gla;
	/* Guest Physical Address */
	u64 gpa;
	u32 instr_len;
	u32 instr_info;
};

#ifdef CONFIG_INTEL_TDX_GUEST

extern int tdx_notify_irq;

void __init tdx_early_init(void);
bool tdx_debug_enabled(void);

void tdx_get_ve_info(struct ve_info *ve);

void __init tdx_filter_init(void);

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve);

void tdx_safe_halt(void);

bool tdx_early_handle_ve(struct pt_regs *regs);

int tdx_mcall_get_report0(u8 *reportdata, u8 *tdreport);

bool tdx_allowed_port(int port);

u64 tdx_mcall_verify_report(u8 *reportmac);

int tdx_mcall_extend_rtmr(u8 *data, u8 index);

int tdx_hcall_get_quote(void *tdquote, int size);

int tdx_alloc_event_irq(void);

void tdx_free_event_irq(int);

int tdx_map_private_mmio(phys_addr_t gpa, u64 offset, int numpages);

#else

static inline void tdx_early_init(void) { };
static inline void tdx_safe_halt(void) { };
static inline void tdx_filter_init(void) { };

static inline bool tdx_early_handle_ve(struct pt_regs *regs) { return false; }

static inline int tdx_map_private_mmio(phys_addr_t gpa, u64 offset, int numpages)
			{ return -EOPNOTSUPP; }

#endif /* CONFIG_INTEL_TDX_GUEST */

#if defined(CONFIG_KVM_GUEST) && defined(CONFIG_INTEL_TDX_GUEST)
long tdx_kvm_hypercall(unsigned int nr, unsigned long p1, unsigned long p2,
		       unsigned long p3, unsigned long p4);
#else
static inline long tdx_kvm_hypercall(unsigned int nr, unsigned long p1,
				     unsigned long p2, unsigned long p3,
				     unsigned long p4)
{
	return -ENODEV;
}
#endif /* CONFIG_INTEL_TDX_GUEST && CONFIG_KVM_GUEST */

#ifdef CONFIG_INTEL_TDX_HOST
u64 __seamcall(u64 fn, struct tdx_module_args *args);
u64 __seamcall_ret(u64 fn, struct tdx_module_args *args);
u64 __seamcall_saved(u64 fn, struct tdx_module_args *args);
u64 __seamcall_saved_ret(u64 fn, struct tdx_module_args *args);

#define DEBUGCONFIG_TRACE_ALL		0
#define DEBUGCONFIG_TRACE_WARN		1
#define DEBUGCONFIG_TRACE_ERROR		2
#define DEBUGCONFIG_TRACE_CUSTOM	1000
#define DEBUGCONFIG_TRACE_NONE		-1ULL
void tdx_trace_seamcalls(u64 level);

/* -1 indicates CPUID leaf with no sub-leaves. */
#define TDX_CPUID_NO_SUBLEAF	((u32)-1)
struct tdx_cpuid_config {
	__struct_group(tdx_cpuid_config_leaf, leaf_sub_leaf, __packed,
		u32 leaf;
		u32 sub_leaf;
	);
	__struct_group(tdx_cpuid_config_value, value, __packed,
		u32 eax;
		u32 ebx;
		u32 ecx;
		u32 edx;
	);
} __packed;

#define TDSYSINFO_STRUCT_SIZE		1024

/*
 * The size of this structure itself is flexible.  The actual structure
 * passed to TDH.SYS.INFO must be padded to 1024 bytes and be 1204-bytes
 * aligned.
 */
#define TDSYSINFO_ATTRIBUTES_DEBUG	BIT(31)
struct tdsysinfo_struct {
	/* TDX-SEAM Module Info */
	u32	attributes;
	u32	vendor_id;
	u32	build_date;
	u16	build_num;
	u16	minor_version;
	u16	major_version;
	u8	sys_rd;
	u8	reserved0[13];
	/* Memory Info */
	u16	max_tdmrs;
	u16	max_reserved_per_tdmr;
	u16	pamt_entry_size;
	u8	reserved1[10];
	/* Control Struct Info */
	u16	tdcs_base_size;
	u8	reserved2[2];
	u16	tdvps_base_size;
	u8	tdvps_xfam_dependent_size;
	u8	reserved3[9];
	/* TD Capabilities */
	u64	attributes_fixed0;
	u64	attributes_fixed1;
	u64	xfam_fixed0;
	u64	xfam_fixed1;
	u8	reserved4[32];
	u32	num_cpuid_config;
	/*
	 * The actual number of CPUID_CONFIG depends on above
	 * 'num_cpuid_config'.
	 */
	DECLARE_FLEX_ARRAY(struct tdx_cpuid_config, cpuid_configs);
} __packed;

#include <linux/bug.h>
static __always_inline int pg_level_to_tdx_sept_level(enum pg_level level)
{
	WARN_ON_ONCE(level == PG_LEVEL_NONE);
	return level - 1;
}

#include <asm/processor.h>
static __always_inline u64 set_hkid_to_hpa(u64 pa, u16 hkid)
{
	return pa | ((u64)hkid << boot_cpu_data.x86_phys_bits);
}

const struct tdsysinfo_struct *tdx_get_sysinfo(void);
bool platform_tdx_enabled(void);
int tdx_enable(void);
void tdx_reset_memory(void);
bool tdx_is_private_mem(unsigned long phys);

/*
 * Key id globally used by TDX module: TDX module maps TDR with this TDX global
 * key id.  TDR includes key id assigned to the TD.  Then TDX module maps other
 * TD-related pages with the assigned key id.  TDR requires this TDX global key
 * id for cache flush unlike other TD-related pages.
 */
extern u32 tdx_global_keyid;
u32 tdx_get_nr_guest_keyids(void);
int tdx_guest_keyid_alloc(void);
void tdx_guest_keyid_free(int keyid);
int __init tdx_init(void);

/* tdxio related */
bool tdx_io_support(void);
bool tdx_io_enabled(void);
void tdx_clear_page(unsigned long page_pa, int size);
void tdx_set_page_present_level(unsigned long addr, enum pg_level pg_level);
int __tdx_reclaim_page(unsigned long pa, enum pg_level level, bool do_wb, u16 hkid);
int tdx_reclaim_page(unsigned long pa, bool do_wb, u16 hkid);
void tdx_reclaim_td_page(unsigned long td_page_pa);

/* Export Intel-IOMMU registers for other components */
#define DMAR_CONFIG_RP_REG	0x8000000B
#define DMAR_CLEAR_RP_REG	0x8000000C

#define TDH_PHYMEM_PAGE_RECLAIM		28
#define TDH_PHYMEM_PAGE_WBINVD		41
#define TDH_IOMMU_SETREG		128
#define TDH_IOMMU_GETREG		129
#define TDH_SPDM_CREATE			130
#define TDH_SPDM_DELETE			131
#define TDH_IDE_STREAM_CREATE		132
#define TDH_IDE_STREAM_BLOCK		133
#define TDH_IDE_STREAM_DELETE		134
#define TDH_IDE_STREAM_IDEKMREQ		135
#define TDH_IDE_STREAM_IDEKMRSP		136
#define TDH_DEVIF_CREATE		137
#define TDH_DEVIF_REMOVE		138
#define TDH_DEVIF_REQUEST		139
#define TDH_DEVIF_RESPONSE		140
#define TDH_DMAR_ADD			150
#define TDH_DMAR_BLOCK			151
#define TDH_DMAR_READ			152
#define TDH_DMAR_REMOVE			153
#define TDH_MMIOMT_ADD			154
#define TDH_MMIOMT_SET			155
#define TDH_MMIOMT_RD			156
#define TDH_MMIOMT_REMOVE		157
#define TDH_MMIO_MAP			158
#define TDH_MMIO_BLOCK			159
#define TDH_MMIO_UNMAP			160
#define TDH_IQINV_REQ			161
#define TDH_IQINV_PROC			162
#define TDH_MEM_SHARED_SEPT_WR		163
#define TDH_DEVIFMT_ADD			164
#define TDH_DEVIFMT_REMOVE		165
#define TDH_DEVIFMT_RD			166

/* Temp solution, copied from tdx_error.h */
#define TDX_INTERRUPTED_RESUMABLE		0x8000000300000000ULL
#define TDX_VCPU_ASSOCIATED			0x8000070100000000ULL
#define TDX_VCPU_NOT_ASSOCIATED			0x8000070200000000ULL

#define TDX_SEAMCALL_STATUS_MASK		0xFFFFFFFF00000000ULL

static inline u64 __seamcall_retry(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			         u64 r10, u64 r11, u64 r12, u64 r13, u64 r14,
				 u64 r15,
				 struct tdx_module_args *out, bool need_saved)
{
	u64 ret, retries = 0;

	do {
		if (out) {
			*out = (struct tdx_module_args) {
				.rcx = rcx,
				.rdx = rdx,
				.r8 = r8,
				.r9 = r9,
				.r10 = r10,
				.r11 = r11,
			};
			if (need_saved) {
				out->r12 = r12;
				out->r13 = r13;
				out->r14 = r14;
				out->r15 = r15;
				ret = __seamcall_saved_ret(op, out);
			} else {
				ret = __seamcall_ret(op, out);
			}
		} else {
			struct tdx_module_args args = {
				.rcx = rcx,
				.rdx = rdx,
				.r8 = r8,
				.r9 = r9,
				.r10 = r10,
				.r11 = r11,
			};
			if (need_saved) {
				args.r12 = r12;
				args.r13 = r13;
				args.r14 = r14;
				args.r15 = r15;
				ret = __seamcall_saved(op, &args);
			} else {
				ret = __seamcall(op, &args);
			}
		}
		if (unlikely(ret == TDX_SEAMCALL_UD)) {
			/*
			 * SEAMCALLs fail with TDX_SEAMCALL_UD returned when VMX is off.
			 * This can happen when the host gets rebooted or live
			 * updated. In this case, the instruction execution is ignored
			 * as KVM is shut down, so the error code is suppressed. Other
			 * than this, the error is unexpected and the execution can't
			 * continue as the TDX features reply on VMX to be on.
			 */
			pr_err("%s ret 0x%llx TDX_SEAMCALL_UD\n", __func__, ret);
			return ret;
		}
		if (!ret ||
		    ret == TDX_VCPU_ASSOCIATED ||
		    ret == TDX_VCPU_NOT_ASSOCIATED ||
		    ret == TDX_INTERRUPTED_RESUMABLE)
			return ret;

		if (retries++ > TDX_SEAMCALL_RETRY_MAX)
			break;
	} while (TDX_SEAMCALL_ERR_RECOVERABLE(ret));

	return ret;
}

static inline u64 seamcall_retry(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			         u64 r10, u64 r11,
				 struct tdx_module_args *out)
{
	return __seamcall_retry(op, rcx, rdx, r8, r9, r10, r11,
				0, 0, 0, 0, out, false);
}

static inline u64 seamcall_retry_saved(u64 op, u64 rcx, u64 rdx, u64 r8,
				       u64 r9, u64 r10, u64 r11, u64 r12,
				       u64 r13, u64 r14, u64 r15,
				       struct tdx_module_args *out)
{
	return __seamcall_retry(op, rcx, rdx, r8, r9, r10, r11, r12, r13, r14,
				r15, out, true);
}

static inline u64 tdh_phymem_page_reclaim(u64 page,
					  struct tdx_module_args *out)
{
	return seamcall_retry(TDH_PHYMEM_PAGE_RECLAIM,
			      page, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_phymem_page_wbinvd(u64 page)
{
	return seamcall_retry(TDH_PHYMEM_PAGE_WBINVD,
			      page, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_iommu_setreg(u64 iommu_id, u64 reg, u64 val)
{
	u64 ret;

        /*
         * Input: RCX: iommu id
         * Input: RDX: register id
         * Input: R8:  register value
         */
	ret = seamcall_retry(TDH_IOMMU_SETREG, iommu_id, reg, val,
			     0, 0, 0, NULL);

	pr_info("%s: iommu_id 0x%llx reg 0x%llx val 0x%llx ret 0x%llx\n",
		__func__, iommu_id, reg, val, ret);

	return ret;
}

static inline u64 tdh_iommu_getreg(u64 iommu_id, u64 reg, u64 *val)
{
        struct tdx_module_args out;
        u64 ret;

	/*
         * Input: RCX: iommu id
         * Input: RDX: register id
         * Output: R8: register value
	 */
	ret = seamcall_retry(TDH_IOMMU_GETREG, iommu_id, reg,
			     0, 0, 0, 0, &out);

	pr_info("%s: iommu_id 0x%llx reg 0x%llx val 0x%llx ret 0x%llx\n",
		__func__, iommu_id, reg, out.r8, ret);

	if (!ret)
		*val = out.r8;

        return ret;
}

static inline u64 tdh_spdm_create(u64 iommu_id, u64 spdm_session_idx, u64 spdm_info_pa)
{
	u64 ret;

	/*
	 * TDH.SPDM.CREATE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - SPDM session index of device connected to stream
	 * Input: R8  - Physical address of page a free page in PAMT to
	 * hold SPDM session information
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 */

	ret = seamcall_retry(TDH_SPDM_CREATE, iommu_id, spdm_session_idx,
			     spdm_info_pa, 0, 0, 0, NULL);
	pr_info("%s: iommu_id 0x%llx spdm_session_idx 0x%llx spdm_info_pa 0x%llx ret 0x%llx\n",
		__func__, iommu_id, spdm_session_idx, spdm_info_pa, ret);

	return ret;
}

static inline u64 tdh_spdm_delete(u64 iommu_id, u64 spdm_session_idx, u64 *spdm_info_pa)
{
	struct tdx_module_args out;
	u64 ret;

	/*
	 * TDH.SPDM.DELETE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - SPDM session index of device connected to stream
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 * Output: RCX - Physical address of the freed SPDM session information page
	 */

	ret = seamcall_retry(TDH_SPDM_DELETE, iommu_id, spdm_session_idx,
			     0, 0, 0, 0, &out);
	pr_info("%s: iommu_id 0x%llx spdm_session_idx 0x%llx ret 0x%llx\n",
		__func__, iommu_id, spdm_session_idx, ret);

	if (!ret && spdm_info_pa)
		*spdm_info_pa = out.rcx;

	return ret;
}

static inline u64 tdh_ide_stream_create(u64 iommu_id,
					u64 spdm_session_idx,
					u64 stream_cfg_reg,
					u64 stream_ctrl_reg,
					u64 rid_assoc1_reg,
					u64 rid_assoc2_reg,
					u64 addr_assoc1_reg,
					u64 addr_assoc2_reg,
					u64 addr_assoc3_reg,
					u64 stream_exinfo_pa)
{
	u64 ret;

	/*
	 * TDH.IDE.STREAM.CREATE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - SPDM session index of device connected to stream
	 * Input: R8  - Stream configuration information   Type: IDE_STREAM_CONFIG_T
	 * Input: R9  - Stream Control register configurations   Type: IDE_STREAM_CONTROL_T
	 * Input: R10 - RID association register 1   Type: IDE_RID_ASSOC_REG_1_T
	 * Input: R11 - RID association register 2   Type: IDE_RID_ASSOC_REG_2_T
	 * Input: R12 - Address association register 1   Type: IDE_ADDR_ASSOC_REG_1_T
	 * Input: R13 - Address association register 2   Type: IDE_ADDR_ASSOC_REG_2_T
	 * Input: R14 - Address association register 3   Type: IDE_ADDR_ASSOC_REG_3_T
	 * Input: R15 - Physical address of a free page in PAMT to
	 * hold stream extended information
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 */

	ret = seamcall_retry_saved(TDH_IDE_STREAM_CREATE, iommu_id, spdm_session_idx,
				   stream_cfg_reg, stream_ctrl_reg, rid_assoc1_reg,
				   rid_assoc2_reg, addr_assoc1_reg, addr_assoc2_reg,
				   addr_assoc3_reg, stream_exinfo_pa, NULL);
	pr_info("%s: iommu_id 0x%llx spdm_session_idx 0x%llx stream_cfg 0x%llx stream_ctrl_reg 0x%llx rid_assoc1_reg 0x%llx rid_assoc2_reg 0x%llx addr_assoc1_reg 0x%llx addr_assoc2_reg 0x%llx addr_assoc3_reg 0x%llx stream_exinfo_pa 0x%llx ret 0x%llx\n",
		__func__, iommu_id, spdm_session_idx, stream_cfg_reg, stream_ctrl_reg,
		rid_assoc1_reg, rid_assoc2_reg, addr_assoc1_reg, addr_assoc2_reg,
		addr_assoc3_reg, stream_exinfo_pa, ret);

	return ret;
}

static inline u64 tdh_ide_stream_block(u64 iommu_id, u64 stream_id)
{
	u64 ret;

	/*
	 * TDH.IDE.STREAM.BLOCK
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - Stream ID of stream to delete
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 */

	ret = seamcall_retry(TDH_IDE_STREAM_BLOCK, iommu_id, stream_id,
			     0, 0, 0, 0, NULL);
	pr_info("%s: iommu_id 0x%llx stream_id 0x%llx ret 0x%llx\n",
		__func__, iommu_id, stream_id, ret);

	return ret;
}

static inline u64 tdh_ide_stream_delete(u64 iommu_id, u64 stream_id)
{
	u64 ret;

	/*
	 * TDH.IDE.STREAM.DELETE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - Stream ID of stream to delete
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 */

	ret = seamcall_retry(TDH_IDE_STREAM_DELETE, iommu_id, stream_id,
			     0, 0, 0, 0, NULL);

	pr_info("%s: iommu_id 0x%llx stream_id 0x%llx ret 0x%llx\n",
		__func__, iommu_id, stream_id, ret);

	return ret;
}

static inline u64 tdh_ide_stream_idekmreq(u64 iommu_id,
					  u64 stream_id,
					  u64 object_id,
					  u64 ide_km_param,
					  u64 slot_id,
					  u64 message_pa)
{
	u64 ret;

	/*
	 * TDH.IDE.STREAM.IDEKMREQ
	 *
	 * Input: RAX - SEAMCALL ins]truction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - Stream ID of stream to generate key management request message for
	 * Input: R8  - Object ID of message to generate
	 * Input: R9  - IDE Key Management message parameters - Type: IDE_KM_PARAM_T
	 * Input: R10 - Key Slot ID to configure if needed in the root port
	 * Input: R11 - Physical address of a shared memory buffer in which to
	 * emit the key management protocol message
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 */

	ret = seamcall_retry(TDH_IDE_STREAM_IDEKMREQ, iommu_id, stream_id,
			     object_id, ide_km_param, slot_id, message_pa,
			     NULL);

	pr_info("%s: iommu_id 0x%llx stream_id 0x%llx object_id 0x%llx ide_km_param 0x%llx slot_id 0x%llx message_pa 0x%llx ret 0x%llx\n",
		__func__, iommu_id, stream_id, object_id,
		ide_km_param, slot_id, message_pa, ret);

	return ret;
}

static inline u64 tdh_ide_stream_idekmrsp(u64 iommu_id,
					  u64 stream_id,
					  u64 message_pa,
					  u64 *resp_data)
{
	struct tdx_module_args out;
	u64 ret;

	/*
	 * TDH.IDE.STREAM.IDEKMRSP
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - Stream ID of stream to generate key management request message for
	 * Input: R8  - Physical address of a shared memory buffer holding the response message
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 * Output: RCX - Returns 8 bytes of the IDE Key management response
	 * if authentication successful
	 */

	ret = seamcall_retry(TDH_IDE_STREAM_IDEKMRSP, iommu_id, stream_id,
			     message_pa, 0, 0, 0, &out);
	pr_info("%s: iommu_id 0x%llx stream_id 0x%llx message_pa 0x%llx ret 0x%llx\n",
		__func__, iommu_id, stream_id, message_pa, ret);

	if (!ret && resp_data)
		*resp_data = out.rcx;

	return ret;
}

static inline u64 tdh_mmiomt_add(u64 mmiomt_idx, u64 mmiomt_pa)
{
	u64 ret;
	/*
	 * TDH.MMIOMT.ADD
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - MMIOMT index (level + PA)
	 * Input: RDX - MMIOMT PA of new page
	 *
	 */
	ret =  seamcall_retry(TDH_MMIOMT_ADD, mmiomt_idx, mmiomt_pa,
			      0, 0, 0, 0, NULL);
	pr_debug("%s: ret %llx, mmiomt_idx %llx, mmiomt_pa %llx\n",
		 __func__, ret, mmiomt_idx, mmiomt_pa);

	return ret;
}

static inline u64 tdh_mmiomt_set(u64 mmiomt_idx, u64 mmiomt_info)
{
	u64 ret;
	/*
	 * TDH.MMIOMT.SET
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - MMIOMT index (level + PA)
	 * Input: RDX - MMIOMT INFO: devifcs PA and DATA type
	 *
	 */
	ret = seamcall_retry(TDH_MMIOMT_SET, mmiomt_idx, mmiomt_info,
			     0, 0, 0, 0, NULL);

	pr_debug("%s: ret %llx, mmiomt_idx %llx, mmiomt_info %llx\n",
		 __func__, ret, mmiomt_idx, mmiomt_info);

	return ret;
}

static inline u64 tdh_mmiomt_read(u64 mmiomt_idx, struct tdx_module_args *out)
{
	/*
	 * TDH.MMIOMT.READ
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - MMIOMT index (level + PA)
	 *
	 * Output: Entry Value - RCX, RDX, R8, R9
	 */
	return seamcall_retry(TDH_MMIOMT_RD, mmiomt_idx,
			      0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mmiomt_remove(u64 mmiomt_idx)
{
	u64 ret;
	/*
	 * TDH.MMIOMT.REMOVE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX -  MMIOMT index
	 *
	 */
	ret = seamcall_retry(TDH_MMIOMT_REMOVE, mmiomt_idx,
			     0, 0, 0, 0, 0, NULL);

	pr_debug("%s: ret %llx, mmiomt_idx %llx\n",
		 __func__, ret, mmiomt_idx);

	return ret;
}

static inline u64 tdh_mmio_map(u64 gpa_page_info, u64 tdr_pa, u64 mmio_pa)
{
	/*
	 * TDH.MMIO.MAP
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX -  GPA PAGE INFO
	 * Input: RDX - TDR PA
	 * Input: R8 - MMIO PA
	 */
	return seamcall_retry(TDH_MMIO_MAP, gpa_page_info, tdr_pa, mmio_pa,
			      0, 0, 0, NULL);
}

static inline u64 tdh_mmio_block(u64 gpa_page_info, u64 tdr_pa)
{
	/*
	 * TDH.MMIO.BLOCK
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX -  GPA PAGE INFO
	 * Input: RDX - TDR PA
	 */
	return seamcall_retry(TDH_MMIO_BLOCK, gpa_page_info, tdr_pa,
			      0, 0, 0, 0, NULL);
}

static inline u64 tdh_mmio_unmap(u64 gpa_page_info, u64 tdr_pa)
{
	/*
	 * TDH.MMIO.UNMAP
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX -  GPA PAGE INFO
	 * Input: RDX - TDR PA
	 */
	return seamcall_retry(TDH_MMIO_UNMAP, gpa_page_info, tdr_pa,
			      0, 0, 0, 0, NULL);
}

static inline u64 tdh_dmar_add(u64 index, u64 tdr_pa, u64 entry0, u64 entry1,
			       u64 entry2, u64 entry3, u64 entry4, u64 entry5,
			       u64 entry6, u64 entry7)
{
	/*
	 * TDH.DMAR.ADD
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - Index to locate the DMAR entry
	 * Input: RDX - TDR, valid for PASIDTE only
	 * Input: R8-R15 - parameters
	 *   RTE: R8 R9
	 *   CTE: R8 R9 R10 R11
	 *   PASIDDE: R8
	 *   PASIDTE: R8 R9 R10 R11 R12 R13 R14 R15
	 *
	 * Output: RAX - SEAMCALL return code
	 */
	return seamcall_retry_saved(TDH_DMAR_ADD, index, tdr_pa,
				    entry0, entry1, entry2, entry3,
				    entry4, entry5, entry6, entry7, NULL);
}

static inline u64 tdh_dmar_block(u64 index)
{
	/*
	 * TDH.DMAR.BLOCK
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - Index to locate the DMAR entry
	 *
	 * Output: RAX - SEAMCALL return code
	 */
	return seamcall_retry(TDH_DMAR_BLOCK, index,
			      0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_dmar_read(u64 index, struct tdx_module_args *out)
{
	/*
	 * TDH.DMAR.READ
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - Index to locate the DMAR entry
	 *
	 * Output: RAX - SEAMCALL return code
	 * Output: R8-R15
	 */
	return seamcall_retry_saved(TDH_DMAR_READ, index,
				    0, 0, 0, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_dmar_remove(u64 index)
{
	/*
	 * TDH.DMAR.REMOVE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - Index to locate the DMAR entry
	 *
	 * Output: RAX - SEAMCALL return code
	 */
	return seamcall_retry(TDH_DMAR_REMOVE, index,
			      0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_iqinv_req(u64 iommu_id, u64 inv_type, u64 inv_target,
				u64 wait_desc_1, u64 wait_desc_2,
				u64 wait_desc_3, u64 wait_desc_4)
{
	/*
	 * TDH.IQ.INV.REQUEST
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU ID
	 * Input: RDX - INVALIDATION TYPE
	 * Input: R8  - RID, PASID and TDR PA
	 * Input: R9 - Invalidation Wait Descriptor bits 63:0
	 * Input: R10 - Invalidation Wait Descriptor bits 127:64
	 * Input: R11 - Invalidation Wait Descriptor bits 128:191
	 * Input: R12 - Invalidation Wait Descriptor bits 192:255
	 */
	return seamcall_retry_saved(TDH_IQINV_REQ, iommu_id, inv_type,
				    inv_target, wait_desc_1, wait_desc_2,
				    wait_desc_3, wait_desc_4, 0, 0, 0, NULL);
}

static inline u64 tdh_iqinv_process(u64 iommu_id)
{
	/*
	 * TDH.IQ.INV.PROCESS
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU ID
	 */
	return seamcall_retry(TDH_IQINV_PROC, iommu_id,
			      0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_shared_sept_wr(u64 gpa_info, u64 tdr_pa, u64 entry,
					 struct tdx_module_args *out)
{
	/*
	 * TDH.MEM.SHARED.SEPT.WR
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - GPA [51:12] + Level [2:0] - must be GPAW + 3
	 * Input: RDX - TDR page
	 * Input: R8 - EPT entry value
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 * Output: RCX - Secure EPT entry architectural content
	 */
	return seamcall_retry(TDH_MEM_SHARED_SEPT_WR, gpa_info, tdr_pa, entry,
			      0, 0, 0, out);
}

static inline u64 tdh_devifmt_add(u64 devifmt_idx, u64 devifmt_pa)
{
	u64 ret;
	/*
	 * TDH.DEVIFMT.ADD
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - DEVIFMT index (level + function id)
	 * Input: RDX - DEVIFMT PA of new page
	 */
	ret = seamcall_retry(TDH_DEVIFMT_ADD, devifmt_idx, devifmt_pa,
			     0, 0, 0, 0, NULL);
	pr_debug("%s: ret %llx, devifmt_idx %llx, devifmt_pa %llx\n",
		 __func__, ret, devifmt_idx, devifmt_pa);

	return ret;
}

static inline u64 tdh_devifmt_remove(u64 devifmt_idx)
{
	u64 ret;
	/*
	 * TDH.DEVIFMT.REMOVE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - DEVIFMT index (level + function id)
	 */
	ret = seamcall_retry(TDH_DEVIFMT_REMOVE, devifmt_idx,
			     0, 0, 0, 0, 0, NULL);

	pr_debug("%s: ret %llx, devifmt_idx %llx\n",
		 __func__, ret, devifmt_idx);

	return ret;
}

static inline u64 tdh_devifmt_read(u64 devifmt_idx, struct tdx_module_args *out)
{
	/*
	 * TDH.DEVIFMT.READ
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - DEVIFMT index (level + function id)
	 *
	 * Output: RAX - SEAMCALL return code
	 * Output: RCX - DEVIFMT entry data
	 */
	return seamcall_retry(TDH_DEVIFMT_RD, devifmt_idx,
			      0, 0, 0, 0, 0, out);
}

static inline u64 tdh_devif_create(u64 devif_id, u64 tdr_pa, u64 devifcs_pa,
				   u64 td_tdisp_msg_pa, u64 vmm_tdisp_msg_pa)
{
	u64 ret;

	/*
	 * TDH.DEVIF.CREATE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - DEVIF_ID (tdx_devif_id)
	 * Input: RDX - TDR PA
	 * Input: R8 - DEVIFCS pa
	 * Input: R9 - TD_TDISP_MSG buffer pa
	 * Input: R10 - VMM_TDISP_MSG buffer pa
	 *
	 * Output: RAX - SEAMCALL return code
	 */
	ret = seamcall_retry(TDH_DEVIF_CREATE, devif_id, tdr_pa, devifcs_pa,
			     td_tdisp_msg_pa, vmm_tdisp_msg_pa,
			     0, NULL);

	pr_debug("%s: ret %llx, devif_id %llx tdr_pa %llx devifcs %llx, td_buf %llx vm_buf %llx\n",
		 __func__, ret, devif_id, tdr_pa, devifcs_pa,
		 td_tdisp_msg_pa, vmm_tdisp_msg_pa);

	return ret;
}

static inline u64 tdh_devif_remove(u32 func_id, struct tdx_module_args *out)
{
	u64 ret;

	/*
	 * TDH.DEVIF.REMOVE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - func_id
	 *
	 * Output: RAX - SEAMCALL return code
	 * Output: RCX - TD_TDISP_MSG buffer pa
	 * Output: RDX - VMM_TDISP_MSG buffer pa
	 */

	ret = seamcall_retry(TDH_DEVIF_REMOVE, func_id,
			     0, 0, 0, 0, 0, out);

	pr_debug("%s: ret %llx, func_id %x td_tdisp_buf %llx vmm_tdisp_buf %llx\n",
		 __func__, ret, func_id, out->rcx, out->rdx);

	return ret;
}

static inline u64 tdh_devif_request(u32 func_id, u64 payload, u64 req_out_pa,
				    struct tdx_module_args *out)
{
	u64 ret;

	/*
	 * TDH.DEVIF.REQUEST
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - func_id
	 * Input: RDX - payload parm (request)
	 * Input: R8  - pa target of TDISP request message output
	 *
	 * Output: RAX - SEAMCALL return code
	 * Output: RCX - message code of generated TDISP request message
	 */
	ret = seamcall_retry(TDH_DEVIF_REQUEST, func_id, payload,
			     req_out_pa, 0, 0, 0, out);

	pr_debug("%s: ret %llx, func_id %x payload %llx req_out_pa %llx msg_cde %llx\n",
		 __func__, ret, func_id, payload, req_out_pa, out->rcx);

	return ret;
}

static inline u64 tdh_devif_response(u32 func_id, u64 payload, u64 rsp_out_pa,
				     struct tdx_module_args *out)
{
	u64 ret;

	/*
	 * TDH.DEVIF.RESPONSE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - func_id
	 * Input: RDX - payload parm (response)
	 * Input: R8  - pa of TDISP response message output
	 *
	 * Output: RAX - SEAMCALL return code
	 * Output: RDX - TDISP payload size
	 */
	ret = seamcall_retry(TDH_DEVIF_RESPONSE, func_id, payload,
			     rsp_out_pa, 0, 0, 0, out);

	pr_debug("%s: ret %llx, func_id %x payload %llx rsp_out_pa %llx payload_size %llx\n",
		 __func__, ret, func_id, payload, rsp_out_pa, out->rdx);

	return ret;
}

/* tdxio related end */
#else
static inline u64 __seamcall(u64 fn, struct tdx_module_args *args) { return TDX_SEAMCALL_UD; }
static inline u64 __seamcall_ret(u64 fn, struct tdx_module_args *args) { return TDX_SEAMCALL_UD; }
static inline u64 __seamcall_saved(u64 fn, struct tdx_module_args *args) { return TDX_SEAMCALL_UD; }
static inline u64 __seamcall_saved_ret(u64 fn, struct tdx_module_args *args) { return TDX_SEAMCALL_UD; }

struct tdsysinfo_struct;
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void) { return NULL; }
static inline bool platform_tdx_enabled(void) { return false; }
static inline int tdx_enable(void)  { return -ENODEV; }
static inline void tdx_reset_memory(void) { }
static inline bool tdx_is_private_mem(unsigned long phys) { return false; }
static inline u32 tdx_get_nr_guest_keyids(void) { return 0; }
static inline int tdx_guest_keyid_alloc(void) { return -EOPNOTSUPP; }
static inline void tdx_guest_keyid_free(int keyid) { }
static inline int __init tdx_init(void) { return 0; }

/* tdxio related */
static inline bool tdx_io_support(void) { return false; }
static inline bool tdx_io_enabled(void) { return false; }
static inline u64 seamcall_retry(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			         u64 r10, u64 r11, u64 r12, u64 r13,
			         u64 r14, u64 r15,
			         struct tdx_module_args *out)
{
	return TDX_SEAMCALL_UD;
}
static inline u64 seamcall_retry_saved(u64 op, u64 rcx, u64 rdx, u64 r8,
				       u64 r9, u64 r10, u64 r11, u64 r12,
				       u64 r13, u64 r14, u64 r15,
				       struct tdx_module_args *out)
{
	return TDX_SEAMCALL_UD;
}
static inline void tdx_clear_page(unsigned long page_pa, int size) { }
static inline void tdx_set_page_present_level(unsigned long addr, enum pg_level pg_level) { }
static inline int __tdx_reclaim_page(unsigned long pa, enum pg_level level, bool do_wb,
				     u16 hkid) { return -EOPNOTSUPP; }
static inline int tdx_reclaim_page(unsigned long pa, bool do_wb,
				   u16 hkid) { return -EOPNOTSUPP; }
static inline void tdx_reclaim_td_page(unsigned long td_page_pa) { }
static inline u64 tdh_phymem_page_reclaim(u64 page,
					  struct tdx_module_args *out) { return -EOPNOTSUPP; }
static inline u64 tdh_phymem_page_wbinvd(u64 page) { return -EOPNOTSUPP; }
static inline u64 tdh_iommu_setreg(u64 iommu_id, u64 reg, u64 val) { return 0; }
static inline u64 tdh_iommu_getreg(u64 iommu_id, u64 reg, u64 *val) { return 0; }
static inline u64 tdh_spdm_create(u64 iommu_id, u64 spdm_session_idx,
				  u64 spdm_info_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_spdm_delete(u64 iommu_id, u64 spdm_session_idx,
				  u64 *spdm_info_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_ide_stream_create(u64 iommu_id,
					u64 spdm_session_idx,
					u64 stream_cfg_reg,
					u64 stream_ctrl_reg,
					u64 rid_assoc1_reg,
					u64 rid_assoc2_reg,
					u64 addr_assoc1_reg,
					u64 addr_assoc2_reg,
					u64 addr_assoc3_reg,
					u64 stream_exinfo_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_ide_stream_block(u64 iommu_id, u64 stream_id) { return -EOPNOTSUPP; }
static inline u64 tdh_ide_stream_delete(u64 iommu_id, u64 stream_id) { return -EOPNOTSUPP; }
static inline u64 tdh_ide_stream_idekmreq(u64 iommu_id,
					  u64 stream_id,
					  u64 object_id,
					  u64 ide_km_param,
					  u64 slot_id,
					  u64 message_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_ide_stream_idekmrsp(u64 iommu_id,
					  u64 stream_id,
					  u64 message_pa,
					  u64 *resp_data) { return -EOPNOTSUPP; }
static inline u64 tdh_mmiomt_add(u64 mmiomt_idx,
				 u64 mmiomt_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_mmiomt_set(u64 mmiomt_idx,
				 u64 mmiomt_info) { return -EOPNOTSUPP; }
static inline u64
tdh_mmiomt_read(u64 mmiomt_idx,
		struct tdx_module_args *out) { return -EOPNOTSUPP; }
static inline u64 tdh_mmiomt_remove(u64 mmiomt_idx) { return -EOPNOTSUPP; }
static inline u64 tdh_mmio_map(u64 gpa_page_info, u64 tdr_pa,
			       u64 mmio_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_mmio_block(u64 gpa_page_info,
				 u64 tdr_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_mmio_unmap(u64 gpa_page_info,
				 u64 tdr_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_dmar_add(u64 index, u64 tdr_pa, u64 entry0, u64 entry1,
			       u64 entry2, u64 entry3, u64 entry4, u64 entry5,
			       u64 entry6, u64 entry7) { return -EOPNOTSUPP; }
static inline u64 tdh_dmar_block(u64 index) { return -EOPNOTSUPP; }
static inline u64
tdh_dmar_read(u64 index, struct tdx_module_args *out) { return -EOPNOTSUPP; }
static inline u64 tdh_dmar_remove(u64 index) { return -EOPNOTSUPP; }
static inline u64 tdh_iqinv_req(u64 iommu_id, u64 inv_type, u64 inv_target,
				u64 wait_desc_1, u64 wait_desc_2,
				u64 wait_desc_3,
				u64 wait_desc_4) { return -EOPNOTSUPP; }
static inline u64 tdh_iqinv_process(u64 iommu_id) { return -EOPNOTSUPP; }
static inline u64
tdh_mem_shared_sept_wr(u64 gpa_info, u64 tdr_pa, u64 entry,
		       struct tdx_module_args *out) { return -EOPNOTSUPP; }
static inline u64 tdh_devifmt_add(u64 devifmt_idx,
				  u64 devifmt_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_devifmt_remove(u64 devifmt_idx) { return -EOPNOTSUPP; }
static inline u64
tdh_devifmt_read(u64 devifmt_idx,
		 struct tdx_module_args *out) { return -EOPNOTSUPP; }
static inline u64
tdh_devif_create(u64 devif_id, u64 tdr_pa, u64 devifcs_pa,
		 u64 td_tdisp_msg_pa,
		 u64 vmm_tdisp_msg_pa) { return -EOPNOTSUPP; }
static inline u64
tdh_devif_remove(u32 func_id,
		 struct tdx_module_args *out) { return -EOPNOTSUPP; }
static inline u64
tdh_devif_request(u32 func_id, u64 payload, u64 req_out_pa,
		  struct tdx_module_args *out) { return -EOPNOTSUPP; }
static inline u64
tdh_devif_response(u32 func_id, u64 payload, u64 rsp_out_pa,
		   struct tdx_module_args *out) { return -EOPNOTSUPP; }
/* tdxio related end */
#endif	/* CONFIG_INTEL_TDX_HOST */

struct notifier_block;
#ifdef CONFIG_INTEL_TDX_MODULE_UPDATE
int register_tdx_update_notifier(struct notifier_block *nb);
int unregister_tdx_update_notifier(struct notifier_block *nb);
#else /* !CONFIG_INTEL_TDX_MODULE_UPDATE */
static inline int register_tdx_update_notifier(struct notifier_block *nb)
{
	return 0;
}

static inline int unregister_tdx_update_notifier(struct notifier_block *nb)
{
	return 0;
}
#endif /* CONFIG_INTEL_TDX_MODULE_UPDATE */

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_TDX_H */

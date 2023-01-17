/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_VIRT_TDX_H
#define _X86_VIRT_TDX_H

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/compiler_attributes.h>

/*
 * This file contains both macros and data structures defined by the TDX
 * architecture and Linux defined software data structures and functions.
 * The two should not be mixed together for better readability.  The
 * architectural definitions come first.
 */

/* MSR to report KeyID partitioning between MKTME and TDX */
#define MSR_IA32_MKTME_KEYID_PARTITIONING	0x00000087

/*
 * TDX module SEAMCALL leaf functions
 */
#define TDH_SYS_KEY_CONFIG	31
#define TDH_SYS_INFO		32
#define TDH_SYS_RD		34
#define TDH_SYS_TDMR_INIT	36
#define TDH_SYS_CONFIG		45
#define TDH_SYS_INIT		33
#define TDH_SYS_LP_INIT		35
#define TDH_SYS_SHUTDOWN	52
#define TDH_SYS_UPDATE		53

/* P-SEAMLDR SEAMCALL leaf function */
#define P_SEAMLDR_SEAMCALL_BASE		BIT_ULL(63)
#define P_SEAMCALL_SEAMLDR_INFO		(P_SEAMLDR_SEAMCALL_BASE | 0x0)
#define P_SEAMCALL_SEAMLDR_INSTALL	(P_SEAMLDR_SEAMCALL_BASE | 0x1)

/* P-SEAMLDR SEAMCALL error codes */
#define P_SEAMCALL_NO_ENTROPY		0x8000000000030001

struct cmr_info {
	u64	base;
	u64	size;
} __packed;

#define MAX_CMRS			32
#define CMR_INFO_ARRAY_ALIGNMENT	512

#define DECLARE_PADDED_STRUCT(type, name, size, alignment)	\
	struct type##_padded {					\
		union {						\
			struct type name;			\
			u8 padding[size];			\
		};						\
	} name##_padded __aligned(alignment)

#define PADDED_STRUCT(name)	(name##_padded.name)

struct tdmr_reserved_area {
	u64 offset;
	u64 size;
} __packed;

#define TDMR_INFO_ALIGNMENT	512
#define TDMR_INFO_PA_ARRAY_ALIGNMENT	512

struct tdmr_info {
	u64 base;
	u64 size;
	u64 pamt_1g_base;
	u64 pamt_1g_size;
	u64 pamt_2m_base;
	u64 pamt_2m_size;
	u64 pamt_4k_base;
	u64 pamt_4k_size;
	/*
	 * Actual number of reserved areas depends on
	 * 'struct tdsysinfo_struct'::max_reserved_per_tdmr.
	 */
	DECLARE_FLEX_ARRAY(struct tdmr_reserved_area, reserved_areas);
} __packed __aligned(TDMR_INFO_ALIGNMENT);

/*
 * TDX module's signature structure, which provides metadata
 * information about the module.
 */
struct seam_sigstruct {
	u32		header_type;
	u32		header_length;
	u32		header_version;
	u32		module_type;
	u32		module_vendor;
	u32		date;
	u32		size;
	u32		key_size;
	u32		module_size;
	u32		exponent_size;
	u8		reserved[88];
	u8		modulus[384];
	u32		exponent;
	u8		signature[384];
	u8		seamhash[48];
	u16		seamsvn;
	u64		attributes;
	u32		rip_offset;
	u8		num_stack_pages;
	u8		num_tls_pages;
	u16		num_keyhole_pgs;
	u16		min_glb_data_pages;
	u16		max_tdmrs;
	u16		max_reserved_per_tdmr;
	u16		pamt_entry_size_4K;
	u16		pamt_entry_size_2M;
	u16		pamt_entry_size_1G;
	u8		reserved2[6];
	u16		module_hv;
	u16		min_update_hv;
	u8		no_downgrade;
	u8		reserved3;
	u16		num_handoff_pages;
	u8		reserved4[32];
	u32		cpuid_table_size;
	u8		cpuid_table[1020];
} __packed;

#define SEAMLDR_MAX_NR_MODULE_PAGES	496

#define SEAMLDR_SIGSTRUCT_SIZE		2048

#define SEAMLDR_SCENARIO_LOAD		0
#define SEAMLDR_SCENARIO_UPDATE		1

/* Passed to P-SEAMLDR to describe information about the TDX module to load */
struct seamldr_params {
	u32	version;
	u32	scenario; /* SEAMLDR_SCENARIO_LOAD/UPDATE */
	u64	sigstruct_pa;
	u8	reserved[104];
	u64	num_module_pages;
	u64	mod_pages_pa_list[SEAMLDR_MAX_NR_MODULE_PAGES];
} __packed;

struct tee_tcb_svn {
	u16	seamsvn;
	u8	reserved[14];
} __packed;

struct __tee_tcb_info {
	u64			valid;
	struct tee_tcb_svn	tcb_svn;
	u8			mrseam[48];
	u8			mrsignerseam[48];
	u64			attributes;
} __packed;

#define P_SEAMLDR_INFO_ALIGNMENT	256

struct p_seamldr_info {
	u32	version;
	u32	attributes;
	u32	vendor_id;
	u32	build_date;
	u16	build_num;
	u16	minor;
	u16	major;
	u8	reserved0[2];
	u32	acm_x2apicid;
	u32	num_remaining_updates;
	struct __tee_tcb_info tcb_info;
	u8	seam_ready;
	u8	seam_debug;
	u8	p_seamldr_ready;
	u8	reserved2[88];
} __packed __aligned(P_SEAMLDR_INFO_ALIGNMENT);

/*
 * TDX module metadata identifiers
 */
#define TDX_MD_FEATURES0		0x0A00000300000008
#define		TDX_FEATURES0_TD_PRES	BIT(1)
#define TDX_MD_MODULE_HV		0x8900000100000000
#define TDX_MD_MIN_UPDATE_HV		0x8900000100000001
#define TDX_MD_NO_DOWNGRADE		0x8900000000000002

/*
 * Do not put any hardware-defined TDX structure representations below
 * this comment!
 */

struct tdx_module_output;
u64 __seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10, u64 r11,
	       u64 r12, u64 r13, struct tdx_module_output *out);
#endif

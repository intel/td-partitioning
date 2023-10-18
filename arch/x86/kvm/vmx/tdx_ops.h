/* SPDX-License-Identifier: GPL-2.0 */
/* constants/data definitions for TDX SEAMCALLs */

#ifndef __KVM_X86_TDX_OPS_H
#define __KVM_X86_TDX_OPS_H

#include <linux/compiler.h>

#include <asm/pgtable_types.h>
#include <asm/archrandom.h>
#include <asm/cacheflush.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>
#include <asm/asm.h>
#include <asm/kvm_host.h>
#include <asm/tdx.h>

#include "tdx_errno.h"
#include "tdx_arch.h"
#include "x86.h"

static inline u64 __tdx_seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			         u64 r10, u64 r11, u64 r12, u64 r13, u64 r14,
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
				ret = __seamcall_saved_ret(op, out);
			} else {
				ret = __seamcall_ret(op, out);
			}
		} else {
			/*
			 * Currently, all the APIs that use non-volatile
			 * registers are required to provide @out.
			 */
			WARN_ON_ONCE(need_saved);
			struct tdx_module_args args = {
				.rcx = rcx,
				.rdx = rdx,
				.r8 = r8,
				.r9 = r9,
				.r10 = r10,
				.r11 = r11,
			};
			ret = __seamcall(op, &args);
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
			kvm_spurious_fault();
			return 0;
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

static inline u64 tdx_seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			       u64 r10, u64 r11, struct tdx_module_args *out)
{
	return __tdx_seamcall(op, rcx, rdx, r8, r9, r10, r11, 0, 0, 0, out,
			      false);
}

static inline u64 tdx_seamcall_saved(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
				     u64 r10, u64 r11, u64 r12, u64 r13, u64 r14,
				     struct tdx_module_args *out)
{
	return __tdx_seamcall(op, rcx, rdx, r8, r9, r10, r11, r12, r13, r14,
			      out, true);
}

#ifdef CONFIG_INTEL_TDX_HOST
void pr_tdx_error(u64 op, u64 error_code, const struct tdx_module_args *out);
#endif

static inline enum pg_level tdx_sept_level_to_pg_level(int tdx_level)
{
	return tdx_level + 1;
}

static inline void tdx_clflush_page(hpa_t addr, enum pg_level level)
{
	clflush_cache_range(__va(addr), KVM_HPAGE_SIZE(level));
}

static inline void tdx_set_page_np(hpa_t addr)
{
	if (!IS_ENABLED(CONFIG_INTEL_TDX_HOST_DEBUG_MEMORY_CORRUPT))
		return;

	/* set_page_np() doesn't work due to non-preemptive context. */
	set_direct_map_invalid_noflush(pfn_to_page(addr >> PAGE_SHIFT));
	preempt_disable();
	__flush_tlb_all();
	preempt_enable();
	arch_flush_lazy_mmu_mode();
}

static inline void tdx_set_page_np_level(hpa_t addr, int tdx_level)
{
	enum pg_level pg_level = tdx_sept_level_to_pg_level(tdx_level);
	int i;

	if (!IS_ENABLED(CONFIG_INTEL_TDX_HOST_DEBUG_MEMORY_CORRUPT))
		return;

	for (i = 0; i < KVM_PAGES_PER_HPAGE(pg_level); i++)
		set_direct_map_invalid_noflush(pfn_to_page((addr >> PAGE_SHIFT) + i));
	preempt_disable();
	__flush_tlb_all();
	preempt_enable();
	arch_flush_lazy_mmu_mode();
}

static inline void tdx_set_page_present(hpa_t addr)
{
	if (IS_ENABLED(CONFIG_INTEL_TDX_HOST_DEBUG_MEMORY_CORRUPT))
		set_direct_map_default_noflush(pfn_to_page(addr >> PAGE_SHIFT));
}

static inline int tdx_vm_index_to_index(enum tdx_vm_index vm_index)
{
	return vm_index - TDX_L2TD_1;
}

static inline u64 *tdx_module_output_for_vm(struct tdx_module_args *out,
					    enum tdx_vm_index vm_index)
{
	/*
	 * Out.R8 contains the correponding HPA information for
	 * L1 VM, and Out.R9/R10/R11 contains the corresponding
	 * HPA information of L2 VM#1/VM#2/VM#3.
	 */
	switch (vm_index) {
	case TDX_L1TD:
		return &out->r8;
	case TDX_L2TD_1:
		return &out->r9;
	case TDX_L2TD_2:
		return &out->r10;
	case TDX_L2TD_3:
		return &out->r11;
	default:
		break;
	}

	return NULL;
}

static inline u64 tdh_mng_addcx(hpa_t tdr, hpa_t addr)
{
	u64 r;

	tdx_clflush_page(addr, PG_LEVEL_4K);
	r = tdx_seamcall(TDH_MNG_ADDCX, addr, tdr, 0, 0, 0, 0, NULL);
	if (!r)
		tdx_set_page_np(addr);
	return r;
}

static inline u64 tdh_mem_page_add(hpa_t tdr, gpa_t gpa, int level, hpa_t hpa,
				   hpa_t source, struct tdx_module_args *out)
{
	u64 r;

	tdx_clflush_page(hpa, tdx_sept_level_to_pg_level(level));
	r = tdx_seamcall(TDH_MEM_PAGE_ADD, gpa | level, tdr, hpa, source, 0, 0,
			 out);
	if (!r)
		tdx_set_page_np_level(hpa, level);
	return r;
}

#define TDX_SEAMCALL_VER_SHIFT			16
#define TDX_SEAMCALL_V0				0
#define TDX_SEAMCALL_V1				1

#define SEPT_ADD_ALLOW_EXISTING			1
#define SEPT_ADD_EXISTING_MASK			BIT(63)

static inline u64 tdh_mem_sept_add(u8 version, hpa_t tdr, gpa_t gpa, int level, hpa_t l1sept_page,
				   hpa_t l2sept1_page, hpa_t l2sept2_page, hpa_t l2sept3_page,
				   struct tdx_module_args *out)
{
	hpa_t pages[TDX_MAX_L2_VMS] = {l2sept1_page, l2sept2_page, l2sept3_page};
	gpa_t aligned_gpa = gpa & KVM_HPAGE_MASK(tdx_sept_level_to_pg_level(level));
	u64 r;
	int i;

	BUILD_BUG_ON(TDX_MAX_L2_VMS != 3);

	if (VALID_PAGE(l1sept_page))
		tdx_clflush_page(l1sept_page, PG_LEVEL_4K);

	switch (version) {
	case TDX_SEAMCALL_V0:
		/* For version 0, only l1sept will be added */
		for (i = 0; i < TDX_MAX_L2_VMS; i++)
			WARN_ON(pages[i] && VALID_PAGE(pages[i]));
		break;
	case TDX_SEAMCALL_V1:
		/* For version 1, paging page can be added to either l2septx */
		for (i = 0; i < TDX_MAX_L2_VMS; i++) {
			if (VALID_PAGE(pages[i]))
				tdx_clflush_page(pages[i], PG_LEVEL_4K);
		}
		break;
	default:
		return -EINVAL;
	}

	r = tdx_seamcall((version << TDX_SEAMCALL_VER_SHIFT) | TDH_MEM_SEPT_ADD,
			 aligned_gpa | level, tdr, l1sept_page, l2sept1_page,
			 l2sept2_page, l2sept3_page, out);
	if (!r) {
		if (VALID_PAGE(l1sept_page))
			tdx_set_page_np(l1sept_page);

		if (version == TDX_SEAMCALL_V1) {
			for (i = 0; i < TDX_MAX_L2_VMS; i++) {
				if (VALID_PAGE(pages[i]))
					tdx_set_page_np(pages[i]);
			}
		}
	}

	return r;
}

static inline u64 tdh_mem_sept_add_v0(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
				      struct tdx_module_args *out)
{
	return tdh_mem_sept_add(TDX_SEAMCALL_V0, tdr, gpa, level, page, 0, 0, 0, out);
}

static inline u64 tdh_mem_sept_add_v1(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
				      hpa_t page_1, hpa_t page_2, hpa_t page_3,
				      struct tdx_module_args *out)
{
	return tdh_mem_sept_add(TDX_SEAMCALL_V1, tdr | SEPT_ADD_ALLOW_EXISTING,
				gpa, level, page, page_1, page_2, page_3, out);
}

static inline u64 tdh_mem_sept_rd(hpa_t tdr, gpa_t gpa, int level,
				  struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_MEM_SEPT_RD, gpa | level, tdr, 0, 0, 0, 0,
			    out);
}


static inline u64 tdh_mem_sept_remove(u8 version, hpa_t tdr, gpa_t gpa, int level,
				      struct tdx_module_args *out)
{
	return tdx_seamcall((version << TDX_SEAMCALL_VER_SHIFT) | TDH_MEM_SEPT_REMOVE,
				   gpa | level, tdr, 0, 0, 0, 0, out);
}

static inline u64 tdh_mem_sept_remove_v0(hpa_t tdr, gpa_t gpa, int level,
					 struct tdx_module_args *out)
{
	return tdh_mem_sept_remove(TDX_SEAMCALL_V0, tdr, gpa, level, out);
}

static inline u64 tdh_mem_sept_remove_v1(hpa_t tdr, gpa_t gpa, int level,
					 struct tdx_module_args *out)
{
	return tdh_mem_sept_remove(TDX_SEAMCALL_V1, tdr, gpa, level, out);
}

static inline u64 tdh_vp_addcx(hpa_t tdvpr, hpa_t addr)
{
	u64 r;

	tdx_clflush_page(addr, PG_LEVEL_4K);
	r = tdx_seamcall(TDH_VP_ADDCX, addr, tdvpr, 0, 0, 0, 0, NULL);
	if (!r)
		tdx_set_page_np(addr);
	return r;
}

static inline u64 tdh_mem_page_relocate(hpa_t tdr, gpa_t gpa, hpa_t hpa,
					struct tdx_module_args *out)
{
	tdx_clflush_page(hpa, PG_LEVEL_4K);
	return tdx_seamcall(TDH_MEM_PAGE_RELOCATE, gpa, tdr, hpa, 0, 0, 0,
			    out);
}

static inline u64 tdh_mem_page_aug(hpa_t tdr, gpa_t gpa, int level, hpa_t hpa,
				   struct tdx_module_args *out)
{
	u64 r;

	tdx_clflush_page(hpa, tdx_sept_level_to_pg_level(level));
	r = tdx_seamcall(TDH_MEM_PAGE_AUG, gpa | level, tdr, hpa, 0, 0, 0,
			 out);
	if (!r)
		tdx_set_page_np_level(hpa, level);
	return r;
}

static inline u64 tdh_mem_range_block(hpa_t tdr, gpa_t gpa, int level,
				      struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_MEM_RANGE_BLOCK, gpa | level, tdr, 0, 0, 0, 0,
			    out);
}

static inline u64 tdh_mng_key_config(hpa_t tdr)
{
	return tdx_seamcall(TDH_MNG_KEY_CONFIG, tdr, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_create(hpa_t tdr, int hkid)
{
	u64 r;

	tdx_clflush_page(tdr, PG_LEVEL_4K);
	r = tdx_seamcall(TDH_MNG_CREATE, tdr, hkid, 0, 0, 0, 0, NULL);
	if (!r)
		tdx_set_page_np(tdr);
	return r;
}

static inline u64 tdh_vp_create(hpa_t tdr, hpa_t tdvpr)
{
	u64 r;

	tdx_clflush_page(tdvpr, PG_LEVEL_4K);
	r = tdx_seamcall(TDH_VP_CREATE, tdvpr, tdr, 0, 0, 0, 0, NULL);
	if (!r)
		tdx_set_page_np(tdvpr);
	return r;
}

static inline u64 tdh_mem_rd(hpa_t tdr, gpa_t addr, struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_MEM_RD, addr, tdr, 0, 0, 0, 0, out);
}

static inline u64 tdh_mem_wr(hpa_t tdr, hpa_t addr, u64 val, struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_MEM_WR, addr, tdr, val, 0, 0, 0, out);
}

static inline u64 tdh_mng_rd(hpa_t tdr, u64 field, struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_MNG_RD, tdr, field, 0, 0, 0, 0, out);
}

static inline u64 tdh_mng_wr(hpa_t tdr, u64 field, u64 data, u64 mask, struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_MNG_WR, tdr, field, data, mask, 0, 0, out);
}

static inline u64 tdh_mem_page_demote(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
				      struct tdx_module_args *out)
{
	u64 r;

	tdx_clflush_page(page, PG_LEVEL_4K);
	r = tdx_seamcall(TDH_MEM_PAGE_DEMOTE, gpa | level, tdr, page, 0, 0, 0,
			 out);
	if (!r)
		tdx_set_page_np(page);
	return r;
}

static inline u64 tdh_mem_page_promote(hpa_t tdr, gpa_t gpa, int level,
				       struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_MEM_PAGE_PROMOTE, gpa | level, tdr, 0, 0, 0, 0,
			    out);
}

#define DEMOTE_ADD_ON_ALIAS			1
#define DEMOTE_L2SEPT_HPA_CONSUMED		BIT(63)
static inline u64 tdh_mem_page_demote_with_tdpart(hpa_t tdr, gpa_t gpa, int level,
						  hpa_t l1sept_page, hpa_t l2sept1_page,
						  hpa_t l2sept2_page, hpa_t l2sept3_page,
						  struct tdx_module_args *out)
{
	hpa_t pages[TDX_MAX_L2_VMS] = {l2sept1_page, l2sept2_page, l2sept3_page};
	int i;
	u64 r;

	tdx_clflush_page(l1sept_page, PG_LEVEL_4K);
	for (i = 0; i < TDX_MAX_L2_VMS; i++) {
		if (VALID_PAGE(pages[i]))
			tdx_clflush_page(pages[i], PG_LEVEL_4K);
	}

	r = tdx_seamcall(TDH_MEM_PAGE_DEMOTE, gpa | level, tdr | DEMOTE_ADD_ON_ALIAS,
			 l1sept_page, l2sept1_page, l2sept2_page, l2sept3_page, out);
	if (r)
		return r;

	tdx_set_page_np(l1sept_page);

	for (i = 0; i < TDX_MAX_L2_VMS; i++) {
		if (VALID_PAGE(pages[i]))
			tdx_set_page_np(pages[i]);
	}

	return 0;
}

static inline bool tdh_mem_page_demote_consumed(hpa_t in_hpa, hpa_t out_hpa)
{
	return !(out_hpa & DEMOTE_L2SEPT_HPA_CONSUMED) && (in_hpa == out_hpa);
}

static inline u64 tdh_mr_extend(hpa_t tdr, gpa_t gpa,
				struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_MR_EXTEND, gpa, tdr, 0, 0, 0, 0, out);
}

static inline u64 tdh_mr_finalize(hpa_t tdr)
{
	return tdx_seamcall(TDH_MR_FINALIZE, tdr, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_vp_flush(hpa_t tdvpr)
{
	return tdx_seamcall(TDH_VP_FLUSH, tdvpr, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_vpflushdone(hpa_t tdr)
{
	return tdx_seamcall(TDH_MNG_VPFLUSHDONE, tdr, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_key_freeid(hpa_t tdr)
{
	return tdx_seamcall(TDH_MNG_KEY_FREEID, tdr, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_init(hpa_t tdr, hpa_t td_params,
			       struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_MNG_INIT, tdr, td_params, 0, 0, 0, 0, out);
}

static inline u64 tdh_vp_init(hpa_t tdvpr, u64 rcx)
{
	return tdx_seamcall(TDH_VP_INIT, tdvpr, rcx, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_vp_rd(hpa_t tdvpr, u64 field,
			    struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_VP_RD, tdvpr, field, 0, 0, 0, 0, out);
}

static inline u64 tdh_mng_key_reclaimid(hpa_t tdr)
{
	return tdx_seamcall(TDH_MNG_KEY_RECLAIMID, tdr, 0, 0, 0, 0, 0, NULL);
}

#if 0
static inline u64 tdh_phymem_page_reclaim(hpa_t page,
					  struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_PHYMEM_PAGE_RECLAIM, page, 0, 0, 0, 0, 0, out);
}
#endif

static inline u64 tdh_mem_page_remove(hpa_t tdr, gpa_t gpa, int level,
				      struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_MEM_PAGE_REMOVE, gpa | level, tdr, 0, 0, 0, 0,
			    out);
}

static inline u64 tdh_sys_lp_shutdown(void)
{
	return tdx_seamcall(TDH_SYS_LP_SHUTDOWN, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_track(hpa_t tdr)
{
	return tdx_seamcall(TDH_MEM_TRACK, tdr, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_range_unblock(hpa_t tdr, gpa_t gpa, int level,
					struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_MEM_RANGE_UNBLOCK, gpa | level, tdr, 0, 0, 0,
			    0, out);
}

static inline u64 tdh_phymem_cache_wb(bool resume)
{
	return tdx_seamcall(TDH_PHYMEM_CACHE_WB, resume ? 1 : 0, 0, 0, 0, 0, 0,
			    NULL);
}

#if 0
static inline u64 tdh_phymem_page_wbinvd(hpa_t page)
{
	return tdx_seamcall(TDH_PHYMEM_PAGE_WBINVD, page, 0, 0, 0, 0, 0, NULL);
}
#endif

static inline u64 tdh_vp_wr(hpa_t tdvpr, u64 field, u64 val, u64 mask,
			    struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_VP_WR, tdvpr, field, val, mask, 0, 0, out);
}

static inline u64 tdh_sys_rd(u64 field, struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_SYS_RD, 0, field, 0, 0, 0, 0, out);
}

static inline u64 tdh_servtd_prebind(hpa_t target_tdr,
				     hpa_t hash_addr,
				     u64 slot_idx,
				     u64 attr,
				     enum kvm_tdx_servtd_type type)
{
	return tdx_seamcall(TDH_SERVTD_PREBIND, target_tdr,
			    hash_addr, slot_idx, type, attr, 0, NULL);
}

static inline u64 tdh_servtd_bind(hpa_t servtd_tdr,
				  hpa_t target_tdr,
				  u64 slot_idx,
				  u64 attr,
				  enum kvm_tdx_servtd_type type,
				  struct tdx_module_args *out)
{
	return tdx_seamcall_saved(TDH_SERVTD_BIND, target_tdr, servtd_tdr,
				  slot_idx, type, attr, 0, 0, 0, 0, out);
}

static inline u64 tdh_mig_stream_create(hpa_t tdr, hpa_t migsc)
{
	return tdx_seamcall(TDH_MIG_STREAM_CREATE, migsc, tdr, 0, 0, 0, 0,
			    NULL);
}

static inline u64 tdh_export_blockw(hpa_t tdr,
				    u64 gpa_list_info,
				    struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_EXPORT_BLOCKW, gpa_list_info, tdr,
			    0, 0, 0, 0, out);
}

static inline u64 tdh_export_unblockw(hpa_t tdr,
				      u64 ept_info,
				      struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_EXPORT_UNBLOCKW, ept_info, tdr, 0, 0, 0, 0,
			    out);
}

static inline u64 tdh_export_state_immutable(hpa_t tdr,
					     u64 mbmd_info,
					     u64 page_list_info,
					     u64 mig_stream_info,
					     struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_EXPORT_STATE_IMMUTABLE, tdr, 0, mbmd_info,
			    page_list_info, mig_stream_info, 0, out);
}

static inline u64 tdh_import_state_immutable(hpa_t tdr,
					     u64 mbmd_info,
					     u64 buf_list_info,
					     u64 mig_stream_info,
					     struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_IMPORT_STATE_IMMUTABLE, tdr, 0, mbmd_info,
			    buf_list_info, mig_stream_info, 0, out);
}

static inline u64 tdh_export_mem(hpa_t tdr,
				 u64 mbmd_info,
				 u64 gpa_list_info,
				 u64 buf_list_info,
				 u64 mac_list0_info,
				 u64 mac_list1_info,
				 u64 mig_stream_info,
				 struct tdx_module_args *out)

{
	return tdx_seamcall_saved(TDH_EXPORT_MEM, gpa_list_info, tdr,
				  mbmd_info, buf_list_info, mig_stream_info,
				  mac_list0_info, mac_list1_info, 0, 0, out);
}

static inline u64 tdh_import_mem(hpa_t tdr,
				 u64 mbmd_info,
				 u64 gpa_list_info,
				 u64 buf_list_info,
				 u64 mac_list0_info,
				 u64 mac_list1_info,
				 u64 td_page_list_info,
				 u64 mig_stream_info,
				 struct tdx_module_args *out)
{
	return tdx_seamcall_saved(TDH_IMPORT_MEM, gpa_list_info, tdr,
				  mbmd_info, buf_list_info, mig_stream_info,
				  mac_list0_info, mac_list1_info,
				  td_page_list_info, 0, out);
}

static inline u64 tdh_export_track(hpa_t tdr,
				   u64 mbmd_info,
				   u64 mig_stream_info)
{
	return tdx_seamcall(TDH_EXPORT_TRACK, tdr, 0, mbmd_info, 0,
			    mig_stream_info, 0, NULL);
}

static inline u64 tdh_import_track(hpa_t tdr,
				    u64 mbmd_info,
				    u64 mig_stream_info)
{
	return tdx_seamcall(TDH_IMPORT_TRACK, tdr, 0, mbmd_info, 0,
			    mig_stream_info, 0, NULL);
}

static inline u64 tdh_import_commit(hpa_t tdr)
{
	return tdx_seamcall(TDH_IMPORT_COMMIT, tdr, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_export_pasue(hpa_t tdr)
{
	return tdx_seamcall(TDH_EXPORT_PAUSE, tdr, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_export_state_td(hpa_t tdr,
				      u64 mbmd_info,
				      u64 buf_list_info,
				      u64 mig_stream_info,
				      struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_EXPORT_STATE_TD, tdr, 0, mbmd_info,
			    buf_list_info, mig_stream_info, 0, out);
}

static inline u64 tdh_import_state_td(hpa_t tdr,
				      u64 mbmd_info,
				      u64 buf_list_info,
				      u64 mig_stream_info,
				      struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_IMPORT_STATE_TD, tdr, 0, mbmd_info,
			    buf_list_info, mig_stream_info, 0, out);
}

static inline u64 tdh_export_state_vp(hpa_t tdvpr,
				      u64 mbmd_info,
				      u64 buf_list_info,
				      u64 mig_stream_info,
				      struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_EXPORT_STATE_VP, tdvpr, 0, mbmd_info,
			    buf_list_info, mig_stream_info, 0, out);
}

static inline u64 tdh_import_state_vp(hpa_t tdvpr,
				      u64 mbmd_info,
				      u64 buf_list_info,
				      u64 mig_stream_info,
				      struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_IMPORT_STATE_VP, tdvpr, 0, mbmd_info,
			    buf_list_info, mig_stream_info, 0, out);
}

static inline u64 tdh_export_abort(hpa_t tdr,
				   u64 mbmd_info,
				   u64 mig_stream_info)
{
	return tdx_seamcall(TDH_EXPORT_ABORT, tdr, 0, mbmd_info,
			    0, mig_stream_info, 0, NULL);
}

static inline u64 tdh_export_restore(hpa_t tdr,
				     u64 gpa_list_info,
				     struct tdx_module_args *out)
{
	return tdx_seamcall(TDH_EXPORT_RESTORE, gpa_list_info, tdr, 0, 0, 0, 0,
			    out);
}

static inline u64 tdh_import_end(hpa_t tdr)
{
	return tdx_seamcall(TDH_IMPORT_END, tdr, 0, 0, 0, 0, 0, NULL);
}

static __always_inline void tdvps_vmcs_check(u32 field, u8 bits)
{
#define VMCS_ENC_ACCESS_TYPE_MASK	0x1UL
#define VMCS_ENC_ACCESS_TYPE_FULL	0x0UL
#define VMCS_ENC_ACCESS_TYPE_HIGH	0x1UL
#define VMCS_ENC_ACCESS_TYPE(field)	((field) & VMCS_ENC_ACCESS_TYPE_MASK)

	/* TDX is 64bit only.  HIGH field isn't supported. */
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
			 VMCS_ENC_ACCESS_TYPE(field) == VMCS_ENC_ACCESS_TYPE_HIGH,
			 "Read/Write to TD VMCS *_HIGH fields not supported");

	BUILD_BUG_ON(bits != 16 && bits != 32 && bits != 64);

#define VMCS_ENC_WIDTH_MASK	GENMASK(14, 13)
#define VMCS_ENC_WIDTH_16BIT	(0UL << 13)
#define VMCS_ENC_WIDTH_64BIT	(1UL << 13)
#define VMCS_ENC_WIDTH_32BIT	(2UL << 13)
#define VMCS_ENC_WIDTH_NATURAL	(3UL << 13)
#define VMCS_ENC_WIDTH(field)	((field) & VMCS_ENC_WIDTH_MASK)

	/* TDX is 64bit only.  i.e. natural width = 64bit. */
	BUILD_BUG_ON_MSG(bits != 64 && __builtin_constant_p(field) &&
			 (VMCS_ENC_WIDTH(field) == VMCS_ENC_WIDTH_64BIT ||
			  VMCS_ENC_WIDTH(field) == VMCS_ENC_WIDTH_NATURAL),
			 "Invalid TD VMCS access for 64-bit field");
	BUILD_BUG_ON_MSG(bits != 32 && __builtin_constant_p(field) &&
			 VMCS_ENC_WIDTH(field) == VMCS_ENC_WIDTH_32BIT,
			 "Invalid TD VMCS access for 32-bit field");
	BUILD_BUG_ON_MSG(bits != 16 && __builtin_constant_p(field) &&
			 VMCS_ENC_WIDTH(field) == VMCS_ENC_WIDTH_16BIT,
			 "Invalid TD VMCS access for 16-bit field");
}

static __always_inline void tdvps_gpr_check(u64 field, u8 bits)
{
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) && (field) >= NR_VCPU_REGS,
			 "Invalid TDX Guest GPR index");
}

#endif /* __KVM_X86_TDX_OPS_H */

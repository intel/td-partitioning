// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019-2022 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/sched/task.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/vfio.h>
#include <linux/msi.h>
#include <linux/iommu.h>
#include <linux/kvm_host.h>
#include <linux/eventfd.h>
#include <linux/sched/mm.h>
#include <uapi/linux/idxd.h>
#include "registers.h"
#include "idxd.h"
#include "vidxd.h"

static u64 idxd_pci_config[] = {
	0x0010000000008086ULL,
	0x0080000008800000ULL,
	0x000000000000000cULL,
	0x000000000000000cULL,
	0x0000000000000000ULL,
	0x2010808600000000ULL,
	0x0000004000000000ULL,
	0x000000ff00000000ULL,
	0x0000060000015011ULL, /* MSI-X capability, hardcoded 2 entries, Encoded as N-1 */
	0x0000070000000000ULL,
	0x0000000000920010ULL, /* PCIe capability */
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0070001000000000ULL, /* point to the extended region. */
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
};

static u64 idxd_pci_ext_cap[] = {
	0x000000611101000fULL, /* ATS capability */
	0x0000000000000000ULL,
	0x8100000012010013ULL, /* Page Request capability */
	0x0000000000000001ULL,
	0x000014040001001bULL, /* PASID capability */
	0x0000000000000000ULL,
	0x0181808600010023ULL, /* Scalable IOV capability */
	0x0000000100000005ULL,
	0x0000000000000001ULL,
	0x0000000000000000ULL,
};

static void vidxd_mmio_init_grpcap(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	union group_cap_reg *grp_cap = (union group_cap_reg *)(bar0 + IDXD_GRPCAP_OFFSET);

	/* single group for current implementation */
	grp_cap->num_groups = 1;
}

static void vidxd_mmio_init_grpcfg(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	struct grpcfg *grpcfg = (struct grpcfg *)(bar0 + VIDXD_GRPCFG_OFFSET);
	struct idxd_wq *wq = vidxd->wq;
	struct idxd_group *group = wq->group;
	int i;

	/*
	 * At this point, we are only exporting a single workqueue for
	 * each vdev.
	 */
	grpcfg->wqs[0] = BIT(0);
	for (i = 0; i < group->num_engines; i++)
		grpcfg->engines |= BIT(i);
	grpcfg->flags.bits = group->grpcfg.flags.bits;
}

static void vidxd_mmio_init_wqcap(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	struct idxd_wq *wq = vidxd->wq;
	union wq_cap_reg *wq_cap = (union wq_cap_reg *)(bar0 + IDXD_WQCAP_OFFSET);

	wq_cap->occupancy_int = 0;
	wq_cap->occupancy = 0;
	wq_cap->priority = 0;
	wq_cap->total_wq_size = wq->size;
	wq_cap->num_wqs = VIDXD_MAX_WQS;
	wq_cap->wq_ats_support = 0;
	wq_cap->dedicated_mode = 1;
}

static void vidxd_mmio_init_wqcfg(struct vdcm_idxd *vidxd)
{
	struct idxd_wq *wq = vidxd->wq;
	u8 *bar0 = vidxd->bar0;
	union wqcfg *wqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);

	wqcfg->wq_size = wq->size;
	wqcfg->wq_thresh = wq->threshold;

	wqcfg->mode = WQCFG_MODE_DEDICATED;

	wqcfg->bof = wq->wqcfg->bof;

	wqcfg->priority = wq->priority;
	wqcfg->max_xfer_shift = ilog2(wq->max_xfer_bytes);
	wqcfg->max_batch_shift = ilog2(wq->max_batch_size);

	wqcfg->mode_support = 1;
}

static void vidxd_mmio_init_engcap(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	union engine_cap_reg *engcap = (union engine_cap_reg *)(bar0 + IDXD_ENGCAP_OFFSET);
	struct idxd_wq *wq = vidxd->wq;
	struct idxd_group *group = wq->group;

	engcap->num_engines = group->num_engines;
}

static void vidxd_mmio_init_gencap(struct vdcm_idxd *vidxd)
{
	struct idxd_device *idxd = vidxd->idxd;
	u8 *bar0 = vidxd->bar0;
	union gen_cap_reg *gencap = (union gen_cap_reg *)(bar0 + IDXD_GENCAP_OFFSET);

	gencap->overlap_copy = idxd->hw.gen_cap.overlap_copy;
	gencap->cache_control_mem = idxd->hw.gen_cap.cache_control_mem;
	gencap->cache_control_cache = idxd->hw.gen_cap.cache_control_cache;
	gencap->cmd_cap = 1;
	gencap->dest_readback = idxd->hw.gen_cap.dest_readback;
	gencap->drain_readback = idxd->hw.gen_cap.drain_readback;
	gencap->max_xfer_shift = idxd->hw.gen_cap.max_xfer_shift;
	gencap->max_batch_shift = idxd->hw.gen_cap.max_batch_shift;
	if (device_user_pasid_enabled(idxd))
		gencap->block_on_fault = idxd->hw.gen_cap.block_on_fault;
}

static void vidxd_mmio_init_cmdcap(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	u32 *cmdcap = (u32 *)(bar0 + IDXD_CMDCAP_OFFSET);

	*cmdcap |= BIT(IDXD_CMD_ENABLE_DEVICE) | BIT(IDXD_CMD_DISABLE_DEVICE) |
		   BIT(IDXD_CMD_DRAIN_ALL) | BIT(IDXD_CMD_ABORT_ALL) |
		   BIT(IDXD_CMD_RESET_DEVICE) | BIT(IDXD_CMD_ENABLE_WQ) |
		   BIT(IDXD_CMD_DISABLE_WQ) | BIT(IDXD_CMD_DRAIN_WQ) |
		   BIT(IDXD_CMD_ABORT_WQ) | BIT(IDXD_CMD_RESET_WQ) |
		   BIT(IDXD_CMD_DRAIN_PASID) | BIT(IDXD_CMD_ABORT_PASID) |
		   BIT(IDXD_CMD_REQUEST_INT_HANDLE) | BIT(IDXD_CMD_RELEASE_INT_HANDLE);
}

static void vidxd_mmio_init_opcap(struct vdcm_idxd *vidxd)
{
	struct idxd_device *idxd = vidxd->idxd;
	u64 opcode;
	u8 *bar0 = vidxd->bar0;
	u64 *opcap = (u64 *)(bar0 + IDXD_OPCAP_OFFSET);

	if (idxd->data->type == IDXD_TYPE_DSA) {
		opcode = BIT_ULL(DSA_OPCODE_NOOP) | BIT_ULL(DSA_OPCODE_BATCH) |
			 BIT_ULL(DSA_OPCODE_DRAIN) | BIT_ULL(DSA_OPCODE_MEMMOVE) |
			 BIT_ULL(DSA_OPCODE_MEMFILL) | BIT_ULL(DSA_OPCODE_COMPARE) |
			 BIT_ULL(DSA_OPCODE_COMPVAL) | BIT_ULL(DSA_OPCODE_CR_DELTA) |
			 BIT_ULL(DSA_OPCODE_AP_DELTA) | BIT_ULL(DSA_OPCODE_DUALCAST) |
			 BIT_ULL(DSA_OPCODE_CRCGEN) | BIT_ULL(DSA_OPCODE_COPY_CRC) |
			 BIT_ULL(DSA_OPCODE_DIF_CHECK) | BIT_ULL(DSA_OPCODE_DIF_INS) |
			 BIT_ULL(DSA_OPCODE_DIF_STRP) | BIT_ULL(DSA_OPCODE_DIF_UPDT) |
			 BIT_ULL(DSA_OPCODE_CFLUSH);
		*opcap = opcode;
	} else if (idxd->data->type == IDXD_TYPE_IAX) {
		opcode = BIT_ULL(IAX_OPCODE_NOOP) | BIT_ULL(IAX_OPCODE_DRAIN) |
			 BIT_ULL(IAX_OPCODE_MEMMOVE);
		*opcap = opcode;
		opcap++;
		opcode = OPCAP_BIT(IAX_OPCODE_DECOMPRESS) |
			 OPCAP_BIT(IAX_OPCODE_COMPRESS);
		*opcap = opcode;
	}
}

static void vidxd_mmio_init_version(struct vdcm_idxd *vidxd)
{
	struct idxd_device *idxd = vidxd->idxd;
	u32 *version;

	version = (u32 *)(vidxd->bar0 + VIDXD_VERSION_OFFSET);
	*version = idxd->hw.version;
}

void vidxd_mmio_init(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	union offsets_reg *offsets;

	memset(vidxd->bar0, 0, VIDXD_BAR0_SIZE);

	vidxd_mmio_init_version(vidxd);
	vidxd_mmio_init_gencap(vidxd);
	vidxd_mmio_init_wqcap(vidxd);
	vidxd_mmio_init_grpcap(vidxd);
	vidxd_mmio_init_engcap(vidxd);
	vidxd_mmio_init_opcap(vidxd);

	offsets = (union offsets_reg *)(bar0 + IDXD_TABLE_OFFSET);
	offsets->grpcfg = VIDXD_GRPCFG_OFFSET / 0x100;
	offsets->wqcfg = VIDXD_WQCFG_OFFSET / 0x100;
	offsets->msix_perm = VIDXD_MSIX_PERM_OFFSET / 0x100;

	vidxd_mmio_init_cmdcap(vidxd);
	memset(bar0 + VIDXD_MSIX_PERM_OFFSET, 0, VIDXD_MSIX_PERM_TBL_SZ);
	vidxd_mmio_init_grpcfg(vidxd);
	vidxd_mmio_init_wqcfg(vidxd);
}

static void vidxd_reset_config(struct vdcm_idxd *vidxd)
{
	u16 *devid = (u16 *)(vidxd->cfg + PCI_DEVICE_ID);
	struct idxd_device *idxd = vidxd->idxd;

	memset(vidxd->cfg, 0, VIDXD_MAX_CFG_SPACE_SZ);
	memcpy(vidxd->cfg, idxd_pci_config, sizeof(idxd_pci_config));

	if (idxd->data->type == IDXD_TYPE_DSA)
		*devid = PCI_DEVICE_ID_INTEL_DSA_SPR0;
	else if (idxd->data->type == IDXD_TYPE_IAX)
		*devid = PCI_DEVICE_ID_INTEL_IAX_SPR0;

	memcpy(vidxd->cfg + 0x100, idxd_pci_ext_cap, sizeof(idxd_pci_ext_cap));
}

static inline void vidxd_reset_mmio(struct vdcm_idxd *vidxd)
{
	memset(&vidxd->bar0, 0, VIDXD_MAX_MMIO_SPACE_SZ);
}

void vidxd_init(struct vdcm_idxd *vidxd)
{
	struct idxd_wq *wq = vidxd->wq;

	vidxd_reset_config(vidxd);
	vidxd_reset_mmio(vidxd);

	vidxd->bar_size[0] = VIDXD_BAR0_SIZE;
	vidxd->bar_size[1] = VIDXD_BAR2_SIZE;

	vidxd_mmio_init(vidxd);

	if (wq->state == IDXD_WQ_ENABLED) {
		idxd_wq_disable(wq, false);
		wq->state = IDXD_WQ_LOCKED;
	}
}

void vidxd_shutdown(struct vdcm_idxd *vidxd)
{
	struct idxd_wq *wq = vidxd->wq;

	if (wq->state == IDXD_WQ_ENABLED) {
		idxd_wq_disable(wq, false);
		wq->state = IDXD_WQ_LOCKED;
	}
}

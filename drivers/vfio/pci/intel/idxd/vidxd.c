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
//	wq_cap->dedicated_mode = 1;
	if (wq_dedicated(wq))
		wq_cap->dedicated_mode = 1;
	else
		wq_cap->shared_mode = 1;
}

static void vidxd_mmio_init_wqcfg(struct vdcm_idxd *vidxd)
{
	struct idxd_device *idxd = vidxd->idxd;
	struct idxd_wq *wq = vidxd->wq;
	u8 *bar0 = vidxd->bar0;
	union wqcfg *wqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);

	wqcfg->wq_size = wq->size;
	wqcfg->wq_thresh = wq->threshold;

	if (wq_dedicated(wq))
		wqcfg->mode = WQCFG_MODE_DEDICATED;
	else if (device_user_pasid_enabled(idxd))
		wqcfg->pasid_en = 1;

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

	if (wq_dedicated(wq) && wq->state == IDXD_WQ_ENABLED) {
		idxd_wq_disable(wq, false);
		wq->state = IDXD_WQ_LOCKED;
	}
}

void vidxd_shutdown(struct vdcm_idxd *vidxd)
{
	struct idxd_wq *wq = vidxd->wq;

	if (wq_dedicated(wq) && wq->state == IDXD_WQ_ENABLED) {
		idxd_wq_disable(wq, false);
		wq->state = IDXD_WQ_LOCKED;
	}
}

static void vidxd_set_swerr(struct vdcm_idxd *vidxd, unsigned int error)
{
	union sw_err_reg *swerr = (union sw_err_reg *)(vidxd->bar0 + IDXD_SWERR_OFFSET);

	if (!swerr->valid) {
		memset(swerr, 0, sizeof(*swerr));
		swerr->valid = 1;
		swerr->error = error;
	} else if (!swerr->overflow) {
		swerr->overflow = 1;
	}
}

static inline void send_swerr_interrupt(struct vdcm_idxd *vidxd)
{
	union genctrl_reg *genctrl = (union genctrl_reg *)(vidxd->bar0 + IDXD_GENCTRL_OFFSET);
	u32 *intcause = (u32 *)(vidxd->bar0 + IDXD_INTCAUSE_OFFSET);

	if (!genctrl->softerr_int_en)
		return;

	*intcause |= IDXD_INTC_ERR;
	vidxd_send_interrupt(vidxd, 0);
}

static inline void send_halt_interrupt(struct vdcm_idxd *vidxd)
{
	union genctrl_reg *genctrl = (union genctrl_reg *)(vidxd->bar0 + IDXD_GENCTRL_OFFSET);
	u32 *intcause = (u32 *)(vidxd->bar0 + IDXD_INTCAUSE_OFFSET);

	if (!genctrl->halt_int_en)
		return;

	*intcause |= IDXD_INTC_HALT_STATE;
	vidxd_send_interrupt(vidxd, 0);
}

static void vidxd_report_pci_error(struct vdcm_idxd *vidxd)
{
	union gensts_reg *gensts = (union gensts_reg *)(vidxd->bar0 + IDXD_GENSTATS_OFFSET);

	vidxd_set_swerr(vidxd, DSA_ERR_PCI_CFG);
	/* set device to halt */
	gensts->reset_type = IDXD_DEVICE_RESET_FLR;
	gensts->state = IDXD_DEVICE_STATE_HALT;

	send_halt_interrupt(vidxd);
}

void vidxd_notify_revoked_handles (struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	u32 *intcause = (u32 *)(bar0 + IDXD_INTCAUSE_OFFSET);

	*intcause |= IDXD_INTC_INT_HANDLE_REVOKED;

	pr_info("informating guest about revoked handles\n");
	vidxd_send_interrupt(vidxd, 0);
}

int vidxd_cfg_read(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int count)
{
	u32 offset = pos & 0xfff;
	struct device *dev = vidxd_dev(vidxd);

	memcpy(buf, &vidxd->cfg[offset], count);

	dev_dbg(dev, "vidxd pci R %d %x %x: %llx\n",
		vidxd->wq->id, count, offset, get_reg_val(buf, count));

	return 0;
}

/*
 * Much of the emulation code has been borrowed from Intel i915 cfg space
 * emulation code.
 * drivers/gpu/drm/i915/gvt/cfg_space.c:
 */

/*
 * Bitmap for writable bits (RW or RW1C bits, but cannot co-exist in one
 * byte) byte by byte in standard pci configuration space. (not the full
 * 256 bytes.)
 */
static const u8 pci_cfg_space_rw_bmp[PCI_INTERRUPT_LINE + 4] = {
	[PCI_COMMAND]		= 0xff, 0x07,
	[PCI_STATUS]		= 0x00, 0xf9, /* the only one RW1C byte */
	[PCI_CACHE_LINE_SIZE]	= 0xff,
	[PCI_BASE_ADDRESS_0 ... PCI_CARDBUS_CIS - 1] = 0xff,
	[PCI_ROM_ADDRESS]	= 0x01, 0xf8, 0xff, 0xff,
	[PCI_INTERRUPT_LINE]	= 0xff,
};

static void _pci_cfg_mem_write(struct vdcm_idxd *vidxd, unsigned int off, u8 *src,
			       unsigned int bytes)
{
	u8 *cfg_base = vidxd->cfg;
	u8 mask, new, old;
	int i = 0;

	for (; i < bytes && (off + i < sizeof(pci_cfg_space_rw_bmp)); i++) {
		mask = pci_cfg_space_rw_bmp[off + i];
		old = cfg_base[off + i];
		new = src[i] & mask;

		/**
		 * The PCI_STATUS high byte has RW1C bits, here
		 * emulates clear by writing 1 for these bits.
		 * Writing a 0b to RW1C bits has no effect.
		 */
		if (off + i == PCI_STATUS + 1)
			new = (~new & old) & mask;

		cfg_base[off + i] = (old & ~mask) | new;
	}

	/* For other configuration space directly copy as it is. */
	if (i < bytes)
		memcpy(cfg_base + off + i, src + i, bytes - i);
}

static inline void _write_pci_bar(struct vdcm_idxd *vidxd, u32 offset, u32 val, bool low)
{
	u32 *pval;

	/* BAR offset should be 32 bits algiend */
	offset = rounddown(offset, 4);
	pval = (u32 *)(vidxd->cfg + offset);

	if (low) {
		/*
		 * only update bit 31 - bit 4,
		 * leave the bit 3 - bit 0 unchanged.
		 */
		*pval = (val & GENMASK(31, 4)) | (*pval & GENMASK(3, 0));
	} else {
		*pval = val;
	}
}

static int _pci_cfg_bar_write(struct vdcm_idxd *vidxd, unsigned int offset, void *p_data,
			      unsigned int bytes)
{
	u32 new = *(u32 *)(p_data);
	bool lo = IS_ALIGNED(offset, 8);
	u64 size;
	unsigned int bar_id;

	/*
	 * Power-up software can determine how much address
	 * space the device requires by writing a value of
	 * all 1's to the register and then reading the value
	 * back. The device will return 0's in all don't-care
	 * address bits.
	 */
	if (new == 0xffffffff) {
		switch (offset) {
		case PCI_BASE_ADDRESS_0:
		case PCI_BASE_ADDRESS_1:
		case PCI_BASE_ADDRESS_2:
		case PCI_BASE_ADDRESS_3:
			bar_id = (offset - PCI_BASE_ADDRESS_0) / 8;
			size = vidxd->bar_size[bar_id];
			_write_pci_bar(vidxd, offset, size >> (lo ? 0 : 32), lo);
			break;
		default:
			/* Unimplemented BARs */
			_write_pci_bar(vidxd, offset, 0x0, false);
		}
	} else {
		switch (offset) {
		case PCI_BASE_ADDRESS_0:
		case PCI_BASE_ADDRESS_1:
		case PCI_BASE_ADDRESS_2:
		case PCI_BASE_ADDRESS_3:
			_write_pci_bar(vidxd, offset, new, lo);
			break;
		default:
			break;
		}
	}
	return 0;
}

int vidxd_cfg_write(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int size)
{
	struct device *dev = &vidxd->idxd->pdev->dev;
	u32 offset = pos & 0xfff;
	u8 *cfg = vidxd->cfg;
	u64 val;

	if (size > 4)
		return -EINVAL;

	if (pos + size > VIDXD_MAX_CFG_SPACE_SZ)
		return -EINVAL;

	dev_dbg(dev, "vidxd pci W %d %x %x: %llx\n", vidxd->wq->id, size, pos,
		get_reg_val(buf, size));

	/* First check if it's PCI_COMMAND */
	if (IS_ALIGNED(pos, 2) && pos == PCI_COMMAND) {
		bool new_bme;
		bool bme;

		if (size > 2)
			return -EINVAL;

		new_bme = !!(get_reg_val(buf, 2) & PCI_COMMAND_MASTER);
		bme = !!(vidxd->cfg[pos] & PCI_COMMAND_MASTER);
		_pci_cfg_mem_write(vidxd, pos, buf, size);

		/* Flag error if turning off BME while device is enabled */
		if ((bme && !new_bme) && vidxd_state(vidxd) == IDXD_DEVICE_STATE_ENABLED)
			vidxd_report_pci_error(vidxd);
		return 0;
	}

	switch (pos) {
	case PCI_BASE_ADDRESS_0 ... PCI_BASE_ADDRESS_5:
		if (!IS_ALIGNED(pos, 4))
			return -EINVAL;
		return _pci_cfg_bar_write(vidxd, pos, buf, size);

	case VIDXD_ATS_OFFSET + 4:
		if (size < 4)
			break;
		offset += 2;
		buf = buf + 2;
		size -= 2;
		fallthrough;

	case VIDXD_ATS_OFFSET + 6:
		memcpy(&cfg[offset], buf, size);
		break;

	case VIDXD_PRS_OFFSET + 4: {
		u8 old_val, new_val;

		val = get_reg_val(buf, 1);
		old_val = cfg[VIDXD_PRS_OFFSET + 4];
		new_val = val & 1;

		cfg[offset] = new_val;
		if (old_val == 0 && new_val == 1) {
			/*
			 * Clear Stopped, Response Failure,
			 * and Unexpected Response.
			 */
			*(u16 *)&cfg[VIDXD_PRS_OFFSET + 6] &= ~(u16)(0x0103);
		}

		if (size < 4)
			break;

		offset += 2;
		buf = (u8 *)buf + 2;
		size -= 2;
		fallthrough;
	}

	case VIDXD_PRS_OFFSET + 6:
		cfg[offset] &= ~(get_reg_val(buf, 1) & 3);
		break;

	case VIDXD_PRS_OFFSET + 12 ... VIDXD_PRS_OFFSET + 15:
		memcpy(&cfg[offset], buf, size);
		break;

	case VIDXD_PASID_OFFSET + 4:
		if (size < 4)
			break;
		offset += 2;
		buf = buf + 2;
		size -= 2;
		fallthrough;

	case VIDXD_PASID_OFFSET + 6:
		cfg[offset] = get_reg_val(buf, 1) & 5;
		break;

	default:
		_pci_cfg_mem_write(vidxd, pos, buf, size);
	}
	return 0;
}

static void vidxd_report_swerror(struct vdcm_idxd *vidxd, unsigned int error)
{
	vidxd_set_swerr(vidxd, error);
	send_swerr_interrupt(vidxd);
}

int vidxd_mmio_write(struct vdcm_idxd *vidxd, u64 pos, void *buf, unsigned int size)
{
	u32 offset = pos & (vidxd->bar_size[0] - 1);
	u8 *bar0 = vidxd->bar0;
	struct device *dev = vidxd_dev(vidxd);

	dev_dbg(dev, "vidxd mmio W %d %x %x: %llx\n", vidxd->wq->id, size,
		offset, get_reg_val(buf, size));

	if (((size & (size - 1)) != 0) || (offset & (size - 1)) != 0)
		return -EINVAL;

	/* If we don't limit this, we potentially can write out of bound */
	if (size > sizeof(u32))
		return -EINVAL;

	switch (offset) {
	case IDXD_GENCFG_OFFSET ... IDXD_GENCFG_OFFSET + 3:
		/* Write only when device is disabled. */
		if (vidxd_state(vidxd) == IDXD_DEVICE_STATE_DISABLED) {
			dev_warn(dev, "Guest writes to unsupported GENCFG register\n");
			memcpy(bar0 + offset, buf, size);
		}
		break;

	case IDXD_GENCTRL_OFFSET:
		memcpy(bar0 + offset, buf, size);
		break;

	case IDXD_INTCAUSE_OFFSET:
		*(u32 *)&bar0[offset] &= ~(get_reg_val(buf, 4));
		break;

	case IDXD_CMD_OFFSET: {
		u32 *cmdsts = (u32 *)(bar0 + IDXD_CMDSTS_OFFSET);
		u32 val = get_reg_val(buf, size);

		if (size != sizeof(u32))
			return -EINVAL;

		/* Check and set command in progress */
		if (test_and_set_bit(IDXD_CMDS_ACTIVE_BIT, (unsigned long *)cmdsts) == 0)
			vidxd_do_command(vidxd, val);
		else
			vidxd_report_swerror(vidxd, DSA_ERR_CMD_REG);
		break;
	}

	case IDXD_SWERR_OFFSET:
		/* W1C */
		bar0[offset] &= ~(get_reg_val(buf, 1) & GENMASK(1, 0));
		break;

	case VIDXD_WQCFG_OFFSET ... VIDXD_WQCFG_OFFSET + VIDXD_WQ_CTRL_SZ - 1: {
		union wqcfg *wqcfg;
		int wq_id = (offset - VIDXD_WQCFG_OFFSET) / 0x20;
		int subreg = offset & 0x1c;
		u32 new_val;

		if (wq_id >= VIDXD_MAX_WQS)
			break;

		/* FIXME: Need to sanitize for RO Config WQ mode 1 */
		wqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET + wq_id * 0x20);
		if (size >= 4) {
			new_val = get_reg_val(buf, 4);
		} else {
			u32 tmp1, tmp2, shift, mask;

			switch (subreg) {
			case 4:
				tmp1 = wqcfg->bits[1];
				break;
			case 8:
				tmp1 = wqcfg->bits[2];
				break;
			case 12:
				tmp1 = wqcfg->bits[3];
				break;
			case 16:
				tmp1 = wqcfg->bits[4];
				break;
			case 20:
				tmp1 = wqcfg->bits[5];
				break;
			default:
				tmp1 = 0;
			}

			tmp2 = get_reg_val(buf, size);
			shift = (offset & 0x03U) * 8;
			mask = ((1U << size * 8) - 1u) << shift;
			new_val = (tmp1 & ~mask) | (tmp2 << shift);
		}

		if (subreg == 8) {
			if (wqcfg->wq_state == 0) {
				wqcfg->bits[2] &= 0xfe;
				wqcfg->bits[2] |= new_val & 0xffffff01;
			}
		}

		break;
	} /* WQCFG */

	case VIDXD_GRPCFG_OFFSET ...  VIDXD_GRPCFG_OFFSET + VIDXD_GRP_CTRL_SZ - 1:
		/* Nothing is written. Should be all RO */
		break;

	case VIDXD_MSIX_TABLE_OFFSET ...  VIDXD_MSIX_TABLE_OFFSET + VIDXD_MSIX_TBL_SZ - 1: {
		int index = (offset - VIDXD_MSIX_TABLE_OFFSET) / 0x10;
		u8 *msix_entry = &bar0[VIDXD_MSIX_TABLE_OFFSET + index * 0x10];
		u64 *pba = (u64 *)(bar0 + VIDXD_MSIX_PBA_OFFSET);
		u8 ctrl, new_mask;
		int ims_index, ims_off;
		u32 ims_ctrl, ims_mask;
		struct idxd_device *idxd = vidxd->idxd;

		memcpy(bar0 + offset, buf, size);
		ctrl = msix_entry[MSIX_ENTRY_CTRL_BYTE];

		new_mask = ctrl & MSIX_ENTRY_MASK_INT;
		if (!new_mask && test_and_clear_bit(index, (unsigned long *)pba))
			vidxd_send_interrupt(vidxd, index);

		if (index == 0)
			break;

// This needs to be reworked and needs to go through IMS core!!! FIXME
		ims_index = vfio_pci_ims_hwirq(&vidxd->vdev, index);
		ims_off = idxd->ims_offset + ims_index * 16 + sizeof(u64);
		ims_ctrl = ioread32(idxd->reg_base + ims_off);
		ims_mask = ims_ctrl & MSIX_ENTRY_MASK_INT;

		dev_dbg(dev, "%s writing to MSIX: ims_index: %d, ims_mask: 0x%x, new_mask: 0x%x\n",
			__func__, ims_index, ims_mask, new_mask);
		if (new_mask == ims_mask)
			break;

		if (new_mask)
			ims_ctrl |= MSIX_ENTRY_MASK_INT;
		else
			ims_ctrl &= ~MSIX_ENTRY_MASK_INT;

		iowrite32(ims_ctrl, idxd->reg_base + ims_off);
		/* readback to flush */
		ims_ctrl = ioread32(idxd->reg_base + ims_off);
		break;
	}

	case VIDXD_MSIX_PERM_OFFSET ...  VIDXD_MSIX_PERM_OFFSET + VIDXD_MSIX_PERM_TBL_SZ - 1: {
#define MSIX_PERM_PASID_EN_MASK		0x8
#define MSIX_PERM_PASID_MASK		0xfffff000
#define MSIX_PERM_PASID_SHIFT		12

		struct device *dev = vidxd_dev(vidxd);
		u32 msix_perm, pasid_en, pasid, gpasid;
		int index;

		if (size != sizeof(u32) || !IS_ALIGNED(offset, sizeof(u64))) {
			dev_warn(dev, "XXX unaligned MSIX PERM access\n");
			break;
		}

		memcpy(bar0 + offset, buf, size);
		index = (offset - VIDXD_MSIX_PERM_OFFSET) / 8;
		msix_perm = get_reg_val(buf, sizeof(u32)) & 0xfffff00d;
		pasid_en = msix_perm & MSIX_PERM_PASID_EN_MASK;
		/* May check if guest changes pasid_en bit, then may do sth. */
		if (pasid_en) {
			gpasid = (msix_perm & MSIX_PERM_PASID_MASK) >> MSIX_PERM_PASID_SHIFT;
			vidxd_get_host_pasid(dev, gpasid, &pasid);
			vfio_device_set_pasid(&vidxd->vdev, pasid);
			vfio_pci_ims_set_cookie(&vidxd->vdev, index,
						(union msi_instance_cookie *)&pasid);
		} else {
			vfio_device_set_pasid(&vidxd->vdev, vidxd->pasid);
			vfio_pci_ims_set_cookie(&vidxd->vdev, index,
						(union msi_instance_cookie *)&vidxd->pasid);
		}

		dev_dbg(dev, "%s writing to MSIX_PERM: %#x offset %#x index: %u, pasid: %d, gpasid: %d\n",
			__func__, msix_perm, offset, index, pasid, gpasid);
		break;
	}
	}

	return 0;
}

int vidxd_mmio_read(struct vdcm_idxd *vidxd, u64 pos, void *buf, unsigned int size)
{
	u32 offset = pos & (vidxd->bar_size[0] - 1);
	struct device *dev = vidxd_dev(vidxd);

	memcpy(buf, vidxd->bar0 + offset, size);

	dev_dbg(dev, "vidxd mmio R %d %x %x: %llx\n",
		vidxd->wq->id, size, offset, get_reg_val(buf, size));
	return 0;
}

int vidxd_portal_mmio_read(struct vdcm_idxd *vidxd, u64 pos, void *buf,
                                unsigned int size)
{
	u32 offset = pos & (vidxd->bar_size[1] - 1);
	struct device *dev = vidxd_dev(vidxd);

	BUG_ON((size & (size - 1)) != 0);
	BUG_ON(size > 8);
	BUG_ON((offset & (size - 1)) != 0);

	memset(buf, 0xff, size);

	dev_dbg(dev, "vidxd portal mmio R %d %x %x: %llx\n",
		vidxd->wq->id, size, offset, get_reg_val(buf, size));

	return 0;
}

int vidxd_portal_mmio_write(struct vdcm_idxd *vidxd, u64 pos, void *buf,
				unsigned int size)
{
	struct device *dev = vidxd_dev(vidxd);
	u32 offset = pos & (vidxd->bar_size[1] - 1);
	uint16_t wq_id = offset >> 14;
	uint16_t portal_id, portal_offset;
	struct idxd_virtual_wq *vwq;
	struct idxd_wq *wq;
	struct idxd_wq_portal *portal;
	enum idxd_portal_prot portal_prot = IDXD_PORTAL_UNLIMITED;
	int rc = 0;

	BUG_ON((size & (size - 1)) != 0);
	BUG_ON(size > 64);
	BUG_ON((offset & (size - 1)) != 0);

	dev_dbg(dev, "vidxd portal mmio W %d %x %x: %llx\n", vidxd->wq->id, size,
			offset, get_reg_val(buf, size));

	if (wq_id >= vidxd->num_wqs) {
		printk("DSA portal write: Invalid wq  %d\n", wq_id);
	}

	vwq = &vidxd->vwq[0];
	wq = vidxd->wq;

	if (!wq_dedicated(wq) || (((offset >> PAGE_SHIFT) & 0x3) == 1))
		portal_prot = IDXD_PORTAL_LIMITED;

	portal_id = (offset & 0xFFF) >> 6;
	portal_offset = offset & 0x3F;

	portal = &vwq->portals[portal_id];

	portal->count += size;
	memcpy(&portal->data[portal_offset], buf, size);

	if (portal->count == IDXD_DESC_SIZE) {
		struct idxd_wq_desc_elem *elem;
		u64 *p = (u64 *)portal->data;
		printk("desc: %016llx %016llx  %016llx %016llx %016llx %016llx %016llx %016llx\n",
				p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

		mutex_lock(&vidxd->mig_submit_lock);
		if (vidxd->paused) {
#if 0
			if (wq_dedicated(wq)) {
#endif
				/* Queue the descriptor if submitted to DWQ */
				if (vwq->ndescs == wq->size) {
					printk("can't submit more descriptors than WQ size. Dropping.\n");
					goto out_unlock;
				}

				elem = kmalloc(sizeof(struct idxd_wq_desc_elem),
					GFP_KERNEL);

				if (elem == NULL) {
					printk("kmalloc failed\n");
					rc = -ENOMEM;
					goto out_unlock;
				}
				printk("queuing the desc\n");
				memcpy(elem->work_desc, portal->data, IDXD_DESC_SIZE);
				elem->portal_prot = portal_prot;
				elem->portal_id = portal_id;

				list_add_tail(&elem->link, &vwq->head);
				vwq->ndescs++;
#if 0
			} else {
				/* Return retry if submitted to SWQ */
				rc = -EAGAIN;
				goto out_unlock;
			}
#endif
               } else {
			void __iomem *wq_portal;

			wq_portal = vidxd->idxd->portal_base +
				idxd_get_wq_portal_offset(wq->id,
						portal_prot, IDXD_IRQ_IMS);
                        wq_portal += (portal_id << 6);

			printk("submitting a desc to WQ %d ded %d\n", wq->id,
					wq_dedicated(wq));
			if (wq_dedicated(wq)) {
				iosubmit_cmds512(wq_portal, (struct dsa_hw_desc *)p, 1);
			} else {
				int rc;
				struct dsa_hw_desc *hw =
					(struct dsa_hw_desc *)portal->data;
				int hpasid, gpasid = hw->pasid;

				/* Translate the gpasid in the descriptor */
                                rc = vidxd_get_host_pasid(dev, gpasid, &hpasid);
                                if (rc < 0) {
                                        pr_info("gpasid->hpasid trans failed\n");
					rc = -EINVAL;
					goto out_unlock;
                                }
                                hw->pasid = hpasid;

				/* FIXME: Allow enqcmds to retry a few times
				 * before failing */
				rc = enqcmds(wq_portal, hw);
				if (rc < 0) {
					pr_info("%s: enqcmds failed\n", __func__);
					goto out_unlock;
				}
			}
		}
out_unlock:
		mutex_unlock(&vidxd->mig_submit_lock);
		memset(&portal->data, 0, IDXD_DESC_SIZE);
		portal->count = 0;
	}

	return rc;
}

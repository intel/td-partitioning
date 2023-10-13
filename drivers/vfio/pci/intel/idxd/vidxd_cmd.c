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

static void idxd_complete_command(struct vdcm_idxd *vidxd, enum idxd_cmdsts_err val)
{
	u8 *bar0 = vidxd->bar0;
	u32 *cmd = (u32 *)(bar0 + IDXD_CMD_OFFSET);
	u32 *cmdsts = (u32 *)(bar0 + IDXD_CMDSTS_OFFSET);
	u32 *intcause = (u32 *)(bar0 + IDXD_INTCAUSE_OFFSET);
	struct device *dev = vidxd_dev(vidxd);

	*cmdsts = val;
	dev_dbg(dev, "%s: cmd: %#x  status: %#x\n", __func__, *cmd, val);

	if (*cmd & IDXD_CMD_INT_MASK) {
		*intcause |= IDXD_INTC_CMD;
		vidxd_send_interrupt(vidxd, 0);
	}
}

static void vidxd_enable(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	union gensts_reg *gensts = (union gensts_reg *)(bar0 + IDXD_GENSTATS_OFFSET);
	bool ats = (*(u16 *)&vidxd->cfg[VIDXD_ATS_OFFSET + 6]) & (1U << 15);
	bool prs = (*(u16 *)&vidxd->cfg[VIDXD_PRS_OFFSET + 4]) & 1U;
	bool pasid = (*(u16 *)&vidxd->cfg[VIDXD_PASID_OFFSET + 6]) & 1U;

	if (gensts->state == IDXD_DEVICE_STATE_ENABLED)
		return idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_DEV_ENABLED);

	/* Check PCI configuration */
	if (!(vidxd->cfg[PCI_COMMAND] & PCI_COMMAND_MASTER))
		return idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_BUSMASTER_EN);

	if (pasid != prs || (pasid && !ats))
		return idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_BUSMASTER_EN);

	gensts->state = IDXD_DEVICE_STATE_ENABLED;

	return idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_disable(struct vdcm_idxd *vidxd)
{
	struct idxd_wq *wq;
	union wqcfg *vwqcfg;
	u8 *bar0 = vidxd->bar0;
	union gensts_reg *gensts = (union gensts_reg *)(bar0 + IDXD_GENSTATS_OFFSET);
	struct device *dev = vidxd_dev(vidxd);
	int rc;

	if (gensts->state == IDXD_DEVICE_STATE_DISABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_DIS_DEV_EN);
		return;
	}

	vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
	wq = vidxd->wq;

	if (wq_dedicated(wq)) {
		rc = idxd_wq_disable(wq, false);
		if (rc) {
			dev_warn(dev, "vidxd disable (wq disable) failed: %#x\n", rc);
			idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_DIS_DEV_EN);
			return;
		}
	} else {
		idxd_wq_drain(wq);
	}

	vwqcfg->wq_state = IDXD_WQ_DISABLED;
	gensts->state = IDXD_DEVICE_STATE_DISABLED;
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_drain_all(struct vdcm_idxd *vidxd)
{
	struct idxd_wq *wq = vidxd->wq;

	idxd_wq_drain(wq);
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_wq_drain(struct vdcm_idxd *vidxd, int val)
{
	u8 *bar0 = vidxd->bar0;
	union wqcfg *vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
	struct idxd_wq *wq = vidxd->wq;

	if (vwqcfg->wq_state != IDXD_WQ_DEV_ENABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_WQ_NOT_EN);
		return;
	}

	idxd_wq_drain(wq);
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_abort_all(struct vdcm_idxd *vidxd)
{
	struct idxd_wq *wq = vidxd->wq;
	int rc;

	rc = idxd_wq_abort(wq);
	if (rc < 0) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
		return;
	}
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_wq_abort(struct vdcm_idxd *vidxd, int val)
{
	u8 *bar0 = vidxd->bar0;
	union wqcfg *vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
	struct idxd_wq *wq = vidxd->wq;
	int rc;

	if (vwqcfg->wq_state != IDXD_WQ_DEV_ENABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_WQ_NOT_EN);
		return;
	}

	rc = idxd_wq_abort(wq);
	if (rc < 0) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
		return;
	}
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static inline void vidxd_vwq_init(struct vdcm_idxd *vidxd)
{
	int i;

	for (i = 0; i < VIDXD_MAX_WQS; i++) {
		INIT_LIST_HEAD(&vidxd->vwq[i].head);
		vidxd->vwq[i].ndescs = 0;

		memset(vidxd->vwq[i].portals, 0,
		       VIDXD_MAX_PORTALS * sizeof(struct idxd_wq_portal));
	}
}

void vidxd_reset(struct vdcm_idxd *vidxd)
{
	u8 *bar0 = vidxd->bar0;
	union gensts_reg *gensts = (union gensts_reg *)(bar0 + IDXD_GENSTATS_OFFSET);
	union wqcfg *vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
	struct idxd_wq *wq;
	int rc;

	gensts->state = IDXD_DEVICE_STATE_DRAIN;
	wq = vidxd->wq;

	vidxd_vwq_init(vidxd);

	if (wq_dedicated(wq) && wq->state == IDXD_WQ_ENABLED) {
		rc = idxd_wq_abort(wq);
		if (rc < 0) {
			idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
			return;
		}

		rc = idxd_wq_disable(wq, false);
		if (rc < 0) {
			idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
			return;
		}
	}

	vidxd_mmio_init(vidxd);
	vwqcfg->wq_state = IDXD_WQ_DISABLED;
	gensts->state = IDXD_DEVICE_STATE_DISABLED;
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_wq_reset(struct vdcm_idxd *vidxd, int wq_id_mask)
{
	struct idxd_wq *wq;
	u8 *bar0 = vidxd->bar0;
	union wqcfg *vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
	int rc;

	wq = vidxd->wq;
	if (vwqcfg->wq_state != IDXD_WQ_DEV_ENABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_WQ_NOT_EN);
		return;
	}

	if (wq_dedicated(wq)) {
		rc = idxd_wq_abort(wq);
		if (rc < 0) {
			idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
			return;
		}
		rc = idxd_wq_disable(wq, false);
		if (rc < 0) {
			idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
			return;
		}
	} else {
		idxd_wq_drain(wq);
	}

	vwqcfg->wq_state = IDXD_WQ_DEV_DISABLED;
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_alloc_int_handle(struct vdcm_idxd *vidxd, int operand)
{
	bool ims = !!(operand & CMD_INT_HANDLE_IMS);
	u32 cmdsts;
	struct device *dev = vidxd_dev(vidxd);
	int ims_idx, vidx;

	vidx = operand & GENMASK(15, 0);

	/* vidx cannot be 0 since that's emulated and does not require IMS handle */
	if (vidx <= 0 || vidx >= VIDXD_MAX_MSIX_VECS) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_INVAL_INT_IDX);
		return;
	}

	if (ims) {
		dev_warn(dev, "IMS allocation is not implemented yet\n");
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_NO_HANDLE);
		return;
	}

	/*
	 * The index coming from the guest driver will start at 1. Vector 0 is
	 * the command interrupt and is emulated by the vdcm. Here we are asking
	 * for the IMS index that's backing the I/O vectors from the relative
	 * index to the vdev device. This index would start at 0. So for a
	 * passed in vidx that is 1, we pass 0 to dev_msi_hwirq() and so forth.
	 */
	ims_idx = vfio_pci_ims_hwirq(&vidxd->vdev, vidx);
	cmdsts = ims_idx << IDXD_CMDSTS_RES_SHIFT;
	dev_dbg(dev, "requested index %d handle %d\n", vidx, ims_idx);
	idxd_complete_command(vidxd, cmdsts);
}

static void vidxd_release_int_handle(struct vdcm_idxd *vidxd, int operand)
{
	struct device *dev = vidxd_dev(vidxd);
	bool ims = !!(operand & CMD_INT_HANDLE_IMS);
	int handle, i;
	bool found = false;

	handle = operand & GENMASK(15, 0);
	if (ims) {
		dev_dbg(dev, "IMS allocation is not implemented yet\n");
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_INVAL_INT_IDX_RELEASE);
		return;
	}

	/* IMS backed entry start at 1, 0 is emulated vector */
	for (i = 1; i < VIDXD_MAX_MSIX_VECS; i++) {
		if (vfio_pci_ims_hwirq(&vidxd->vdev, i) == handle) {
			found = true;
			break;
		}
	}

	if (!found) {
		dev_dbg(dev, "Freeing unallocated int handle.\n");
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_INVAL_INT_IDX_RELEASE);
	}

	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

int vidxd_get_host_pasid(struct device *dev, u32 gpasid, u32 *pasid)
{
	struct ioasid_set *ioasid_set;
	struct mm_struct *mm;

	mm = get_task_mm(current);
	if (!mm) {
		dev_warn(dev, "%s no mm!\n", __func__);

		return -ENXIO;
	}

	ioasid_set = ioasid_find_mm_set(mm);
	if (!ioasid_set) {
		mmput(mm);
		dev_warn(dev, "%s no ioasid_set!\n", __func__);

		return -ENXIO;
	}

	*pasid = ioasid_find_by_spid(ioasid_set, gpasid, true);
	mmput(mm);
	if (*pasid == INVALID_IOASID) {
		dev_warn(dev, "%s invalid ioasid by spid!\n", __func__);

		return -ENXIO;
	}

	return 0;
}

static void vidxd_wq_enable(struct vdcm_idxd *vidxd, int wq_id)
{
	struct idxd_wq *wq;
	u8 *bar0 = vidxd->bar0;
	union wq_cap_reg *wqcap;
	struct device *dev = vidxd_dev(vidxd);
	struct idxd_device *idxd;
	union wqcfg *vwqcfg, *wqcfg;
	bool wq_pasid_enable;
	int rc;
	int wq_pasid = -1;
	bool priv;

	if (wq_id >= VIDXD_MAX_WQS) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_INVAL_WQIDX);
		return;
	}

	idxd = vidxd->idxd;
	wq = vidxd->wq;

	vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET + wq_id * 32);
	wqcap = (union wq_cap_reg *)(bar0 + IDXD_WQCAP_OFFSET);
	wqcfg = wq->wqcfg;

	if (vidxd_state(vidxd) != IDXD_DEVICE_STATE_ENABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_DEV_NOTEN);
		return;
	}

	if (vwqcfg->wq_state != IDXD_WQ_DEV_DISABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_WQ_ENABLED);
		return;
	}


        if ((!wq_dedicated(wq) && wqcap->shared_mode == 0) ||
            (wq_dedicated(wq) && wqcap->dedicated_mode == 0)) {
                idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_WQ_MODE);
                return;
        }

        if ((!wq_dedicated(wq) && vwqcfg->pasid_en == 0)) {
                idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_PASID_EN);
                return;
        }

	wq_pasid_enable = vwqcfg->pasid_en;

	if (!wq_dedicated(wq))
		goto out;

	if (wq_pasid_enable) {
		u32 gpasid;

		priv = vwqcfg->priv;
		gpasid = vwqcfg->pasid;

		if (gpasid == 0) {
			wq_pasid = vidxd->pasid;
			dev_dbg(dev, "shared wq, pasid 0, use default host: %u\n",
				wq_pasid);
		} else {
			rc = vidxd_get_host_pasid(dev, gpasid, &wq_pasid);
			dev_dbg(dev, "guest pasid enabled, translate gpasid: %d to wq_pasid %d\n",
				gpasid, wq_pasid);
		}
	} else {
		priv = 0;
		wq_pasid = vfio_device_get_pasid(&vidxd->vdev);
		if (wq_pasid == IOMMU_PASID_INVALID) {
			dev_warn(dev, "idxd pasid setup failed wq %d\n",
				 wq->id);
			idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_PASID_EN);
			return;
		}

		dev_dbg(dev, "guest pasid disabled, using default host pasid: %u in wq %d\n",
			wq_pasid, wq->id);
	}

	if (wq_pasid >= 0) {
		unsigned long flags;

		wqcfg->bits[WQCFG_PASID_IDX] &= ~GENMASK(29, 8);
		wqcfg->priv = priv;
		wqcfg->pasid_en = 1;
		wqcfg->pasid = wq_pasid;
		dev_dbg(dev, "program pasid %d in wq %d\n", wq_pasid, wq->id);
		spin_lock_irqsave(&idxd->dev_lock, flags);
		idxd_wq_setup_pasid(wq, wq_pasid);
		idxd_wq_setup_priv(wq, priv);
		spin_unlock_irqrestore(&idxd->dev_lock, flags);
		rc = idxd_wq_enable(wq);
		if (rc < 0) {
			dev_err(dev, "vidxd enable wq %d failed\n", wq->id);
			idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_WQ_NOT_EN);
			return;
		}
	} else {
		dev_err(dev, "idxd pasid setup failed wq %d wq_pasid %d\n",
			wq->id, wq_pasid);
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_PASID_EN);
		return;
	}

out:
	vwqcfg->wq_state = IDXD_WQ_DEV_ENABLED;
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static void vidxd_wq_disable(struct vdcm_idxd *vidxd, int wq_id_mask)
{
	struct idxd_wq *wq;
	union wqcfg *wqcfg, *vwqcfg;
	u8 *bar0 = vidxd->bar0;
	struct device *dev = vidxd_dev(vidxd);
	int rc;

	wq = vidxd->wq;

	dev_dbg(dev, "vidxd disable wq %u:%u\n", 0, wq->id);

	wqcfg = wq->wqcfg;
	vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
	if (vwqcfg->wq_state != IDXD_WQ_DEV_ENABLED) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_ERR_WQ_NOT_EN);
		return;
	}

	if (!wq_dedicated(wq)) {
		idxd_wq_drain(wq);
		goto out;
	}

	rc = idxd_wq_disable(wq, false);
	if (rc < 0) {
		dev_warn(dev, "vidxd disable wq failed: %#x\n", rc);
		idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
		return;
	}

#if 0
	if (vwqcfg->pasid_en) {
		mm = get_task_mm(current);
		if (!mm) {
			dev_dbg(dev, "Can't retrieve task mm\n");
			return;
		}
	}
#endif

out:
	vwqcfg->wq_state = IDXD_WQ_DEV_DISABLED;
	idxd_complete_command(vidxd, IDXD_CMDSTS_SUCCESS);
}

static bool command_supported(struct vdcm_idxd *vidxd, u32 cmd)
{
	u8 *bar0 = vidxd->bar0;
	u32 *cmd_cap = (u32 *)(bar0 + IDXD_CMDCAP_OFFSET);

	return !!(*cmd_cap & BIT(cmd));
}

void vidxd_do_command(struct vdcm_idxd *vidxd, u32 val)
{
	union idxd_command_reg *reg = (union idxd_command_reg *)(vidxd->bar0 + IDXD_CMD_OFFSET);
	union gensts_reg *gensts = (union gensts_reg *)(vidxd->bar0 + IDXD_GENSTATS_OFFSET);
	struct device *dev = vidxd_dev(vidxd);

	reg->bits = val;

	dev_dbg(dev, "%s: cmd code: %u reg: %x\n", __func__, reg->cmd, reg->bits);
	if (!command_supported(vidxd, reg->cmd)) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_INVAL_CMD);
		return;
	}

	if (gensts->state == IDXD_DEVICE_STATE_HALT) {
		idxd_complete_command(vidxd, IDXD_CMDSTS_HW_ERR);
		return;
	}

	switch (reg->cmd) {
	case IDXD_CMD_ENABLE_DEVICE:
		vidxd_enable(vidxd);
		break;
	case IDXD_CMD_DISABLE_DEVICE:
		vidxd_disable(vidxd);
		break;
	case IDXD_CMD_DRAIN_ALL:
		vidxd_drain_all(vidxd);
		break;
	case IDXD_CMD_ABORT_ALL:
		vidxd_abort_all(vidxd);
		break;
	case IDXD_CMD_RESET_DEVICE:
		vidxd_reset(vidxd);
		break;
	case IDXD_CMD_ENABLE_WQ:
		vidxd_wq_enable(vidxd, reg->operand);
		break;
	case IDXD_CMD_DISABLE_WQ:
		vidxd_wq_disable(vidxd, reg->operand);
		break;
	case IDXD_CMD_DRAIN_WQ:
		vidxd_wq_drain(vidxd, reg->operand);
		break;
	case IDXD_CMD_ABORT_WQ:
		vidxd_wq_abort(vidxd, reg->operand);
		break;
	case IDXD_CMD_RESET_WQ:
		vidxd_wq_reset(vidxd, reg->operand);
		break;
	case IDXD_CMD_REQUEST_INT_HANDLE:
		vidxd_alloc_int_handle(vidxd, reg->operand);
		break;
	case IDXD_CMD_RELEASE_INT_HANDLE:
		vidxd_release_int_handle(vidxd, reg->operand);
		break;
	default:
		idxd_complete_command(vidxd, IDXD_CMDSTS_INVAL_CMD);
		break;
	}
}

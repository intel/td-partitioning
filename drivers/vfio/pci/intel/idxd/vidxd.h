/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021,2022 Intel Corporation. All rights rsvd. */

#ifndef _IDXD_VDEV_H_
#define _IDXD_VDEV_H_

#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>
#include "idxd.h"

/* two 64-bit BARs implemented */
#define VIDXD_MAX_BARS			2
#define VIDXD_MAX_CFG_SPACE_SZ		4096
#define VIDXD_MAX_MMIO_SPACE_SZ		8192
#define VIDXD_MSIX_TBL_SZ_OFFSET	0x42
#define VIDXD_CAP_CTRL_SZ		0x100
#define VIDXD_GRP_CTRL_SZ		0x100
#define VIDXD_WQ_CTRL_SZ		0x100
#define VIDXD_WQ_OCPY_INT_SZ		0x20
#define VIDXD_MSIX_TBL_SZ		0x90
#define VIDXD_MSIX_PERM_TBL_SZ		0x48

#define VIDXD_VERSION_OFFSET		0
#define VIDXD_MSIX_PERM_OFFSET		0x300
#define VIDXD_GRPCFG_OFFSET		0x400
#define VIDXD_WQCFG_OFFSET		0x500
#define VIDXD_MSIX_TABLE_OFFSET		0x600
#define VIDXD_MSIX_PBA_OFFSET		0x700
#define VIDXD_IMS_OFFSET		0x1000

#define VIDXD_BAR0_SIZE			0x2000
#define VIDXD_BAR2_SIZE			0x2000
#define VIDXD_MAX_MSIX_VECS		2
#define VIDXD_MAX_MSIX_ENTRIES		VIDXD_MAX_MSIX_VECS
#define VIDXD_MAX_WQS			1

struct vdcm_idxd {
	struct vfio_device vdev;
	struct idxd_device *idxd;
	struct idxd_wq *wq;
	struct iommufd_device *idev;

	u64 bar_val[VIDXD_MAX_BARS];
	u64 bar_size[VIDXD_MAX_BARS];
	u8 cfg[VIDXD_MAX_CFG_SPACE_SZ];
	u8 bar0[VIDXD_MAX_MMIO_SPACE_SZ];

	struct idxd_dev *parent;

	struct mutex dev_lock; /* lock for vidxd resources */

	ioasid_t pasid;
	struct xarray pasid_xa;
};

static inline struct vdcm_idxd *vdev_to_vidxd(struct vfio_device *vdev)
{
	return container_of(vdev, struct vdcm_idxd, vdev);
}

void vidxd_init(struct vdcm_idxd *vidxd);
void vidxd_shutdown(struct vdcm_idxd *vidxd);

#endif

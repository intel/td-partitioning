/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021,2022 Intel Corporation. All rights rsvd. */

#ifndef _IDXD_VDEV_H_
#define _IDXD_VDEV_H_

#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>
#include "idxd.h"

#define VIDXD_MAX_MSIX_VECS		2

struct vdcm_idxd {
	struct vfio_device vdev;
	struct idxd_device *idxd;
	struct idxd_wq *wq;

	struct idxd_dev *parent;

	struct mutex dev_lock; /* lock for vidxd resources */
};

static inline struct vdcm_idxd *vdev_to_vidxd(struct vfio_device *vdev)
{
	return container_of(vdev, struct vdcm_idxd, vdev);
}

#endif

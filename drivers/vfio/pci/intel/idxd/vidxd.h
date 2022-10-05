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

#define VIDXD_ATS_OFFSET 0x100
#define VIDXD_PRS_OFFSET 0x110
#define VIDXD_PASID_OFFSET 0x120

enum {
	IDXD_VDCM_READ = 0,
	IDXD_VDCM_WRITE,
};

union hw_desc {
	struct dsa_hw_desc hw;
	struct iax_hw_desc iax_hw;
};

#define IDXD_DESC_SIZE sizeof(union hw_desc)

#define VIDXD_MAX_PORTALS 64

struct idxd_wq_desc_elem {
	enum idxd_portal_prot portal_prot;
	u8 portal_id;
	u8 work_desc[IDXD_DESC_SIZE];
	struct list_head link;
};

struct idxd_wq_portal {
	u8 data[IDXD_DESC_SIZE];
	unsigned int count;
};

struct idxd_virtual_wq {
	unsigned int ndescs;
	struct list_head head;
	struct idxd_wq_portal portals[VIDXD_MAX_PORTALS];
};

struct vidxd_data {
	u64 bar_val[VIDXD_MAX_BARS];
	u64 bar_size[VIDXD_MAX_BARS];
	u8 cfg[VIDXD_MAX_CFG_SPACE_SZ];
	u8 bar0[VIDXD_MAX_MMIO_SPACE_SZ];

	u8 ims_idx[VIDXD_MAX_MSIX_VECS];

	unsigned int ndescs[VIDXD_MAX_WQS];
	struct idxd_wq_desc_elem el[VIDXD_MAX_WQS][VIDXD_MAX_PORTALS];
};

struct vidxd_migration_file {
	struct file *filp;
	struct mutex lock;
	bool disabled;

	struct vidxd_data vidxd_data;
	size_t total_length;
};

struct vdcm_idxd {
	struct vfio_device vdev;
	struct idxd_device *idxd;
	struct idxd_wq *wq;
	struct idxd_virtual_wq vwq[VIDXD_MAX_WQS];
	struct iommufd_device *idev;
	int num_wqs;

	u64 bar_val[VIDXD_MAX_BARS];
	u64 bar_size[VIDXD_MAX_BARS];
	u8 cfg[VIDXD_MAX_CFG_SPACE_SZ];
	u8 bar0[VIDXD_MAX_MMIO_SPACE_SZ];

	struct idxd_dev *parent;

	struct mutex dev_lock; /* lock for vidxd resources */
	struct mutex mig_submit_lock;

	ioasid_t pasid;
	struct xarray pasid_xa;

	struct eventfd_ctx *req_trigger;

	bool paused;
	struct mutex state_mutex;
	enum vfio_device_mig_state mig_state;
	struct vidxd_migration_file *resuming_migf;
	struct vidxd_migration_file *saving_migf;
};

struct vdcm_hwpt {
	ioasid_t	pasid;
	u32		hwpt_id;
};

static inline struct vdcm_idxd *vdev_to_vidxd(struct vfio_device *vdev)
{
	return container_of(vdev, struct vdcm_idxd, vdev);
}

static inline struct device *vidxd_dev(struct vdcm_idxd *vidxd)
{
	return wq_confdev(vidxd->wq);
}

static inline u64 get_reg_val(void *buf, int size)
{
	u64 val = 0;

	switch (size) {
	case 8:
		val = *(u64 *)buf;
		break;
	case 4:
		val = *(u32 *)buf;
		break;
	case 2:
		val = *(u16 *)buf;
		break;
	case 1:
		val = *(u8 *)buf;
		break;
	}

	return val;
}

static inline u8 vidxd_state(struct vdcm_idxd *vidxd)
{
	union gensts_reg *gensts = (union gensts_reg *)(vidxd->bar0 + IDXD_GENSTATS_OFFSET);

	return gensts->state;
}

void vidxd_init(struct vdcm_idxd *vidxd);
void vidxd_shutdown(struct vdcm_idxd *vidxd);
void vidxd_mmio_init(struct vdcm_idxd *vidxd);
int vidxd_cfg_read(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int count);
int vidxd_cfg_write(struct vdcm_idxd *vidxd, unsigned int pos, void *buf, unsigned int size);
int vidxd_get_host_pasid(struct device *dev, u32 gpasid, u32 *pasid);
int vidxd_mmio_read(struct vdcm_idxd *vidxd, u64 pos, void *buf, unsigned int size);
int vidxd_mmio_write(struct vdcm_idxd *vidxd, u64 pos, void *buf, unsigned int size);
int vidxd_portal_mmio_read(struct vdcm_idxd *vidxd, u64 pos, void *buf,
			   unsigned int size);
int vidxd_portal_mmio_write(struct vdcm_idxd *vidxd, u64 pos, void *buf,
			    unsigned int size);
void vidxd_notify_revoked_handles (struct vdcm_idxd *vidxd);
int vidxd_get_host_pasid(struct device *dev, u32 gpasid, u32 *pasid);

static inline void vidxd_send_interrupt(struct vdcm_idxd *vidxd, int vector)
{
	u8 *bar0 = vidxd->bar0;
	u8 *msix_entry = &bar0[VIDXD_MSIX_TABLE_OFFSET + vector * 0x10];
	u64 *pba = (u64 *)(bar0 + VIDXD_MSIX_PBA_OFFSET);
	u8 ctrl;

	ctrl = msix_entry[MSIX_ENTRY_CTRL_BYTE];
	if (ctrl & MSIX_ENTRY_MASK_INT)
		set_bit(vector, (unsigned long *)pba);
	else
		vfio_pci_ims_send_signal(&vidxd->vdev, vector);
}

void vidxd_do_command(struct vdcm_idxd *vidxd, u32 val);

#endif

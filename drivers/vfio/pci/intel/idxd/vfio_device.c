// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/vfio.h>
#include <linux/iommufd.h>
#include <linux/eventfd.h>
#include <linux/anon_inodes.h>
#include <linux/msi.h>
#include <linux/irqchip/irq-pci-intel-idxd.h>
#include "registers.h"
#include "idxd.h"
#include "vidxd.h"

MODULE_IMPORT_NS(IOMMUFD);

enum {
	IDXD_VDEV_TYPE_1DWQ = 0,
	IDXD_VDEV_TYPE_1SWQ,
	IDXD_VDEV_TYPE_MAX
};

static int idxd_vdcm_open(struct vfio_device *vdev)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	struct idxd_device *idxd = vidxd->wq->idxd;
	ioasid_t pasid = vidxd->pasid;
	int ret;

	if (!device_user_pasid_enabled(idxd))
		return -ENODEV;

	mutex_lock(&vidxd->dev_lock);
	vidxd_init(vidxd);
	vfio_pci_ims_init(vdev, vidxd->wq->idxd->pdev, (union msi_instance_cookie *)&pasid);
	ret = vfio_pci_ims_set_emulated(vdev, 0, 1);
	if (ret < 0)
		goto err_ims;

	mutex_unlock(&vidxd->dev_lock);

	if (vdev->mig_ops->migration_set_state)
		vidxd->mig_state = VFIO_DEVICE_STATE_RUNNING;

	return 0;
err_ims:
	vidxd_shutdown(vidxd);
	vfio_device_set_pasid(vdev, IOMMU_PASID_INVALID);
	mutex_unlock(&vidxd->dev_lock);

	return ret;
}

static int idxd_vdcm_set_irqs(struct vdcm_idxd *vidxd, uint32_t flags,
			      unsigned int index, unsigned int start,
			      unsigned int count, void *data)
{
	switch (index) {
	case VFIO_PCI_INTX_IRQ_INDEX:
	case VFIO_PCI_MSI_IRQ_INDEX:
		break;
	case VFIO_PCI_MSIX_IRQ_INDEX:
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			return vfio_pci_set_ims_trigger(&vidxd->vdev, index, start,
							count, flags, data);
		}
		break;
	case VFIO_PCI_REQ_IRQ_INDEX:
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			return vfio_set_req_trigger(&vidxd->vdev, index, start,
						    count, flags, data);
		}
		break;
	}

	return -ENOTTY;
}

static void idxd_vdcm_close(struct vfio_device *vdev)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);

	mutex_lock(&vidxd->dev_lock);
	/* Disable IMS if it was enabled. */
//	if  (ims->ims_en) {
		idxd_vdcm_set_irqs(vidxd,
				   VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
				   VFIO_PCI_MSIX_IRQ_INDEX, 0, 0, NULL);
//	}
	vfio_pci_ims_free(vdev);
	vidxd_shutdown(vidxd);
	vfio_device_set_pasid(vdev, IOMMU_PASID_INVALID);
	vidxd->paused = false;
	mutex_unlock(&vidxd->dev_lock);
}

static int idxd_vdcm_bind_iommufd(struct vfio_device *vdev,
				  struct iommufd_ctx *ictx, u32 *out_device_id)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	struct idxd_device *idxd = vidxd->idxd;
	struct iommufd_device *idev;
	ioasid_t pasid;
	int rc = 0;

	mutex_lock(&vidxd->dev_lock);

	/* Allow only one iommufd per vfio_device */
	if (vidxd->idev) {
		rc = -EBUSY;
		goto out;
	}

	pasid = ioasid_alloc(NULL, 1, idxd->pdev->dev.iommu->max_pasids, vidxd, 0);
	//pasid = iommu_alloc_global_pasid(&idxd->pdev->dev);
	if (pasid == IOMMU_PASID_INVALID) {
		rc = -ENOSPC;
		goto out;
	}
	vidxd->pasid = pasid;
	vfio_device_set_pasid(vdev, pasid);

	idev = iommufd_device_bind_pasid(ictx, &idxd->pdev->dev, pasid, out_device_id);
	if (IS_ERR(idev)) {
		rc = PTR_ERR(idev);
		vfio_device_set_pasid(vdev, IOMMU_PASID_INVALID);
		goto out;
	}

	vidxd->idev = idev;
	xa_init_flags(&vidxd->pasid_xa, XA_FLAGS_ALLOC);
	vdev->iommufd_device = idev;
out:
	mutex_unlock(&vidxd->dev_lock);

	return rc;
}

static void idxd_vdcm_unbind_iommufd(struct vfio_device *vdev)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);

	mutex_lock(&vidxd->dev_lock);
	if (vidxd->idev) {
		struct vdcm_hwpt *hwpt;
		unsigned long index;

		xa_for_each (&vidxd->pasid_xa, index, hwpt) {
			if (!pasid_valid(hwpt->pasid)) {
				continue;
			}
			iommufd_device_pasid_detach(vidxd->idev, hwpt->pasid);
			kfree(hwpt);
		}
		ioasid_put(NULL, vidxd->pasid);
		xa_destroy(&vidxd->pasid_xa);
		iommufd_device_unbind(vidxd->idev);
		vidxd->idev = NULL;
	}
	mutex_unlock(&vidxd->dev_lock);
}

static int idxd_vdcm_pasid_attach(struct vdcm_idxd *vidxd, ioasid_t pasid, u32 *pt_id)
{
	struct vdcm_hwpt *hwpt, *tmp;
	int ret;

	hwpt = xa_load(&vidxd->pasid_xa, pasid);
	if (!hwpt) {
		hwpt = kzalloc(sizeof(*hwpt), GFP_KERNEL);
		if (!hwpt)
			return -ENOMEM;

		ret = iommufd_device_pasid_attach(vidxd->idev, pasid, *pt_id);
		if (ret)
			goto out_free;

		hwpt->pasid = pasid;
		tmp = xa_store(&vidxd->pasid_xa, hwpt->pasid, hwpt, GFP_KERNEL);
		if (IS_ERR(tmp)) {
			ret = PTR_ERR(tmp);
			goto out_detach;
		}
	} else {
		ret = iommufd_device_pasid_replace(vidxd->idev, pasid, *pt_id);
		return ret;
	}

	hwpt->hwpt_id = *pt_id;
	return 0;
out_detach:
	iommufd_device_pasid_detach(vidxd->idev, pasid);
out_free:
	kfree(hwpt);
	return ret;
}

static int idxd_vdcm_attach_ioas(struct vfio_device *vdev,
				 u32 *pt_id)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	u32 pasid;
	int rc = 0;

	mutex_lock(&vidxd->dev_lock);

	if (!vidxd->idev) {
		rc = -EINVAL;
		goto out_unlock;
	}

	pasid = vidxd->pasid;
	if (pasid == IOMMU_PASID_INVALID) {
		rc = -ENODEV;
		goto out_unlock;
	}

	rc = idxd_vdcm_pasid_attach(vidxd, pasid, pt_id);
	if (rc)
		goto out_unlock;
out_unlock:
	mutex_unlock(&vidxd->dev_lock);
	return rc;
}

static void idxd_vdcm_detach_ioas(struct vfio_device *vdev)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	struct vdcm_hwpt *hwpt;
	u32 pasid;

	mutex_lock(&vidxd->dev_lock);

	if (!vidxd->idev) {
		goto out_unlock;
	}

	pasid = vidxd->pasid;
	if (!pasid_valid(pasid)) {
		goto out_unlock;
	}

	hwpt = xa_load(&vidxd->pasid_xa, pasid);
	if (!hwpt) {
		goto out_unlock;
	}

	xa_erase(&vidxd->pasid_xa, pasid);
	kfree(hwpt);
	iommufd_device_pasid_detach(vidxd->idev, pasid);

out_unlock:
	mutex_unlock(&vidxd->dev_lock);
	return;
}

static ioasid_t idxd_vdcm_get_pasid(struct vdcm_idxd *vidxd,
                                    ioasid_t pasid)
{
	if (pasid_valid(pasid))
		return pasid;

	return vidxd->pasid;
}

static int idxd_vdcm_pasid_attach_ioas(struct vfio_device *vdev,
				       u32 pasid, u32 pt_id)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	int rc = 0;

	mutex_lock(&vidxd->dev_lock);

	if (!vidxd->idev) {
		rc = -EINVAL;
		goto out_unlock;
	}

	pasid = idxd_vdcm_get_pasid(vidxd, pasid);
	if (!pasid_valid(pasid)) {
		rc = -EINVAL;
		goto out_unlock;
	}

	rc = idxd_vdcm_pasid_attach(vidxd, pasid, &pt_id);
	if (rc)
		goto out_unlock;
out_unlock:
	mutex_unlock(&vidxd->dev_lock);
	return rc;
}

static void idxd_vdcm_pasid_detach_ioas(struct vfio_device *vdev, u32 pasid)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	struct vdcm_hwpt *hwpt;

	mutex_lock(&vidxd->dev_lock);

	if (!vidxd->idev) {
		goto out_unlock;
	}

	pasid = idxd_vdcm_get_pasid(vidxd, pasid);
	if (!pasid_valid(pasid)) {
		goto out_unlock;
	}

	hwpt = xa_load(&vidxd->pasid_xa, pasid);
	if (!hwpt) {
		goto out_unlock;
	}

	xa_erase(&vidxd->pasid_xa, pasid);
	kfree(hwpt);
	iommufd_device_pasid_detach(vidxd->idev, pasid);

out_unlock:
	mutex_unlock(&vidxd->dev_lock);
	return;
}

static ssize_t idxd_vdcm_rw(struct vfio_device *vdev, char *buf, size_t count,
			    loff_t *ppos, int mode)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	struct device *dev = vdev->dev;
	int rc = -EINVAL;

	if (index >= VFIO_PCI_NUM_REGIONS) {
		dev_err(dev, "invalid index: %u\n", index);
		return -EINVAL;
	}

	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		if (mode == IDXD_VDCM_WRITE)
			rc = vidxd_cfg_write(vidxd, pos, buf, count);
		else
			rc = vidxd_cfg_read(vidxd, pos, buf, count);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR1_REGION_INDEX:
		if (mode == IDXD_VDCM_WRITE)
			rc = vidxd_mmio_write(vidxd, vidxd->bar_val[0] + pos, buf, count);
		else
			rc = vidxd_mmio_read(vidxd, vidxd->bar_val[0] + pos, buf, count);
		break;
	case VFIO_PCI_BAR2_REGION_INDEX:
	case VFIO_PCI_BAR3_REGION_INDEX:
		if (mode == IDXD_VDCM_WRITE) {
			rc = vidxd_portal_mmio_write(vidxd,
				vidxd->bar_val[1] + pos, buf, count);
		} else {
			rc = vidxd_portal_mmio_read(vidxd,
				vidxd->bar_val[1] + pos, buf, count);
		}
		break;

	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
	case VFIO_PCI_VGA_REGION_INDEX:
	case VFIO_PCI_ROM_REGION_INDEX:
	default:
		dev_err(dev, "unsupported region: %u\n", index);
	}

	return rc == 0 ? count : rc;
}

static ssize_t idxd_vdcm_read(struct vfio_device *vdev, char __user *buf, size_t count,
			      loff_t *ppos)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	unsigned int done = 0;
	int rc;

	mutex_lock(&vidxd->dev_lock);
	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			rc = idxd_vdcm_rw(vdev, (char *)&val, sizeof(val),
					  ppos, IDXD_VDCM_READ);
			if (rc <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			rc = idxd_vdcm_rw(vdev, (char *)&val, sizeof(val),
					  ppos, IDXD_VDCM_READ);
			if (rc <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 2;
		} else {
			u8 val;

			rc = idxd_vdcm_rw(vdev, &val, sizeof(val), ppos,
					  IDXD_VDCM_READ);
			if (rc <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	mutex_unlock(&vidxd->dev_lock);
	return done;

 read_err:
	mutex_unlock(&vidxd->dev_lock);
	return -EFAULT;
}

static ssize_t idxd_vdcm_write(struct vfio_device *vdev, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	unsigned int done = 0;
	int rc;

	mutex_lock(&vidxd->dev_lock);
	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = idxd_vdcm_rw(vdev, (char *)&val, sizeof(val),
					  ppos, IDXD_VDCM_WRITE);
			if (rc <= 0)
				goto write_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = idxd_vdcm_rw(vdev, (char *)&val,
					  sizeof(val), ppos, IDXD_VDCM_WRITE);
			if (rc <= 0)
				goto write_err;

			filled = 2;
		} else {
			u8 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = idxd_vdcm_rw(vdev, &val, sizeof(val),
					  ppos, IDXD_VDCM_WRITE);
			if (rc <= 0)
				goto write_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	mutex_unlock(&vidxd->dev_lock);
	return done;

write_err:
	mutex_unlock(&vidxd->dev_lock);
	return -EFAULT;
}

static int idxd_vdcm_mmap(struct vfio_device *vdev, struct vm_area_struct *vma)
{
	unsigned int wq_idx;
	unsigned long req_size, pgoff = 0, offset;
	pgprot_t pg_prot;
	struct vdcm_idxd *vidxd = container_of(vdev, struct vdcm_idxd, vdev);
	struct idxd_wq *wq = vidxd->wq;
	struct idxd_device *idxd = vidxd->idxd;
	enum idxd_portal_prot virt_portal, phys_portal;
	phys_addr_t base = pci_resource_start(idxd->pdev, IDXD_WQ_BAR);
	struct device *dev = vidxd_dev(vidxd);

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	pg_prot = vma->vm_page_prot;
	req_size = vma->vm_end - vma->vm_start;
	if (req_size > PAGE_SIZE)
		return -EINVAL;

	vm_flags_set(vma, VM_DONTCOPY);

	offset = (vma->vm_pgoff << PAGE_SHIFT) &
		 ((1ULL << VFIO_PCI_OFFSET_SHIFT) - 1);

	wq_idx = offset >> (PAGE_SHIFT + 2);
	if (wq_idx >= 1) {
		dev_err(dev, "mapping invalid wq %d off %lx\n",
			wq_idx, offset);
		return -EINVAL;
	}

	/*
	 * Check and see if the guest wants to map to the limited or unlimited portal.
	 * The driver will allow mapping to unlimited portal only if the wq is a
	 * dedicated wq. Otherwise, it goes to limited.
	 */
	virt_portal = ((offset >> PAGE_SHIFT) & 0x3) == 1;
	phys_portal = IDXD_PORTAL_LIMITED;
	if (virt_portal == IDXD_PORTAL_UNLIMITED && wq_dedicated(wq))
		phys_portal = IDXD_PORTAL_UNLIMITED;

	/* We always map IMS portals to the guest */
	pgoff = (base + idxd_get_wq_portal_offset(wq->id, phys_portal,
						  IDXD_IRQ_IMS)) >> PAGE_SHIFT;

	dev_dbg(dev, "mmap %lx %lx %lx %lx\n", vma->vm_start, pgoff, req_size,
		pgprot_val(pg_prot));
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = pgoff;

	return remap_pfn_range(vma, vma->vm_start, pgoff, req_size, pg_prot);
}

static int idxd_vdcm_ioctl_device_get_info(struct vfio_device *vdev, unsigned long arg)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	struct vfio_device_info info;
	unsigned long minsz;
	int rc = 0;

	mutex_lock(&vidxd->dev_lock);
	minsz = offsetofend(struct vfio_device_info, num_irqs);

	if (copy_from_user(&info, (void __user *)arg, minsz)) {
		rc = -EFAULT;
		goto out;
	}

	if (info.argsz < minsz) {
		rc = -EINVAL;
		goto out;
	}

	info.flags = VFIO_DEVICE_FLAGS_PCI;
	info.flags |= VFIO_DEVICE_FLAGS_RESET;
	info.num_regions = VFIO_PCI_NUM_REGIONS;
	info.num_irqs = VFIO_PCI_NUM_IRQS;

	if (copy_to_user((void __user *)arg, &info, minsz))
		rc = -EFAULT;

out:
	mutex_unlock(&vidxd->dev_lock);
	return rc;
}

static int idxd_vdcm_ioctl_device_get_region_info(struct vfio_device *vdev,
						  unsigned long arg)
{
	struct device *dev = vdev->dev;
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	struct vfio_region_info info;
	struct vfio_info_cap caps = { .buf = NULL, .size = 0 };
	struct vfio_region_info_cap_sparse_mmap *sparse = NULL;
	size_t size;
	int nr_areas = 1;
	int cap_type_id = 0;
	unsigned long minsz;
	int rc = 0;

	mutex_lock(&vidxd->dev_lock);
	minsz = offsetofend(struct vfio_region_info, offset);

	if (copy_from_user(&info, (void __user *)arg, minsz)) {
		rc = -EFAULT;
		goto out;
	}

	if (info.argsz < minsz) {
		rc = -EINVAL;
		goto out;
	}

	switch (info.index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
		info.size = VIDXD_MAX_CFG_SPACE_SZ;
		info.flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
		info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
		info.size = vidxd->bar_size[info.index];
		if (!info.size) {
			info.flags = 0;
			break;
		}

		info.flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
		break;
	case VFIO_PCI_BAR1_REGION_INDEX:
		info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
		info.size = 0;
		info.flags = 0;
		break;
	case VFIO_PCI_BAR2_REGION_INDEX:
		info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
		info.flags = VFIO_REGION_INFO_FLAG_CAPS | VFIO_REGION_INFO_FLAG_MMAP |
			     VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE |
			     VFIO_REGION_INFO_FLAG_DYNAMIC_TRAP;
		info.size = vidxd->bar_size[1];

		/*
		 * Every WQ has two areas for unlimited and limited
		 * MSI-X portals. IMS portals are not reported
		 */
		nr_areas = 2;

		size = sizeof(*sparse) + (nr_areas * sizeof(*sparse->areas));
		sparse = kzalloc(size, GFP_KERNEL);
		if (!sparse) {
			rc = -ENOMEM;
			goto out;
		}

		sparse->header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
		sparse->header.version = 1;
		sparse->nr_areas = nr_areas;
		cap_type_id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;

		/* Unlimited portal */
		sparse->areas[0].offset = 0;
		sparse->areas[0].size = PAGE_SIZE;

		/* Limited portal */
		sparse->areas[1].offset = PAGE_SIZE;
		sparse->areas[1].size = PAGE_SIZE;
		break;

	case VFIO_PCI_BAR3_REGION_INDEX ... VFIO_PCI_BAR5_REGION_INDEX:
		info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
		info.size = 0;
		info.flags = 0;
		dev_dbg(dev, "get region info bar:%d\n", info.index);
		break;

	case VFIO_PCI_ROM_REGION_INDEX:
	case VFIO_PCI_VGA_REGION_INDEX:
		dev_dbg(dev, "get region info index:%d\n", info.index);
		break;
	default:
		if (info.index >= VFIO_PCI_NUM_REGIONS)
			rc = -EINVAL;
		else
			rc = 0;
		goto out;
	} /* info.index switch */

	if ((info.flags & VFIO_REGION_INFO_FLAG_CAPS) && sparse) {
		if (cap_type_id == VFIO_REGION_INFO_CAP_SPARSE_MMAP) {
			rc = vfio_info_add_capability(&caps, &sparse->header,
						      sizeof(*sparse) + (sparse->nr_areas *
						      sizeof(*sparse->areas)));
			kfree(sparse);
			if (rc)
				goto out;
		}
	}

	if (caps.size) {
		if (info.argsz < sizeof(info) + caps.size) {
			info.argsz = sizeof(info) + caps.size;
			info.cap_offset = 0;
		} else {
			vfio_info_cap_shift(&caps, sizeof(info));
			if (copy_to_user((void __user *)arg + sizeof(info),
					 caps.buf, caps.size)) {
				kfree(caps.buf);
				rc = -EFAULT;
				goto out;
			}
			info.cap_offset = sizeof(info);
		}

		kfree(caps.buf);
	}

	if (copy_to_user((void __user *)arg, &info, minsz))
		rc = -EFAULT;

out:
	mutex_unlock(&vidxd->dev_lock);
	return rc;
}

static int idxd_vdcm_get_irq_count(struct vfio_device *vdev, int type)
{
	if (type == VFIO_PCI_MSIX_IRQ_INDEX)
		return VIDXD_MAX_MSIX_VECS;
	else if (type == VFIO_PCI_REQ_IRQ_INDEX)
		return 1;

	return 0;
}

static int idxd_vdcm_ioctl_device_get_irq_info(struct vfio_device *vdev, unsigned long arg)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	struct vfio_irq_info info;
	unsigned long minsz;
	int rc = 0;

	mutex_lock(&vidxd->dev_lock);
	minsz = offsetofend(struct vfio_irq_info, count);

	if (copy_from_user(&info, (void __user *)arg, minsz)) {
		rc = -EFAULT;
		goto out;
	}

	if (info.argsz < minsz || info.index >= VFIO_PCI_NUM_IRQS) {
		rc = -EINVAL;
		goto out;
	}

	info.flags = VFIO_IRQ_INFO_EVENTFD;

	switch (info.index) {
	case VFIO_PCI_MSIX_IRQ_INDEX:
	case VFIO_PCI_REQ_IRQ_INDEX:
		info.flags |= VFIO_IRQ_INFO_NORESIZE;
		break;
	default:
		rc = -EINVAL;
		goto out;
	} /* switch(info.index) */

	info.flags = VFIO_IRQ_INFO_EVENTFD | VFIO_IRQ_INFO_NORESIZE;
	info.count = idxd_vdcm_get_irq_count(vdev, info.index);

	if (copy_to_user((void __user *)arg, &info, minsz))
		rc = -EFAULT;

out:
	mutex_unlock(&vidxd->dev_lock);
	return rc;
}

static int idxd_vdcm_ioctl_device_set_irqs(struct vfio_device *vdev, unsigned long arg)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	struct vfio_irq_set hdr;
	u8 *data = NULL;
	size_t data_size = 0;
	unsigned long minsz;
	int rc = 0;

	mutex_lock(&vidxd->dev_lock);
	minsz = offsetofend(struct vfio_irq_set, count);

	if (copy_from_user(&hdr, (void __user *)arg, minsz)) {
		rc = -EFAULT;
		goto out;
	}

	if (!(hdr.flags & VFIO_IRQ_SET_DATA_NONE)) {
		int max = idxd_vdcm_get_irq_count(vdev, hdr.index);

		rc = vfio_set_irqs_validate_and_prepare(&hdr, max, VFIO_PCI_NUM_IRQS,
							&data_size);
		if (rc) {
			rc = -EINVAL;
			goto out;
		}

		if (data_size) {
			data = memdup_user((void __user *)(arg + minsz), data_size);
			if (IS_ERR(data)) {
				rc = PTR_ERR(data);
				goto out;
			}
		}
	}

	if (!data) {
		rc = -EINVAL;
		goto out;
	}

	rc = idxd_vdcm_set_irqs(vidxd, hdr.flags, hdr.index, hdr.start, hdr.count, data);
	kfree(data);

out:
	mutex_unlock(&vidxd->dev_lock);
	return rc;
}

static void vidxd_vdcm_ioctl_reset(struct vfio_device *vdev)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);

	mutex_lock(&vidxd->dev_lock);
	vidxd_init(vidxd);
	mutex_unlock(&vidxd->dev_lock);
}

static long idxd_vdcm_ioctl(struct vfio_device *vdev, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
		return idxd_vdcm_ioctl_device_get_info(vdev, arg);
	case VFIO_DEVICE_GET_REGION_INFO:
		return idxd_vdcm_ioctl_device_get_region_info(vdev, arg);
	case VFIO_DEVICE_GET_IRQ_INFO:
		return idxd_vdcm_ioctl_device_get_irq_info(vdev, arg);
	case VFIO_DEVICE_SET_IRQS:
		return idxd_vdcm_ioctl_device_set_irqs(vdev, arg);
	case VFIO_DEVICE_RESET:
		vidxd_vdcm_ioctl_reset(vdev);
		return 0;
	};

	return -EINVAL;
}

static void idxd_vdcm_request(struct vfio_device *vdev, unsigned int count)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);

	mutex_lock(&vidxd->dev_lock);

	if (vidxd->req_trigger) {
		if (!(count % 10))
			dev_warn_ratelimited(vdev->dev,
					     "Relaying device request to user (#%u)\n",
					     count);
		eventfd_signal(vidxd->req_trigger, 1);
	} else if (count == 0) {
		dev_warn(vdev->dev,
			 "No device request channel registered, blocked until released by user\n");
	}

	mutex_unlock(&vidxd->dev_lock);
}

#if 0
/* return 0 on VM acc device ready, -ETIMEDOUT hardware timeout */
static int qm_wait_dev_not_ready(struct hisi_qm *qm)
{
	u32 val;

	return readl_relaxed_poll_timeout(qm->io_base + QM_VF_STATE,
				val, !(val & 0x1), MB_POLL_PERIOD_US,
				MB_POLL_TIMEOUT_US);
}

/*
 * Each state Reg is checked 100 times,
 * with a delay of 100 microseconds after each check
 */
static u32 qm_check_reg_state(struct hisi_qm *qm, u32 regs)
{
	int check_times = 0;
	u32 state;

	state = readl(qm->io_base + regs);
	while (state && check_times < ERROR_CHECK_TIMEOUT) {
		udelay(CHECK_DELAY_TIME);
		state = readl(qm->io_base + regs);
		check_times++;
	}

	return state;
}

static int qm_read_regs(struct hisi_qm *qm, u32 reg_addr,
			u32 *data, u8 nums)
{
	int i;

	if (nums < 1 || nums > QM_REGS_MAX_LEN)
		return -EINVAL;

	for (i = 0; i < nums; i++) {
		data[i] = readl(qm->io_base + reg_addr);
		reg_addr += QM_REG_ADDR_OFFSET;
	}

	return 0;
}

static int qm_write_regs(struct hisi_qm *qm, u32 reg,
			 u32 *data, u8 nums)
{
	int i;

	if (nums < 1 || nums > QM_REGS_MAX_LEN)
		return -EINVAL;

	for (i = 0; i < nums; i++)
		writel(data[i], qm->io_base + reg + i * QM_REG_ADDR_OFFSET);

	return 0;
}

static int qm_get_vft(struct hisi_qm *qm, u32 *base)
{
	u64 sqc_vft;
	u32 qp_num;
	int ret;

	ret = hisi_qm_mb(qm, QM_MB_CMD_SQC_VFT_V2, 0, 0, 1);
	if (ret)
		return ret;

	sqc_vft = readl(qm->io_base + QM_MB_CMD_DATA_ADDR_L) |
		  ((u64)readl(qm->io_base + QM_MB_CMD_DATA_ADDR_H) <<
		  QM_XQC_ADDR_OFFSET);
	*base = QM_SQC_VFT_BASE_MASK_V2 & (sqc_vft >> QM_SQC_VFT_BASE_SHIFT_V2);
	qp_num = (QM_SQC_VFT_NUM_MASK_V2 &
		  (sqc_vft >> QM_SQC_VFT_NUM_SHIFT_V2)) + 1;

	return qp_num;
}

static int qm_get_sqc(struct hisi_qm *qm, u64 *addr)
{
	int ret;

	ret = hisi_qm_mb(qm, QM_MB_CMD_SQC_BT, 0, 0, 1);
	if (ret)
		return ret;

	*addr = readl(qm->io_base + QM_MB_CMD_DATA_ADDR_L) |
		  ((u64)readl(qm->io_base + QM_MB_CMD_DATA_ADDR_H) <<
		  QM_XQC_ADDR_OFFSET);

	return 0;
}

static int qm_get_cqc(struct hisi_qm *qm, u64 *addr)
{
	int ret;

	ret = hisi_qm_mb(qm, QM_MB_CMD_CQC_BT, 0, 0, 1);
	if (ret)
		return ret;

	*addr = readl(qm->io_base + QM_MB_CMD_DATA_ADDR_L) |
		  ((u64)readl(qm->io_base + QM_MB_CMD_DATA_ADDR_H) <<
		  QM_XQC_ADDR_OFFSET);

	return 0;
}

static int qm_get_regs(struct hisi_qm *qm, struct acc_vf_data *vf_data)
{
	struct device *dev = &qm->pdev->dev;
	int ret;

	ret = qm_read_regs(qm, QM_VF_AEQ_INT_MASK, &vf_data->aeq_int_mask, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_VF_AEQ_INT_MASK\n");
		return ret;
	}

	ret = qm_read_regs(qm, QM_VF_EQ_INT_MASK, &vf_data->eq_int_mask, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_VF_EQ_INT_MASK\n");
		return ret;
	}

	ret = qm_read_regs(qm, QM_IFC_INT_SOURCE_V,
			   &vf_data->ifc_int_source, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_IFC_INT_SOURCE_V\n");
		return ret;
	}

	ret = qm_read_regs(qm, QM_IFC_INT_MASK, &vf_data->ifc_int_mask, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_IFC_INT_MASK\n");
		return ret;
	}

	ret = qm_read_regs(qm, QM_IFC_INT_SET_V, &vf_data->ifc_int_set, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_IFC_INT_SET_V\n");
		return ret;
	}

	ret = qm_read_regs(qm, QM_PAGE_SIZE, &vf_data->page_size, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_PAGE_SIZE\n");
		return ret;
	}

	/* QM_EQC_DW has 7 regs */
	ret = qm_read_regs(qm, QM_EQC_DW0, vf_data->qm_eqc_dw, 7);
	if (ret) {
		dev_err(dev, "failed to read QM_EQC_DW\n");
		return ret;
	}

	/* QM_AEQC_DW has 7 regs */
	ret = qm_read_regs(qm, QM_AEQC_DW0, vf_data->qm_aeqc_dw, 7);
	if (ret) {
		dev_err(dev, "failed to read QM_AEQC_DW\n");
		return ret;
	}

	return 0;
}

static int qm_set_regs(struct hisi_qm *qm, struct acc_vf_data *vf_data)
{
	struct device *dev = &qm->pdev->dev;
	int ret;

	/* check VF state */
	if (unlikely(hisi_qm_wait_mb_ready(qm))) {
		dev_err(&qm->pdev->dev, "QM device is not ready to write\n");
		return -EBUSY;
	}

	ret = qm_write_regs(qm, QM_VF_AEQ_INT_MASK, &vf_data->aeq_int_mask, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_VF_AEQ_INT_MASK\n");
		return ret;
	}

	ret = qm_write_regs(qm, QM_VF_EQ_INT_MASK, &vf_data->eq_int_mask, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_VF_EQ_INT_MASK\n");
		return ret;
	}

	ret = qm_write_regs(qm, QM_IFC_INT_SOURCE_V,
			    &vf_data->ifc_int_source, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_IFC_INT_SOURCE_V\n");
		return ret;
	}

	ret = qm_write_regs(qm, QM_IFC_INT_MASK, &vf_data->ifc_int_mask, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_IFC_INT_MASK\n");
		return ret;
	}

	ret = qm_write_regs(qm, QM_IFC_INT_SET_V, &vf_data->ifc_int_set, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_IFC_INT_SET_V\n");
		return ret;
	}

	ret = qm_write_regs(qm, QM_QUE_ISO_CFG_V, &vf_data->que_iso_cfg, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_QUE_ISO_CFG_V\n");
		return ret;
	}

	ret = qm_write_regs(qm, QM_PAGE_SIZE, &vf_data->page_size, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_PAGE_SIZE\n");
		return ret;
	}

	/* QM_EQC_DW has 7 regs */
	ret = qm_write_regs(qm, QM_EQC_DW0, vf_data->qm_eqc_dw, 7);
	if (ret) {
		dev_err(dev, "failed to write QM_EQC_DW\n");
		return ret;
	}

	/* QM_AEQC_DW has 7 regs */
	ret = qm_write_regs(qm, QM_AEQC_DW0, vf_data->qm_aeqc_dw, 7);
	if (ret) {
		dev_err(dev, "failed to write QM_AEQC_DW\n");
		return ret;
	}

	return 0;
}

static void qm_db(struct hisi_qm *qm, u16 qn, u8 cmd,
		  u16 index, u8 priority)
{
	u64 doorbell;
	u64 dbase;
	u16 randata = 0;

	if (cmd == QM_DOORBELL_CMD_SQ || cmd == QM_DOORBELL_CMD_CQ)
		dbase = QM_DOORBELL_SQ_CQ_BASE_V2;
	else
		dbase = QM_DOORBELL_EQ_AEQ_BASE_V2;

	doorbell = qn | ((u64)cmd << QM_DB_CMD_SHIFT_V2) |
		   ((u64)randata << QM_DB_RAND_SHIFT_V2) |
		   ((u64)index << QM_DB_INDEX_SHIFT_V2)	 |
		   ((u64)priority << QM_DB_PRIORITY_SHIFT_V2);

	writeq(doorbell, qm->io_base + dbase);
}

static int pf_qm_get_qp_num(struct hisi_qm *qm, int vf_id, u32 *rbase)
{
	unsigned int val;
	u64 sqc_vft;
	u32 qp_num;
	int ret;

	ret = readl_relaxed_poll_timeout(qm->io_base + QM_VFT_CFG_RDY, val,
					 val & BIT(0), MB_POLL_PERIOD_US,
					 MB_POLL_TIMEOUT_US);
	if (ret)
		return ret;

	writel(0x1, qm->io_base + QM_VFT_CFG_OP_WR);
	/* 0 mean SQC VFT */
	writel(0x0, qm->io_base + QM_VFT_CFG_TYPE);
	writel(vf_id, qm->io_base + QM_VFT_CFG);

	writel(0x0, qm->io_base + QM_VFT_CFG_RDY);
	writel(0x1, qm->io_base + QM_VFT_CFG_OP_ENABLE);

	ret = readl_relaxed_poll_timeout(qm->io_base + QM_VFT_CFG_RDY, val,
					 val & BIT(0), MB_POLL_PERIOD_US,
					 MB_POLL_TIMEOUT_US);
	if (ret)
		return ret;

	sqc_vft = readl(qm->io_base + QM_VFT_CFG_DATA_L) |
		  ((u64)readl(qm->io_base + QM_VFT_CFG_DATA_H) <<
		  QM_XQC_ADDR_OFFSET);
	*rbase = QM_SQC_VFT_BASE_MASK_V2 &
		  (sqc_vft >> QM_SQC_VFT_BASE_SHIFT_V2);
	qp_num = (QM_SQC_VFT_NUM_MASK_V2 &
		  (sqc_vft >> QM_SQC_VFT_NUM_SHIFT_V2)) + 1;

	return qp_num;
}

static void qm_dev_cmd_init(struct hisi_qm *qm)
{
	/* Clear VF communication status registers. */
	writel(0x1, qm->io_base + QM_IFC_INT_SOURCE_V);

	/* Enable pf and vf communication. */
	writel(0x0, qm->io_base + QM_IFC_INT_MASK);
}

static int vf_qm_cache_wb(struct hisi_qm *qm)
{
	unsigned int val;

	writel(0x1, qm->io_base + QM_CACHE_WB_START);
	if (readl_relaxed_poll_timeout(qm->io_base + QM_CACHE_WB_DONE,
				       val, val & BIT(0), MB_POLL_PERIOD_US,
				       MB_POLL_TIMEOUT_US)) {
		dev_err(&qm->pdev->dev, "vf QM writeback sqc cache fail\n");
		return -EINVAL;
	}

	return 0;
}

static struct hisi_acc_vf_core_device *hssi_acc_drvdata(struct pci_dev *pdev)
{
	struct vfio_pci_core_device *core_device = dev_get_drvdata(&pdev->dev);

	return container_of(core_device, struct hisi_acc_vf_core_device,
			    core_device);
}

static void vf_qm_fun_reset(struct hisi_acc_vf_core_device *hisi_acc_vdev,
			    struct hisi_qm *qm)
{
	int i;

	for (i = 0; i < qm->qp_num; i++)
		qm_db(qm, i, QM_DOORBELL_CMD_SQ, 0, 1);
}

static int vf_qm_func_stop(struct hisi_qm *qm)
{
	return hisi_qm_mb(qm, QM_MB_CMD_PAUSE_QM, 0, 0, 0);
}

static int vf_qm_check_match(struct hisi_acc_vf_core_device *hisi_acc_vdev,
			     struct hisi_acc_vf_migration_file *migf)
{
	struct acc_vf_data *vf_data = &migf->vf_data;
	struct hisi_qm *vf_qm = &hisi_acc_vdev->vf_qm;
	struct hisi_qm *pf_qm = hisi_acc_vdev->pf_qm;
	struct device *dev = &vf_qm->pdev->dev;
	u32 que_iso_state;
	int ret;

	if (migf->total_length < QM_MATCH_SIZE)
		return -EINVAL;

	if (vf_data->acc_magic != ACC_DEV_MAGIC) {
		dev_err(dev, "failed to match ACC_DEV_MAGIC\n");
		return -EINVAL;
	}

	if (vf_data->dev_id != hisi_acc_vdev->vf_dev->device) {
		dev_err(dev, "failed to match VF devices\n");
		return -EINVAL;
	}

	/* vf qp num check */
	ret = qm_get_vft(vf_qm, &vf_qm->qp_base);
	if (ret <= 0) {
		dev_err(dev, "failed to get vft qp nums\n");
		return -EINVAL;
	}

	if (ret != vf_data->qp_num) {
		dev_err(dev, "failed to match VF qp num\n");
		return -EINVAL;
	}

	vf_qm->qp_num = ret;

	/* vf isolation state check */
	ret = qm_read_regs(pf_qm, QM_QUE_ISO_CFG_V, &que_iso_state, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_QUE_ISO_CFG_V\n");
		return ret;
	}

	if (vf_data->que_iso_cfg != que_iso_state) {
		dev_err(dev, "failed to match isolation state\n");
		return ret;
	}

	ret = qm_write_regs(vf_qm, QM_VF_STATE, &vf_data->vf_qm_state, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_VF_STATE\n");
		return ret;
	}

	hisi_acc_vdev->vf_qm_state = vf_data->vf_qm_state;
	return 0;
}

static int vf_qm_get_match_data(struct hisi_acc_vf_core_device *hisi_acc_vdev,
				struct acc_vf_data *vf_data)
{
	struct hisi_qm *pf_qm = hisi_acc_vdev->pf_qm;
	struct device *dev = &pf_qm->pdev->dev;
	int vf_id = hisi_acc_vdev->vf_id;
	int ret;

	vf_data->acc_magic = ACC_DEV_MAGIC;
	/* save device id */
	vf_data->dev_id = hisi_acc_vdev->vf_dev->device;

	/* vf qp num save from PF */
	ret = pf_qm_get_qp_num(pf_qm, vf_id, &vf_data->qp_base);
	if (ret <= 0) {
		dev_err(dev, "failed to get vft qp nums!\n");
		return -EINVAL;
	}

	vf_data->qp_num = ret;

	/* VF isolation state save from PF */
	ret = qm_read_regs(pf_qm, QM_QUE_ISO_CFG_V, &vf_data->que_iso_cfg, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_QUE_ISO_CFG_V!\n");
		return ret;
	}

	return 0;
}

#endif

static int vidxd_resume_wq_state(struct vdcm_idxd *vidxd)
{
	struct idxd_device *idxd = vidxd->idxd;
	struct device *dev = vidxd_dev(vidxd);
	union wqcfg *vwqcfg, *wqcfg;
	struct idxd_wq *wq;
	int wq_id, rc = 0;
	bool priv;
	u8 *bar0 = vidxd->bar0;

	dev_dbg(dev, "%s:%d numwqs %d\n", __func__, __LINE__, vidxd->num_wqs);
	/* TODO: Currently support for only 1 WQ per VDEV */
	for (wq_id = 0; wq_id < vidxd->num_wqs; wq_id++) {
		wq = vidxd->wq;
		dev_dbg(dev, "%s:%d wq %px\n", __func__, __LINE__, wq);
		vwqcfg = (union wqcfg *)(bar0 + VIDXD_WQCFG_OFFSET);
		wqcfg = wq->wqcfg;

		if (vidxd_state(vidxd) != 1 || vwqcfg->wq_state != 1) {
			/* either VDEV or vWQ is disabled */
			if (wq_dedicated(wq) && wq->state == IDXD_WQ_ENABLED)
				idxd_wq_disable(wq, false);
			continue;
		} else {
			unsigned long flags;
			printk("vidxd re-enable wq %u:%u\n", wq_id, wq->id);

			/* If dedicated WQ and PASID is not enabled, program
			 * the default PASID in the WQ PASID register */
			if (wq_dedicated(wq) && vwqcfg->mode_support) {
				int wq_pasid = -1, gpasid = -1;

				if (vwqcfg->pasid_en) {
					gpasid = vwqcfg->pasid;
					priv = vwqcfg->priv;
					rc = vidxd_get_host_pasid(dev,
								  gpasid,
								  &wq_pasid);
				} else {
					wq_pasid = vfio_device_get_pasid(&vidxd->vdev);
					priv = true;
				}

				if (wq_pasid >= 0) {
					wqcfg->bits[WQCFG_PASID_IDX] &=
								~GENMASK(29, 8);
					wqcfg->priv = priv;
					wqcfg->pasid_en = 1;
					wqcfg->pasid = wq_pasid;
					dev_dbg(dev, "pasid %d:%d in wq %d\n",
						gpasid, wq_pasid, wq->id);
					spin_lock_irqsave(&idxd->dev_lock,
									flags);
					idxd_wq_setup_pasid(wq, wq_pasid);
					idxd_wq_setup_priv(wq, priv);
					spin_unlock_irqrestore(&idxd->dev_lock,
									flags);
					rc = idxd_wq_enable(wq);
					if (rc) {
						dev_err(dev, "resume wq failed\n");
						break;;
					}
				}
			} else if (!wq_dedicated(wq) && vwqcfg->mode_support) {
				wqcfg->bits[WQCFG_PASID_IDX] &= ~GENMASK(29, 8);
				wqcfg->pasid_en = 1;
				wqcfg->mode = 0;
				spin_lock_irqsave(&idxd->dev_lock, flags);
				idxd_wq_setup_pasid(wq, 0);
				spin_unlock_irqrestore(&idxd->dev_lock, flags);
				rc = idxd_wq_enable(wq);
				if (rc) {
					dev_err(dev, "resume wq %d failed\n",
							wq->id);
					break;
				}
			}
		}
	}
	return rc;
}

static void vidxd_dest_load_state(struct vdcm_idxd *vidxd)
{
	struct vidxd_migration_file *migf = vidxd->resuming_migf;
	struct vidxd_data *vidxd_data = &migf->vidxd_data;

	pr_info("%s, data_size: %lx\n", __func__, migf->total_length);

	/* restore the state data to device */
	memcpy(vidxd->cfg, vidxd_data->cfg, sizeof(vidxd->cfg));
	memcpy((u8 *)vidxd->bar_val, vidxd_data->bar_val, sizeof(vidxd->bar_val));
	memcpy((u8 *)vidxd->bar_size, vidxd_data->bar_size,
	       sizeof(vidxd->bar_size));
	memcpy((u8 *)vidxd->bar0, vidxd_data->bar0, sizeof(vidxd->bar0));
	//memcpy((u8 *)ims, data_ptr + offset, sizeof(vidxd->ims));
	//offset += sizeof(vidxd->ims);
}

static int
vidxd_resume_ims_state(struct vdcm_idxd *vidxd, bool *int_handle_revoked)
{
	struct vidxd_migration_file *migf = vidxd->resuming_migf;
	struct vidxd_data *vidxd_data = &migf->vidxd_data;
	struct device *dev = &vidxd->vdev.device;
//	struct vfio_pci_ims *ims = &vidxd->vdev.ims;
	u8 *bar0 = vidxd->bar0;
	int i, rc = 0;
	struct idxd_device *idxd = vidxd->wq->idxd;

	/* Restore int handle info */
	for (i = 1; i < 2; i++) {
		u32 revoked_handle, perm_val, gpasid, pasid;
		int ims_idx = vfio_pci_ims_hwirq(&vidxd->vdev, i);
		int irq = vfio_ims_msi_virq(&vidxd->vdev, i);
		bool paside;

		if (irq < 0)
			continue;

		memcpy((u8 *)&revoked_handle, &vidxd_data->ims_idx[i],
		       sizeof(revoked_handle));

		pr_info("%s: %d new handle %x old handle %x\n",
			__func__, i, ims_idx, revoked_handle);

		if (revoked_handle != ims_idx) {
			/* Int Handle Revoked */
			*int_handle_revoked = true;
		}

		perm_val = *(u32 *)(bar0 + VIDXD_MSIX_PERM_OFFSET + i * 8);

		paside = (perm_val >> 3) & 1;
		gpasid = (perm_val >> 12) & 0xfffff;

		if (paside) {
			rc = vidxd_get_host_pasid(dev, gpasid, &pasid);
			if (rc < 0)
				return rc;

			dev_dbg(dev, "guest pasid enabled, translate gpasid: %d to pasid %d\n",
				gpasid, pasid);
		} else {
			pasid = vfio_device_get_pasid(&vidxd->vdev);
                        if (pasid == IOMMU_PASID_INVALID)
				return -ENODEV;

			dev_dbg(dev, "guest pasid disabled, using default host pasid: %u\n",
				pasid);
		}

// FIXME
#if 0
		auxval = ims_ctrl_pasid_aux(pasid, true);

		rc = irq_set_auxdata(irq, IMS_AUXDATA_CONTROL_WORD, auxval);
		pr_info("%s: auxval %x rc %d\n", __func__, auxval, rc);
		if (rc < 0) {
			pr_info("set ims pasid %d failed rc %d\n", pasid, rc);
			break;
		}
#endif
		idxd_ims_set_pasid(&idxd->pdev->dev, irq, pasid);
	}

	return rc;
}

static int vidxd_resubmit_pending_descs (struct vdcm_idxd *vidxd)
{
	struct vidxd_migration_file *migf = vidxd->resuming_migf;
	struct vidxd_data *vidxd_data = &migf->vidxd_data;
	struct idxd_virtual_wq *vwq;
	struct idxd_wq *wq;
	int i;

	/*
	 * Submit the queued descriptors. The WQ states
	 * have been resumed by this point
	 */
	for (i = 0; i < vidxd->num_wqs; i++) {
		struct idxd_wq_desc_elem el;
		void __iomem *portal;
		int j = 0;

		vwq = &vidxd->vwq[i];
		wq = vidxd->wq;

		memcpy((u8 *)&vwq->ndescs, &vidxd_data->ndescs[i],
		       sizeof(vwq->ndescs));

		for (; vwq->ndescs > 0; vwq->ndescs--) {
			memcpy((u8 *)&el, &vidxd_data->el[i][j++], sizeof(el));

			portal = vidxd->idxd->portal_base +
				idxd_get_wq_portal_offset(wq->id,
						el.portal_prot, IDXD_IRQ_IMS);
			portal += (el.portal_id << 6);

			pr_info("submitting desc[%d] to WQ %d:%d ded %d\n",
				j, i, wq->id, wq_dedicated(wq));
			if (wq_dedicated(wq)) {
				iosubmit_cmds512(portal, el.work_desc, 1);
			} else {
				struct dsa_hw_desc *hw =
					(struct dsa_hw_desc *)el.work_desc;
				int hpasid, gpasid = hw->pasid;
				struct device *dev = vidxd_dev(vidxd);
				int rc;

				/* Translate the gpasid in the descriptor */
				rc = vidxd_get_host_pasid(dev, gpasid, &hpasid);
				if (rc < 0) {
					pr_info("gpasid->hpasid trans failed\n");
					continue;
				}
				hw->pasid = hpasid;
				/* FIXME: Allow enqcmds to retry a few times
				 * before failing */
				rc = enqcmds(portal, el.work_desc);
				if (rc < 0) {
					pr_info("%s: enqcmds failed\n", __func__);
					continue;
				}
			}
		}
	}

	return 0;
}

static int idxd_vdcm_load_data(struct vdcm_idxd *vidxd)
{
	bool int_handle_revoked = false;
	int rc = 0;

	vidxd_dest_load_state(vidxd);

	rc = vidxd_resume_wq_state(vidxd);
	if (rc) {
		pr_info("vidxd resume wq state failed %d\n", rc);
		return rc;
	}

	rc = vidxd_resume_ims_state(vidxd, &int_handle_revoked);
	if (rc) {
		pr_info("vidxd int handle revocation handling failed %d\n", rc);

		return rc;
	}

	rc = vidxd_resubmit_pending_descs(vidxd);
	if (rc) {
		pr_info("vidxd pending descs handling failed %d\n", rc);
		return rc;
	}

	if (int_handle_revoked)
                vidxd_notify_revoked_handles(vidxd);

	return rc;
}

#if 0
static int vf_qm_load_data(struct hisi_acc_vf_core_device *hisi_acc_vdev,
			   struct hisi_acc_vf_migration_file *migf)
{
	struct hisi_qm *qm = &hisi_acc_vdev->vf_qm;
	struct device *dev = &qm->pdev->dev;
	struct acc_vf_data *vf_data = &migf->vf_data;
	int ret;

	/* Return if only match data was transferred */
	if (migf->total_length == QM_MATCH_SIZE)
		return 0;

	if (migf->total_length < sizeof(struct acc_vf_data))
		return -EINVAL;

	qm->eqe_dma = vf_data->eqe_dma;
	qm->aeqe_dma = vf_data->aeqe_dma;
	qm->sqc_dma = vf_data->sqc_dma;
	qm->cqc_dma = vf_data->cqc_dma;

	qm->qp_base = vf_data->qp_base;
	qm->qp_num = vf_data->qp_num;

	ret = qm_set_regs(qm, vf_data);
	if (ret) {
		dev_err(dev, "Set VF regs failed\n");
		return ret;
	}

	ret = hisi_qm_mb(qm, QM_MB_CMD_SQC_BT, qm->sqc_dma, 0, 0);
	if (ret) {
		dev_err(dev, "Set sqc failed\n");
		return ret;
	}

	ret = hisi_qm_mb(qm, QM_MB_CMD_CQC_BT, qm->cqc_dma, 0, 0);
	if (ret) {
		dev_err(dev, "Set cqc failed\n");
		return ret;
	}

	qm_dev_cmd_init(qm);
	return 0;
}
#endif

static void
vidxd_source_prepare_for_migration(struct vdcm_idxd *vidxd,
				   struct vidxd_migration_file *migf)
{
	struct vidxd_data *vidxd_data = &migf->vidxd_data;
	struct idxd_virtual_wq *vwq;
	int i;

	memcpy(vidxd_data->cfg, vidxd->cfg, sizeof(vidxd->cfg));
	memcpy(vidxd_data->bar_val, (u8 *)vidxd->bar_val,
	       sizeof(vidxd->bar_val));
	memcpy(vidxd_data->bar_size, (u8 *)vidxd->bar_size,
	       sizeof(vidxd->bar_size));
	memcpy(vidxd_data->bar0, (u8 *)vidxd->bar0, sizeof(vidxd->bar0));

	/* Save int handle info if MIS was set up. */
	for (i = 1; i < 2; i++) {
			u8 ims_idx = vfio_pci_ims_hwirq(&vidxd->vdev, i);
			int irq = vfio_ims_msi_virq(&vidxd->vdev, i);

			if (irq < 0)
				continue;

			/* Save the current handle in use */
			pr_info("Saving handle %d\n", ims_idx);
			memcpy(&vidxd_data->ims_idx[i], (u8 *)&ims_idx,
			       sizeof(ims_idx));
	}

        /* Save the queued descriptors */
        for (i = 0; i < vidxd->num_wqs; i++) {
                struct idxd_wq_desc_elem *el;
		int j = 0;

                vwq = &vidxd->vwq[i];

		/* FIXME: need to dynamic allocate vidxd_data based on ndesc. */
		WARN_ON(vwq->ndescs > VIDXD_MAX_PORTALS);

                memcpy(&vidxd_data->ndescs[i], (u8 *)&vwq->ndescs,
		       sizeof(vwq->ndescs));
                list_for_each_entry(el, &vwq->head, link) {
                        printk("Saving WQ[%d] descriptor[%d]\n", i, j);
                        memcpy(&vidxd_data->el[i][j++], (u8 *)el,
			       sizeof(*el));
                }
        }
}

static void idxd_vdcm_state_save(struct vdcm_idxd *vidxd,
				 struct vidxd_migration_file *migf)
{
	vidxd_source_prepare_for_migration(vidxd, migf);

	migf->total_length = sizeof(struct vidxd_data);
}

#if 0
/* Check the PF's RAS state and Function INT state */
static int
hisi_acc_check_int_state(struct hisi_acc_vf_core_device *hisi_acc_vdev)
{
	struct hisi_qm *vfqm = &hisi_acc_vdev->vf_qm;
	struct hisi_qm *qm = hisi_acc_vdev->pf_qm;
	struct pci_dev *vf_pdev = hisi_acc_vdev->vf_dev;
	struct device *dev = &qm->pdev->dev;
	u32 state;

	/* Check RAS state */
	state = qm_check_reg_state(qm, QM_ABNORMAL_INT_STATUS);
	if (state) {
		dev_err(dev, "failed to check QM RAS state!\n");
		return -EBUSY;
	}

	/* Check Function Communication state between PF and VF */
	state = qm_check_reg_state(vfqm, QM_IFC_INT_STATUS);
	if (state) {
		dev_err(dev, "failed to check QM IFC INT state!\n");
		return -EBUSY;
	}
	state = qm_check_reg_state(vfqm, QM_IFC_INT_SET_V);
	if (state) {
		dev_err(dev, "failed to check QM IFC INT SET state!\n");
		return -EBUSY;
	}

	/* Check submodule task state */
	switch (vf_pdev->device) {
	case PCI_DEVICE_ID_HUAWEI_SEC_VF:
		state = qm_check_reg_state(qm, SEC_CORE_INT_STATUS);
		if (state) {
			dev_err(dev, "failed to check QM SEC Core INT state!\n");
			return -EBUSY;
		}
		return 0;
	case PCI_DEVICE_ID_HUAWEI_HPRE_VF:
		state = qm_check_reg_state(qm, HPRE_HAC_INT_STATUS);
		if (state) {
			dev_err(dev, "failed to check QM HPRE HAC INT state!\n");
			return -EBUSY;
		}
		return 0;
	case PCI_DEVICE_ID_HUAWEI_ZIP_VF:
		state = qm_check_reg_state(qm, HZIP_CORE_INT_STATUS);
		if (state) {
			dev_err(dev, "failed to check QM ZIP Core INT state!\n");
			return -EBUSY;
		}
		return 0;
	default:
		dev_err(dev, "failed to detect acc module type!\n");
		return -EINVAL;
	}
}
#endif

static void idxd_vdcm_disable_fd(struct vidxd_migration_file *migf)
{
	mutex_lock(&migf->lock);
	migf->disabled = true;
	migf->total_length = 0;
	migf->filp->f_pos = 0;
	mutex_unlock(&migf->lock);
}

static void idxd_vdcm_disable_fds(struct vdcm_idxd *vidxd)
{
	if (vidxd->resuming_migf) {
		idxd_vdcm_disable_fd(vidxd->resuming_migf);
		fput(vidxd->resuming_migf->filp);
		vidxd->resuming_migf = NULL;
	}

	if (vidxd->saving_migf) {
		idxd_vdcm_disable_fd(vidxd->saving_migf);
		fput(vidxd->saving_migf->filp);
		vidxd->saving_migf = NULL;
	}
}

#if 0
/*
 * This function is called in all state_mutex unlock cases to
 * handle a 'deferred_reset' if exists.
 */
static void
hisi_acc_vf_state_mutex_unlock(struct hisi_acc_vf_core_device *hisi_acc_vdev)
{
again:
	spin_lock(&hisi_acc_vdev->reset_lock);
	if (hisi_acc_vdev->deferred_reset) {
		hisi_acc_vdev->deferred_reset = false;
		spin_unlock(&hisi_acc_vdev->reset_lock);
		hisi_acc_vdev->vf_qm_state = QM_NOT_READY;
		hisi_acc_vdev->mig_state = VFIO_DEVICE_STATE_RUNNING;
		hisi_acc_vf_disable_fds(hisi_acc_vdev);
		goto again;
	}
	mutex_unlock(&hisi_acc_vdev->state_mutex);
	spin_unlock(&hisi_acc_vdev->reset_lock);
}

#endif

static void idxd_vdcm_start_device(struct vdcm_idxd *vidxd)
{
	/*
	 * The VMM may continue the VM after pausing it. So get ready
	 * for normal operation
	 */
	vidxd->paused = false;
}

static int idxd_vdcm_load_state(struct vdcm_idxd *vidxd)
{
	int ret;

	/* Recover data to VDEV and DEV */
	ret = idxd_vdcm_load_data(vidxd);
	if (ret) {
		struct device *dev = vidxd_dev(vidxd);

		dev_err(dev, "failed to recover the VDEV and DEV!\n");

		return ret;
	}

	return 0;
}

static int idxd_vdcm_release_file(struct inode *inode, struct file *filp)
{
	struct vidxd_migration_file *migf = filp->private_data;

	idxd_vdcm_disable_fd(migf);
	mutex_destroy(&migf->lock);
	kfree(migf);

	return 0;
}

static ssize_t idxd_vdcm_resume_write(struct file *filp, const char __user *buf,
				      size_t len, loff_t *pos)
{
	struct vidxd_migration_file *migf = filp->private_data;
	loff_t requested_length;
	ssize_t done = 0;
	int ret;

	if (pos)
		return -ESPIPE;
	pos = &filp->f_pos;

	if (*pos < 0 ||
	    check_add_overflow((loff_t)len, *pos, &requested_length))
		return -EINVAL;

	if (requested_length > sizeof(struct vidxd_data))
		return -ENOMEM;

	mutex_lock(&migf->lock);
	if (migf->disabled) {
		done = -ENODEV;
		goto out_unlock;
	}

	ret = copy_from_user(&migf->vidxd_data + *pos, buf, len);
	if (ret) {
		done = -EFAULT;
		goto out_unlock;
	}
	*pos += len;
	done = len;
	migf->total_length += len;
out_unlock:
	mutex_unlock(&migf->lock);

	return done;
}

static const struct file_operations idxd_vdcm_resume_fops = {
	.owner = THIS_MODULE,
	.write = idxd_vdcm_resume_write,
	.release = idxd_vdcm_release_file,
	.llseek = no_llseek,
};

static struct vidxd_migration_file *idxd_vdcm_resume(struct vdcm_idxd *vidxd)
{
	struct vidxd_migration_file *migf;

	migf = kzalloc(sizeof(*migf), GFP_KERNEL);
	if (!migf)
		return ERR_PTR(-ENOMEM);

	migf->filp = anon_inode_getfile("vidxd_mig", &idxd_vdcm_resume_fops,
					migf, O_WRONLY);
	if (IS_ERR(migf->filp)) {
		int err = PTR_ERR(migf->filp);

		kfree(migf);
		return ERR_PTR(err);
	}

	stream_open(migf->filp->f_inode, migf->filp);
	mutex_init(&migf->lock);

	return migf;
}

static ssize_t idxd_vdcm_save_read(struct file *filp, char __user *buf,
				   size_t len, loff_t *pos)
{
	struct vidxd_migration_file *migf = filp->private_data;
	ssize_t done = 0;
	int ret;

	if (pos)
		return -ESPIPE;
	pos = &filp->f_pos;

	mutex_lock(&migf->lock);
	if (*pos > migf->total_length) {
		done = -EINVAL;
		goto out_unlock;
	}

	if (migf->disabled) {
		done = -ENODEV;
		goto out_unlock;
	}

	len = min_t(size_t, migf->total_length - *pos, len);
	if (len) {
		ret = copy_to_user(buf, &migf->vidxd_data + *pos, len);
		if (ret) {
			done = -EFAULT;
			goto out_unlock;
		}
		*pos += len;
		done = len;
	}
out_unlock:
	mutex_unlock(&migf->lock);
	return done;
}

static const struct file_operations idxd_vdcm_save_fops = {
	.owner = THIS_MODULE,
	.read = idxd_vdcm_save_read,
	.release = idxd_vdcm_release_file,
	.llseek = no_llseek,
};

static struct vidxd_migration_file *
idxd_vdcm_stop_copy(struct vdcm_idxd *vidxd)
{
	struct vidxd_migration_file *migf;

	migf = kzalloc(sizeof(*migf), GFP_KERNEL);
	if (!migf)
		return ERR_PTR(-ENOMEM);

	migf->filp = anon_inode_getfile("vidxd_mig", &idxd_vdcm_save_fops, migf,
					O_RDONLY);
	if (IS_ERR(migf->filp)) {
		int err = PTR_ERR(migf->filp);

		kfree(migf);

		return ERR_PTR(err);
	}

	stream_open(migf->filp->f_inode, migf->filp);
	mutex_init(&migf->lock);

	idxd_vdcm_state_save(vidxd, migf);

	return migf;
}

static int idxd_vdcm_stop_device(struct vdcm_idxd *vidxd)
{
	int i;

	if (vidxd->paused)
		return 0;

	/* The VMM is expected to have unmap the portals. So once we drain
	 * there shouldn't be any work directly submited from the VM */
	vidxd->paused = true;

	/* For DWQs, pausing the vDSA can always be done by Drain WQ command.
	 * For SWQs, pausing the vDSA may mean Drain PASID if the SWQ is shared
	 * with other VMs. We will need to do Drain PASID for each PASID
	 * allocated to the VM which may take a long time. As an optimization,
	 * we may do Drain PASID if no of PASIDs for the VM is below certain
	 * number and do Drain WQ otherwise.
	 */
	/* Drain WQ(s) to make sure no more outstanding work in the dev */
	/* TODO: Currently support for only 1 WQ per VDev */
	for (i = 0; i < vidxd->num_wqs; i++)
		idxd_wq_drain(vidxd->wq);

	return 0;
}

static struct file *
_idxd_vdcm_set_device_state(struct vdcm_idxd *vidxd, u32 new)
{
	struct vfio_device *vdev = &vidxd->vdev;
	u32 cur = vidxd->mig_state;
	int ret;

	dev_dbg(vidxd_dev(vidxd), "%s: migration state change: %d->%d\n",
		dev_name(vdev->dev), cur, new);

	if (cur == VFIO_DEVICE_STATE_RUNNING && new == VFIO_DEVICE_STATE_STOP) {
		ret = idxd_vdcm_stop_device(vidxd);
		if (ret)
			return ERR_PTR(ret);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_STOP_COPY) {
		struct vidxd_migration_file *migf;

		migf = idxd_vdcm_stop_copy(vidxd);
		if (IS_ERR(migf))
			return ERR_CAST(migf);
		get_file(migf->filp);
		vidxd->saving_migf = migf;

		return migf->filp;
	}

	if ((cur == VFIO_DEVICE_STATE_STOP_COPY && new == VFIO_DEVICE_STATE_STOP)) {
		idxd_vdcm_disable_fds(vidxd);

		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_RESUMING) {
		struct vidxd_migration_file *migf;

		migf = idxd_vdcm_resume(vidxd);
		if (IS_ERR(migf))
			return ERR_CAST(migf);
		get_file(migf->filp);
		vidxd->resuming_migf = migf;

		return migf->filp;
	}

	if (cur == VFIO_DEVICE_STATE_RESUMING && new == VFIO_DEVICE_STATE_STOP) {
		ret = idxd_vdcm_load_state(vidxd);
		if (ret)
			return ERR_PTR(ret);
		idxd_vdcm_disable_fds(vidxd);

		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_RUNNING) {
		idxd_vdcm_start_device(vidxd);

		return NULL;
	}

	/*
	 * vfio_mig_get_next_state() does not use arcs other than the above
	 */
	WARN_ON(true);

	return ERR_PTR(-EINVAL);
}

static struct file *
idxd_vdcm_set_device_state(struct vfio_device *vdev,
			   enum vfio_device_mig_state new_state)
{
	struct vdcm_idxd *vidxd = container_of(vdev, struct vdcm_idxd, vdev);
	enum vfio_device_mig_state next_state;
	struct file *res = NULL;
	int ret;

	mutex_lock(&vidxd->state_mutex);
	while (new_state != vidxd->mig_state) {
		ret = vfio_mig_get_next_state(vdev,
					      vidxd->mig_state,
					      new_state, &next_state);
		if (ret) {
			res = ERR_PTR(-EINVAL);
			break;
		}

		res = _idxd_vdcm_set_device_state(vidxd, next_state);
		if (IS_ERR(res))
			break;
		vidxd->mig_state = next_state;
		if (WARN_ON(res && new_state != vidxd->mig_state)) {
			fput(res);
			res = ERR_PTR(-EINVAL);
			break;
		}
	}
	mutex_unlock(&vidxd->state_mutex);

	return res;
}

static int idxd_vdcm_get_device_state(struct vfio_device *vdev,
				      enum vfio_device_mig_state *curr_state)
{
	struct vdcm_idxd *vidxd = container_of(vdev, struct vdcm_idxd, vdev);

	mutex_lock(&vidxd->state_mutex);
	*curr_state = vidxd->mig_state;
	mutex_unlock(&vidxd->state_mutex);

	return 0;
}

static int
idxd_vdcm_get_data_size(struct vfio_device *vdev,
			unsigned long *stop_copy_length)
{
        *stop_copy_length = sizeof(struct vidxd_data);

        return 0;
}

static const struct vfio_device_ops idxd_vdev_ops = {
	.name = "vfio-vdev",
	.open_device = idxd_vdcm_open,
	.close_device = idxd_vdcm_close,
	.bind_iommufd = idxd_vdcm_bind_iommufd,
	.unbind_iommufd = idxd_vdcm_unbind_iommufd,
	.attach_ioas = idxd_vdcm_attach_ioas,
	.detach_ioas = idxd_vdcm_detach_ioas,
	.pasid_attach_ioas = idxd_vdcm_pasid_attach_ioas,
	.pasid_detach_ioas = idxd_vdcm_pasid_detach_ioas,
	.read = idxd_vdcm_read,
	.write = idxd_vdcm_write,
	.mmap = idxd_vdcm_mmap,
	.ioctl = idxd_vdcm_ioctl,
	.request = idxd_vdcm_request,
//	.migration_set_state = idxd_vdcm_set_device_state,
//	.migration_get_state = idxd_vdcm_get_device_state,
};

static const struct vfio_migration_ops idxd_vdev_migrn_state_ops = {
	.migration_set_state = idxd_vdcm_set_device_state,
	.migration_get_state = idxd_vdcm_get_device_state,
	.migration_get_data_size = idxd_vdcm_get_data_size,
};

static struct idxd_wq *find_wq_by_type(struct idxd_device *idxd, u32 type)
{
	struct idxd_wq *wq, *least_used_swq;
	int i, min_wq_refcount = INT_MAX;
	bool found = false;

	for (i = 0; i < idxd->max_wqs; i++) {
		wq = idxd->wqs[i];

		mutex_lock(&wq->wq_lock);

		if (wq->type != IDXD_WQT_VDEV) {
			mutex_unlock(&wq->wq_lock);
			continue;
		}

		if (wq->state != IDXD_WQ_ENABLED) {
			mutex_unlock(&wq->wq_lock);
			continue;
		}

		if (type == IDXD_VDEV_TYPE_1DWQ && wq_dedicated(wq) &&
		    !idxd_wq_refcount(wq)) {
			found = true;
			mutex_unlock(&wq->wq_lock);
			break;
		}

		/* Find least used shared WQ. */
		if (type == IDXD_VDEV_TYPE_1SWQ && wq_shared(wq)) {
			found = true;
			if (idxd_wq_refcount(wq) < min_wq_refcount) {
				least_used_swq = wq;
				min_wq_refcount = idxd_wq_refcount(wq);
			}
		}

		mutex_unlock(&wq->wq_lock);
	}

	if (type == IDXD_VDEV_TYPE_1SWQ && found)
		wq = least_used_swq;

	if (found) {
		idxd_wq_get(wq);

		return wq;
	}

	return NULL;
}

static void idxd_vfio_dev_migration_init(struct vdcm_idxd *vidxd)
{
	mutex_init(&vidxd->state_mutex);
	vidxd->vdev.migration_flags = VFIO_MIGRATION_STOP_COPY;
	vidxd->vdev.mig_ops = &idxd_vdev_migrn_state_ops;

	dev_dbg(vidxd_dev(vidxd), "idxd migration is initialized\n");
}

static int idxd_vfio_dev_drv_probe(struct idxd_dev *idxd_dev)
{
	struct vdcm_idxd *vidxd;
	struct idxd_device *idxd;
	struct idxd_wq *wq;
	int rc;

	idxd = idxd_dev->idxd;
	wq = find_wq_by_type(idxd, idxd_dev->vdev_type);
	if (!wq)
		return -ENODEV;

	vidxd = vfio_alloc_device(vdcm_idxd, vdev, &idxd_dev->conf_dev, &idxd_vdev_ops);
	if (!vidxd) {
		rc = -ENOMEM;
		goto err_vfio_dev;
	}

	mutex_init(&vidxd->dev_lock);
	vidxd->wq = wq;
	vidxd->idxd = wq->idxd;
	vidxd->parent = idxd_dev;
        vidxd->num_wqs = VIDXD_MAX_WQS;

	rc = vfio_register_emulated_iommu_dev(&vidxd->vdev);
	if (rc < 0)
		goto err_vfio_register;

	dev_set_drvdata(&idxd_dev->conf_dev, vidxd);

	idxd_vfio_dev_migration_init(vidxd);

	return 0;

err_vfio_register:
	vfio_put_device(&vidxd->vdev);
err_vfio_dev:
	mutex_lock(&wq->wq_lock);
	idxd_wq_put(wq);
	mutex_unlock(&wq->wq_lock);
	return rc;
}

static void idxd_vfio_dev_drv_remove(struct idxd_dev *idxd_dev)
{
	struct vdcm_idxd *vidxd = dev_get_drvdata(&idxd_dev->conf_dev);
	struct vfio_device *vdev = &vidxd->vdev;
	struct idxd_wq *wq = vidxd->wq;

	vfio_unregister_group_dev(vdev);
	vfio_put_device(vdev);
	mutex_lock(&wq->wq_lock);
	idxd_wq_put(wq);
	mutex_unlock(&wq->wq_lock);
}

static enum idxd_dev_type idxd_vfio_dev_types[] = {
	IDXD_DEV_VDEV,
	IDXD_DEV_NONE,
};

static struct idxd_device_driver idxd_vfio_dev_driver = {
	.probe = idxd_vfio_dev_drv_probe,
	.remove = idxd_vfio_dev_drv_remove,
	.name = "idxd_vfio",
	.type = idxd_vfio_dev_types,
};

static void idxd_vdev_release(struct device *dev)
{
	struct idxd_dev *idev = container_of(dev, struct idxd_dev, conf_dev);

	kfree(idev);
}

struct device_type idxd_vdev_device_type = {
	.name = "vdev",
	.release = idxd_vdev_release,
};

static int vdev_device_create(struct idxd_device *idxd, u32 type)
{
	struct device *dev, *dev_found;
	struct idxd_dev *parent;
	char vdev_name[32];
	int rc;

	lockdep_assert_held(&idxd->vdev_lock);

	if (type >= IDXD_VDEV_TYPE_MAX)
		return -EINVAL;

	parent = kzalloc(sizeof(*parent), GFP_KERNEL);
	if (!parent)
		return -ENOMEM;

	idxd_dev_set_type(parent, IDXD_DEV_VDEV);
	dev = &parent->conf_dev;
	device_initialize(dev);
	dev->parent = idxd_confdev(idxd);
	dev->bus = &dsa_bus_type;
	dev->type = &idxd_vdev_device_type;

	parent->id = ida_alloc(&idxd->vdev_ida, GFP_KERNEL);
	sprintf(vdev_name, "vdev%u.%u", idxd->id, parent->id);
	dev_found = device_find_child_by_name(dev->parent, vdev_name);
	if (dev_found) {
		put_device(dev);
		return -EEXIST;
	}
	rc = dev_set_name(dev, "%s", vdev_name);
	if (rc < 0) {
		put_device(dev);
		return rc;
	}
	parent->vdev_type = type;
	parent->idxd = idxd;

	rc = device_add(dev);
	if (rc < 0) {
		put_device(dev);
		return rc;
	}

	list_add_tail(&parent->list, &idxd->vdev_list);

	return 0;
}

static int vdev_device_remove(struct idxd_device *idxd, char *vdev_name)
{
	struct idxd_dev *pos, *n;

	lockdep_assert_held(&idxd->vdev_lock);

	list_for_each_entry_safe(pos, n, &idxd->vdev_list, list) {
		struct device *dev = &pos->conf_dev;

		if (!strcmp(dev_name(dev), vdev_name)) {
			list_del(&pos->list);
			device_unregister(dev);
			ida_free(&idxd->vdev_ida, pos->id);

			return 0;
		}
	}

	return -ENODEV;
}

struct vdev_device_ops vidxd_device_ops = {
	.device_create = vdev_device_create,
	.device_remove = vdev_device_remove,
};

static int idxd_vdev_drv_probe(struct idxd_dev *idxd_dev)
{
	struct device *dev = &idxd_dev->conf_dev;
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);
	struct idxd_device *idxd = wq->idxd;
	int rc;

	if (!is_idxd_wq_dev(idxd_dev))
		return -ENODEV;

	if (idxd->state != IDXD_DEV_ENABLED)
		return -ENXIO;

	mutex_lock(&wq->wq_lock);
	if (!idxd_wq_driver_name_match(wq, dev)) {
		idxd->cmd_status = IDXD_SCMD_WQ_NO_DRV_NAME;
		rc = -ENODEV;
		goto err;
	}

	wq->type = IDXD_WQT_VDEV;
	rc = idxd_drv_enable_wq(wq);
	if (rc < 0)
		goto err;

	idxd->cmd_status = 0;

	mutex_lock(&idxd->vdev_lock);
	idxd->vdev_ops = &vidxd_device_ops;
	mutex_unlock(&idxd->vdev_lock);

	mutex_unlock(&wq->wq_lock);

	return 0;
err:
	wq->type = IDXD_WQT_NONE;
	mutex_unlock(&wq->wq_lock);

	return rc;
}

static void idxd_vdev_drv_remove(struct idxd_dev *idxd_dev)
{
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);

	mutex_lock(&wq->wq_lock);
	idxd_drv_disable_wq(wq);
	if (wq->state == IDXD_WQ_LOCKED)
		wq->state = IDXD_WQ_DISABLED;
	wq->type = IDXD_WQT_NONE;
	mutex_unlock(&wq->wq_lock);
}

static enum idxd_dev_type dev_types[] = {
	IDXD_DEV_WQ,
	IDXD_DEV_NONE
};

static struct idxd_device_driver idxd_vdev_driver = {
	.probe = idxd_vdev_drv_probe,
	.remove = idxd_vdev_drv_remove,
	.name = "vdev",
	.type = dev_types,
};

static int __init idxd_vdev_init(void)
{
	int rc;

	rc = idxd_driver_register(&idxd_vdev_driver);
	if (rc < 0)
		return rc;

	rc = idxd_driver_register(&idxd_vfio_dev_driver);
	if (rc < 0) {
		idxd_driver_unregister(&idxd_vdev_driver);
		return rc;
	}

	return 0;
}

static void __exit idxd_vdev_exit(void)
{
	idxd_driver_unregister(&idxd_vfio_dev_driver);
	idxd_driver_unregister(&idxd_vdev_driver);
}

module_init(idxd_vdev_init);
module_exit(idxd_vdev_exit);

MODULE_IMPORT_NS(IDXD);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Intel Corporation");
MODULE_ALIAS_IDXD_DEVICE(0);

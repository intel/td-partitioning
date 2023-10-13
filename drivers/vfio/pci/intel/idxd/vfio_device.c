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
#include "registers.h"
#include "idxd.h"
#include "vidxd.h"

MODULE_IMPORT_NS(IOMMUFD);

enum {
	IDXD_VDEV_TYPE_1DWQ = 0,
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
	idxd_vdcm_set_irqs(vidxd, VFIO_IRQ_SET_DATA_NONE |
			   VFIO_IRQ_SET_ACTION_TRIGGER,
			   VFIO_PCI_MSIX_IRQ_INDEX, 0, 0, NULL);
	vfio_pci_ims_free(vdev);
	vidxd_shutdown(vidxd);
	vfio_device_set_pasid(vdev, IOMMU_PASID_INVALID);
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
	if (virt_portal == IDXD_PORTAL_UNLIMITED)
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
};

static struct idxd_wq *find_wq_by_type(struct idxd_device *idxd, u32 type)
{
	struct idxd_wq *wq;
	int i;
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

		if (type == IDXD_VDEV_TYPE_1DWQ && !idxd_wq_refcount(wq)) {
			found = true;
			mutex_unlock(&wq->wq_lock);
			break;
		}

		mutex_unlock(&wq->wq_lock);
	}

	if (found) {
		idxd_wq_get(wq);

		return wq;
	}

	return NULL;
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

	rc = vfio_register_emulated_iommu_dev(&vidxd->vdev);
	if (rc < 0)
		goto err_vfio_register;

	dev_set_drvdata(&idxd_dev->conf_dev, vidxd);

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

	if (!wq_dedicated(wq)) {
		dev_warn(dev, "Only dedicated workqueues are supported\n");
		return -EOPNOTSUPP;
	}

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

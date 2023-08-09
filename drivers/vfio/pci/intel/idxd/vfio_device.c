// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/vfio.h>
#include <linux/iommufd.h>
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

	pasid = iommu_alloc_global_pasid(&idxd->pdev->dev);
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
		iommufd_device_unbind(vidxd->idev);
		vidxd->idev = NULL;
	}
	mutex_unlock(&vidxd->dev_lock);
}

static const struct vfio_device_ops idxd_vdev_ops = {
	.name = "vfio-vdev",
	.open_device = idxd_vdcm_open,
	.close_device = idxd_vdcm_close,
	.bind_iommufd = idxd_vdcm_bind_iommufd,
	.unbind_iommufd = idxd_vdcm_unbind_iommufd,
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

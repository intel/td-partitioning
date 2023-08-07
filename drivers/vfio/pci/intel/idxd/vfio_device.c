// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/vfio.h>
#include "registers.h"
#include "idxd.h"

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

	return 0;
}

static void __exit idxd_vdev_exit(void)
{
	idxd_driver_unregister(&idxd_vdev_driver);
}

module_init(idxd_vdev_init);
module_exit(idxd_vdev_exit);

MODULE_IMPORT_NS(IDXD);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Intel Corporation");
MODULE_ALIAS_IDXD_DEVICE(0);

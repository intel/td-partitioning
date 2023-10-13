// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Intel, Corp. All rights reserved.
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 * VFIO common helper functions
 */

#include <linux/eventfd.h>
#include <linux/vfio.h>

/*
 * Common helper to set single eventfd trigger
 *
 * @ctx [out]		: address of eventfd ctx to be written to
 * @count [in]		: number of vectors (should be 1)
 * @flags [in]		: VFIO IRQ flags
 * @data [in]		: data from ioctl
 */
int vfio_set_ctx_trigger_single(struct eventfd_ctx **ctx,
				unsigned int count, u32 flags,
				void *data)
{
	/* DATA_NONE/DATA_BOOL enables loopback testing */
	if (flags & VFIO_IRQ_SET_DATA_NONE) {
		if (*ctx) {
			if (count) {
				eventfd_signal(*ctx, 1);
			} else {
				eventfd_ctx_put(*ctx);
				*ctx = NULL;
			}
			return 0;
		}
	} else if (flags & VFIO_IRQ_SET_DATA_BOOL) {
		u8 trigger;

		if (!count)
			return -EINVAL;

		trigger = *(uint8_t *)data;
		if (trigger && *ctx)
			eventfd_signal(*ctx, 1);

		return 0;
	} else if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
		s32 fd;

		if (!count)
			return -EINVAL;

		fd = *(s32 *)data;
		if (fd == -1) {
			if (*ctx)
				eventfd_ctx_put(*ctx);
			*ctx = NULL;
		} else if (fd >= 0) {
			struct eventfd_ctx *efdctx;

			efdctx = eventfd_ctx_fdget(fd);
			if (IS_ERR(efdctx))
				return PTR_ERR(efdctx);

			if (*ctx)
				eventfd_ctx_put(*ctx);

			*ctx = efdctx;
		}
		return 0;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(vfio_set_ctx_trigger_single);

void vfio_device_request(struct vfio_device *vdev, unsigned int count)
{
	struct device *dev = vdev->dev;

	if (vdev->req_trigger) {
		dev_dbg(dev, "Request device from user\n");
		eventfd_signal(vdev->req_trigger, 1);
	}
}
EXPORT_SYMBOL_GPL(vfio_device_request);

int vfio_set_req_trigger(struct vfio_device *vdev, unsigned int index,
			 unsigned int start, unsigned int count, u32 flags,
			 void *data)
{
	if (index != VFIO_PCI_REQ_IRQ_INDEX || start != 0 || count != 1)
		return -EINVAL;

	return vfio_set_ctx_trigger_single(&vdev->req_trigger, count, flags, data);
}
EXPORT_SYMBOL_GPL(vfio_set_req_trigger);

MODULE_LICENSE("GPL v2");

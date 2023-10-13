// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2023, Intel Corporation
 */
#include <linux/iommufd.h>
#include <linux/iommu.h>
#include <linux/ioasid.h>
#include "../iommu-priv.h"

#include "iommufd_private.h"
#include "iommufd_test.h"

#define IOASID_BITS 20

static int __iommufd_device_pasid_do_attach(struct iommufd_device *idev,
					    u32 pasid,
					    struct iommufd_hw_pagetable *hwpt,
					    bool replace)
{
	int rc;

	/*
	 * Try to upgrade the domain we have. This is also required for
	 * pasid attach since pasid only matters for identifying a hwpt
	 * while cache coherency is about memory access semantics post
	 * walking hwpt.
	 */
	if (idev->enforce_cache_coherency) {
		rc = iommufd_hw_pagetable_enforce_cc(hwpt);
		if (rc)
			return rc;
	}

	if (!replace)
		rc = iommu_attach_device_pasid(hwpt->domain, idev->dev, pasid);
	else
		rc = iommu_replace_device_pasid(hwpt->domain, idev->dev, pasid);
	if (rc)
		return rc;

	xa_store(&idev->pasid_hwpts, pasid, hwpt, GFP_KERNEL);
	refcount_inc(&hwpt->obj.users);
	return 0;
}

static struct iommufd_hw_pagetable *
iommufd_device_pasid_do_attach(struct iommufd_device *idev, u32 pasid,
			       struct iommufd_hw_pagetable *hwpt)
{
	struct iommufd_hw_pagetable *old_hwpt;
	int rc;

	old_hwpt = xa_load(&idev->pasid_hwpts, pasid);
	if (old_hwpt) {
		if (old_hwpt == hwpt)
			return NULL;
		else
			return ERR_PTR(-EINVAL);
	}

	rc = __iommufd_device_pasid_do_attach(idev, pasid, hwpt, false);
	return rc ? ERR_PTR(rc) : NULL;
}

static struct iommufd_hw_pagetable *
iommufd_device_pasid_do_replace(struct iommufd_device *idev, u32 pasid,
				struct iommufd_hw_pagetable *hwpt)
{
	struct iommufd_hw_pagetable *old_hwpt;
	int rc;

	old_hwpt = xa_load(&idev->pasid_hwpts, pasid);
	if (!old_hwpt)
		return ERR_PTR(-EINVAL);

	if (hwpt == old_hwpt)
		return NULL;

	rc = __iommufd_device_pasid_do_attach(idev, pasid, hwpt, true);
	/* Caller must destroy old_hwpt */
	return rc ? ERR_PTR(rc) : old_hwpt;
}

typedef struct iommufd_hw_pagetable *(*pasid_attach_fn)(
	struct iommufd_device *idev, u32 pasid, struct iommufd_hw_pagetable *hwpt);

static int iommufd_device_pasid_change_pt(struct iommufd_device *idev, u32 pasid,
					  u32 pt_id, pasid_attach_fn do_pasid_attach)
{
	struct iommufd_object *pt_obj;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_hw_pagetable *destroy_hwpt;

	pt_obj = iommufd_get_object(idev->ictx, pt_id, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(pt_obj))
		return PTR_ERR(pt_obj);

	hwpt = container_of(pt_obj, struct iommufd_hw_pagetable, obj);
	destroy_hwpt = (*do_pasid_attach)(idev, pasid, hwpt);
	iommufd_put_object(pt_obj);
	if (IS_ERR(destroy_hwpt))
		return PTR_ERR(destroy_hwpt);

	/* This destruction has to be after we unlock everything */
	if (destroy_hwpt)
		iommufd_hw_pagetable_put(idev->ictx, destroy_hwpt);
	return 0;
}

/**
 * iommufd_device_pasid_attach - Connect a {device, pasid} to an iommu_domain
 * @idev: device to attach
 * @pasid: pasid to attach
 * @pt_id: IOMMUFD_OBJ_HW_PAGETABLE to attach
 *
 * This connects a pasid in the device to an iommu_domain. Once this
 * completes the device could do DMA with the pasid. Caller should
 * guarantee the pasid is usable by the current user.
 *
 * This function is undone by calling iommufd_device_detach_pasid().
 */
int iommufd_device_pasid_attach(struct iommufd_device *idev, u32 pasid, u32 pt_id)
{
	return iommufd_device_pasid_change_pt(idev, pasid, pt_id,
					      &iommufd_device_pasid_do_attach);
}
EXPORT_SYMBOL_NS_GPL(iommufd_device_pasid_attach, IOMMUFD);

/**
 * iommufd_device_pasid_replace- Change the {device, pasid}'s iommu_domain
 * @idev: device to change
 * @pasid: pasid to change
 * @pt_id: IOMMUFD_OBJ_HW_PAGETABLE to attach
 *
 * This is the same as
 *   iommufd_device_pasid_detach();
 *   iommufd_device_pasid_attach();
 *
 * If it fails then no change is made to the attachment. The iommu driver may
 * implement this so there is no disruption in translation. This can only be
 * called if iommufd_device_pasid_attach() has already succeeded. Caller should
 * guarantee the pasid is usable by the current user.
 */
int iommufd_device_pasid_replace(struct iommufd_device *idev, u32 pasid, u32 pt_id)
{
	return iommufd_device_pasid_change_pt(idev, pasid, pt_id,
					      &iommufd_device_pasid_do_replace);
}
EXPORT_SYMBOL_NS_GPL(iommufd_device_pasid_replace, IOMMUFD);

/**
 * iommufd_device_pasid_detach - Disconnect a {device, pasid} to an iommu_domain
 * @idev: device to detach
 * @pasid: pasid to detach
 *
 * Undo iommufd_device_pasid_attach(). This disconnects the idev/pasid from
 * the previously attached pt_id.
 */
void iommufd_device_pasid_detach(struct iommufd_device *idev, u32 pasid)
{
	struct iommufd_hw_pagetable *hwpt;

	hwpt = xa_load(&idev->pasid_hwpts, pasid);
	if (!hwpt)
		return;
	iommu_detach_device_pasid(hwpt->domain, idev->dev, pasid);
	xa_erase(&idev->pasid_hwpts, pasid);
	iommufd_hw_pagetable_put(idev->ictx, hwpt);
}
EXPORT_SYMBOL_NS_GPL(iommufd_device_pasid_detach, IOMMUFD);

int iommufd_alloc_pasid(struct iommufd_ucmd *ucmd)
{
	struct iommu_alloc_pasid *cmd = ucmd->cmd;
	ioasid_t pasid;
	int rc;

	if (cmd->flags & ~IOMMU_ALLOC_PASID_IDENTICAL)
		return -EOPNOTSUPP;

	if (cmd->range.min > cmd->range.max ||
	    cmd->range.min >= (1 << IOASID_BITS) ||
	    cmd->range.max >= (1 << IOASID_BITS))
		return -EINVAL;

	pasid = ioasid_alloc(ucmd->ictx->pasid_set,
			     cmd->range.min, cmd->range.max,
			     NULL, cmd->pasid);

	if (!pasid_valid(pasid))
		return -ENODEV;

	if (cmd->flags & IOMMU_ALLOC_PASID_IDENTICAL)
		ioasid_attach_spid(pasid, pasid);

	cmd->pasid = pasid;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_free_pasid;

	return 0;
out_free_pasid:
	ioasid_put(ucmd->ictx->pasid_set, pasid);
	return rc;
}

int iommufd_free_pasid(struct iommufd_ucmd *ucmd)
{
	struct iommu_free_pasid *cmd = ucmd->cmd;

	if (cmd->flags)
		return -EOPNOTSUPP;

	if (!pasid_valid(cmd->pasid))
		return -EINVAL;

	ioasid_put(ucmd->ictx->pasid_set, cmd->pasid);

	return 0;
}

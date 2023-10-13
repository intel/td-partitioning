// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/iommu.h>
#include <uapi/linux/iommufd.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/circ_buf.h>
#include <linux/eventfd.h>

#include "../iommu-priv.h"
#include "iommufd_private.h"
#include "iommufd_test.h"

static void
iommufd_hw_pagetable_dma_fault_destroy(struct iommufd_hw_pagetable *hwpt);
static int
iommufd_hw_pagetable_dma_fault_init(struct iommufd_hw_pagetable *hwpt,
				    int eventfd);
static enum iommu_page_response_code
iommufd_hw_pagetable_iopf_handler(struct iommu_fault *fault,
				  void *data);

void iommufd_hw_pagetable_destroy(struct iommufd_object *obj)
{
	struct iommufd_hw_pagetable *hwpt =
		container_of(obj, struct iommufd_hw_pagetable, obj);

	if (!list_empty(&hwpt->hwpt_item)) {
		mutex_lock(&hwpt->ioas->mutex);
		list_del(&hwpt->hwpt_item);
		mutex_unlock(&hwpt->ioas->mutex);

		iopt_table_remove_domain(&hwpt->ioas->iopt, hwpt->domain);
	}

	if (hwpt->domain)
		iommu_domain_free(hwpt->domain);

	if (hwpt->parent) {
		refcount_dec(&hwpt->parent->obj.users);
		/* parent is valid so this is s1 hwpt which need be destroyed */
		iommufd_hw_pagetable_dma_fault_destroy(hwpt);
	}
	refcount_dec(&hwpt->ioas->obj.users);
}

void iommufd_hw_pagetable_abort(struct iommufd_object *obj)
{
	struct iommufd_hw_pagetable *hwpt =
		container_of(obj, struct iommufd_hw_pagetable, obj);

	/* The ioas->mutex must be held until finalize is called. */
	lockdep_assert_held(&hwpt->ioas->mutex);

	if (!list_empty(&hwpt->hwpt_item)) {
		list_del_init(&hwpt->hwpt_item);
		iopt_table_remove_domain(&hwpt->ioas->iopt, hwpt->domain);
	}
	iommufd_hw_pagetable_destroy(obj);
}

int iommufd_hw_pagetable_enforce_cc(struct iommufd_hw_pagetable *hwpt)
{
	if (hwpt->enforce_cache_coherency)
		return 0;

	if (hwpt->domain->ops->enforce_cache_coherency)
		hwpt->enforce_cache_coherency =
			hwpt->domain->ops->enforce_cache_coherency(
				hwpt->domain);
	if (!hwpt->enforce_cache_coherency)
		return -EINVAL;
	return 0;
}

static int iommufd_hw_pagetable_link_ioas(struct iommufd_hw_pagetable *hwpt)
{
	int rc;

	/*
	 * Only a parent hwpt needs to be linked to the IOAS. And a hwpt->parent
	 * must be linked to the IOAS already, when it's being allocated.
	 */
	if (hwpt->parent)
		return 0;

	rc = iopt_table_add_domain(&hwpt->ioas->iopt, hwpt->domain);
	if (rc)
		return rc;
	list_add_tail(&hwpt->hwpt_item, &hwpt->ioas->hwpt_list);
	return 0;
}

int iommufd_hw_pagetable_setup_msi(struct iommufd_hw_pagetable *hwpt,
				   phys_addr_t sw_msi_start)
{
	int rc;

	/*
	 * If the IOMMU driver gives a IOMMU_RESV_SW_MSI then it is asking us to
	 * call iommu_get_msi_cookie() on its behalf. This is necessary to setup
	 * the MSI window so iommu_dma_prepare_msi() can install pages into our
	 * domain after request_irq(). If it is not done interrupts will not
	 * work on this domain. The msi_cookie should be always set into the
	 * kernel-managed (parent) domain.
	 *
	 * FIXME: This is conceptually broken for iommufd since we want to allow
	 * userspace to change the domains, eg switch from an identity IOAS to a
	 * DMA IOAS. There is currently no way to create a MSI window that
	 * matches what the IRQ layer actually expects in a newly created
	 * domain.
	 */
	if (hwpt->parent)
		hwpt = hwpt->parent;
	if (sw_msi_start != PHYS_ADDR_MAX && !hwpt->msi_cookie) {
		rc = iommu_get_msi_cookie(hwpt->domain, sw_msi_start);
		if (rc)
			return rc;

		/*
		 * iommu_get_msi_cookie() can only be called once per domain,
		 * it returns -EBUSY on later calls.
		 */
		hwpt->msi_cookie = true;
	}

	return 0;
}

int iommufd_hw_pagetable_enforce_dirty(struct iommufd_hw_pagetable *hwpt,
				       struct iommufd_device *idev)
{
	hwpt->enforce_dirty =
		!iommu_domain_set_flags(hwpt->domain, idev->dev->bus,
					IOMMU_DOMAIN_F_ENFORCE_DIRTY);
	if (!hwpt->enforce_dirty)
		return -EINVAL;

	return 0;
}

static void iopf_handler(struct work_struct *work)
{
	struct iopf_fault *iopf;
	struct iopf_group *group;
	enum iommu_page_response_code status = IOMMU_PAGE_RESP_SUCCESS;

	group = container_of(work, struct iopf_group, work);
	list_for_each_entry(iopf, &group->faults, list) {
		/*
		 * For the moment, errors are sticky: don't handle subsequent
		 * faults in the group if there is an error.
		 */
		if (status == IOMMU_PAGE_RESP_SUCCESS)
			status = iommufd_hw_pagetable_iopf_handler(&iopf->fault, group->data);
	}
	if (status != IOMMU_PAGE_RESP_ASYNC)
		iopf_complete_group(group->dev, &group->last_fault, status);
	iopf_free_group(group);
}

int iommu_hwpt_handle_iopf_group(struct iopf_group *group)
{
	return iopf_queue_work(group, iopf_handler);
}
/**
 * iommufd_hw_pagetable_alloc() - Get an iommu_domain for a device
 * @ictx: iommufd context
 * @ioas: IOAS to associate the domain with
 * @idev: Device to get an iommu_domain for
 * @hwpt_type: Requested type of hw_pagetable
 * @parent: Optional parent HWPT to associate with
 * @user_data: Optional user_data pointer
 * @immediate_attach: True if idev should be attached to the hwpt
 * @enforce_dirty: True if dirty tracking support should be enforce
 *                 on device attach
 *
 * Allocate a new iommu_domain and return it as a hw_pagetable. The HWPT
 * will be linked to the given ioas and upon return the underlying iommu_domain
 * is fully popoulated.
 *
 * The caller must hold the ioas->mutex until after
 * iommufd_object_abort_and_destroy() or iommufd_object_finalize() is called on
 * the returned hwpt.
 */
struct iommufd_hw_pagetable *
iommufd_hw_pagetable_alloc(struct iommufd_ctx *ictx, struct iommufd_ioas *ioas,
			   struct iommufd_device *idev,
			   enum iommu_hwpt_type hwpt_type,
			   struct iommufd_hw_pagetable *parent,
			   union iommu_domain_user_data *domain_data,
			   struct iommu_hwpt_user_data *user_data,
			   struct iommu_hwpt_user_data __user *uptr,
			   bool immediate_attach, bool enforce_dirty)
{
	const struct iommu_ops *ops = dev_iommu_ops(idev->dev);
	struct iommu_domain *parent_domain = NULL;
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	lockdep_assert_held(&ioas->mutex);

	if (parent && !domain_data)
		return ERR_PTR(-EINVAL);
	if (domain_data && !ops->domain_alloc_user)
		return ERR_PTR(-EOPNOTSUPP);

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt))
		return hwpt;

	INIT_LIST_HEAD(&hwpt->hwpt_item);
	/* Pairs with iommufd_hw_pagetable_destroy() */
	refcount_inc(&ioas->obj.users);
	hwpt->ioas = ioas;
	if (parent) {
		hwpt->parent = parent;
		parent_domain = parent->domain;
		refcount_inc(&parent->obj.users);
	}

	if (ops->domain_alloc_user) {
		hwpt->domain = ops->domain_alloc_user(idev->dev, hwpt_type,
						      parent_domain, domain_data);
		if (IS_ERR(hwpt->domain)) {
			rc = PTR_ERR(hwpt->domain);
			hwpt->domain = NULL;
			goto out_abort;
		}
	} else {
		hwpt->domain = iommu_domain_alloc(idev->dev->bus);
		if (!hwpt->domain) {
			rc = -ENOMEM;
			goto out_abort;
		}
	}

	/* It must be either NESTED or UNMANAGED, depending on parent_domain */
	if (WARN_ON_ONCE((parent_domain &&
			  hwpt->domain->type != IOMMU_DOMAIN_NESTED) ||
			 (!parent_domain &&
			  hwpt->domain->type != IOMMU_DOMAIN_UNMANAGED))) {
		rc = -EINVAL;
		goto out_abort;
	}

	if (parent && user_data && uptr) {
		rc = iommufd_hw_pagetable_dma_fault_init(hwpt, user_data->eventfd);
		if (rc)
			goto out_free_domain;

		rc = put_user((__s32)hwpt->fault->fault_fd, &uptr->out_fault_fd);
		if (rc)
			goto out_destroy_dma_fault;

		iommu_domain_set_iopf_handler(hwpt->domain,
					      iommu_hwpt_handle_iopf_group,
					      hwpt);
	}

	/*
	 * Set the coherency mode before we do iopt_table_add_domain() as some
	 * iommus have a per-PTE bit that controls it and need to decide before
	 * doing any maps. It is an iommu driver bug to report
	 * IOMMU_CAP_ENFORCE_CACHE_COHERENCY but fail enforce_cache_coherency on
	 * a new domain.
	 */
	if (idev->enforce_cache_coherency) {
		rc = iommufd_hw_pagetable_enforce_cc(hwpt);
		if (WARN_ON(rc))
			goto out_destroy_dma_fault;
	}

	if (enforce_dirty) {
		rc = iommufd_hw_pagetable_enforce_dirty(hwpt, idev);
		if (rc)
			goto out_destroy_dma_fault;
	}

	/*
	 * immediate_attach exists only to accommodate iommu drivers that cannot
	 * directly allocate a domain. These drivers do not finish creating the
	 * domain until attach is completed. Thus we must have this call
	 * sequence. Once those drivers are fixed this should be removed.
	 */
	if (immediate_attach) {
		rc = iommufd_hw_pagetable_attach(hwpt, idev);
		if (rc)
			goto out_destroy_dma_fault;
	}

	rc = iommufd_hw_pagetable_link_ioas(hwpt);
	if (rc)
		goto out_detach;
	return hwpt;

out_detach:
	if (immediate_attach)
		iommufd_hw_pagetable_detach(idev);
out_destroy_dma_fault:
	if (parent && user_data && uptr)
		iommufd_hw_pagetable_dma_fault_destroy(hwpt);
out_free_domain:
	if (parent && user_data && uptr)
		iommu_domain_free(hwpt->domain);
out_abort:
	iommufd_object_abort_and_destroy(ictx, &hwpt->obj);

	return ERR_PTR(rc);
}

int iommufd_hwpt_alloc(struct iommufd_ucmd *ucmd)
{
	struct iommufd_hw_pagetable *hwpt, *parent = NULL;
	union iommu_domain_user_data *domain_data = NULL;
	struct iommu_hwpt_user_data __user *uptr = NULL;
	struct iommu_hwpt_alloc *cmd = ucmd->cmd;
	struct iommufd_object *pt_obj;
	struct iommufd_device *idev;
	struct iommufd_ioas *ioas;
	struct iommu_hwpt_user_data *data;
	int rc = 0;

	if ((cmd->flags & ~(IOMMU_HWPT_ALLOC_ENFORCE_DIRTY)) ||
	    cmd->__reserved)
		return -EOPNOTSUPP;

	if (!cmd->data_len && cmd->hwpt_type != IOMMU_HWPT_TYPE_DEFAULT)
		return -EINVAL;

	idev = iommufd_get_device(ucmd, cmd->dev_id);
	if (IS_ERR(idev))
		return PTR_ERR(idev);

	pt_obj = iommufd_get_object(ucmd->ictx, cmd->pt_id, IOMMUFD_OBJ_ANY);
	if (IS_ERR(pt_obj)) {
		rc = -EINVAL;
		goto out_put_idev;
	}

	switch (pt_obj->type) {
	case IOMMUFD_OBJ_IOAS:
		ioas = container_of(pt_obj, struct iommufd_ioas, obj);
		break;
	case IOMMUFD_OBJ_HW_PAGETABLE:
		/* pt_id points HWPT only when hwpt_type is !IOMMU_HWPT_TYPE_DEFAULT */
		if (cmd->hwpt_type == IOMMU_HWPT_TYPE_DEFAULT) {
			rc = -EINVAL;
			goto out_put_pt;
		}

		parent = container_of(pt_obj, struct iommufd_hw_pagetable, obj);
		/*
		 * Cannot allocate user-managed hwpt linking to auto_created
		 * hwpt. If the parent hwpt is already a user-managed hwpt,
		 * don't allocate another user-managed hwpt linking to it.
		 */
		if (parent->auto_domain || parent->parent) {
			rc = -EINVAL;
			goto out_put_pt;
		}
		ioas = parent->ioas;
		break;
	default:
		rc = -EINVAL;
		goto out_put_pt;
	}

	if (cmd->data_len) {
		data = kzalloc(sizeof(*data), GFP_KERNEL);
		if (!data) {
			rc = -ENOMEM;
			goto out_put_pt;
		}

		rc = copy_struct_from_user(data, sizeof(*data),
					   u64_to_user_ptr(cmd->data_uptr),
					   cmd->data_len);
		if (rc)
			goto out_free_data;

		if (!data->config_len)
			goto page_alloc;

		domain_data = kzalloc(data->config_len, GFP_KERNEL);
		if (!domain_data) {
			rc = -ENOMEM;
			goto out_free_data;
		}

		rc = copy_struct_from_user(domain_data, data->config_len,
				(void __user *)data->config_uptr,
				data->config_len);
		if (rc) {
			kfree(domain_data);
			goto out_free_data;
		}
	}

page_alloc:
	mutex_lock(&ioas->mutex);
	uptr = (void __user *)cmd->data_uptr;
	hwpt = iommufd_hw_pagetable_alloc(ucmd->ictx, ioas, idev,
					  cmd->hwpt_type,
					  parent, domain_data,
					  data, uptr, false,
					  cmd->flags & IOMMU_HWPT_ALLOC_ENFORCE_DIRTY);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_unlock;
	}

	cmd->out_hwpt_id = hwpt->obj.id;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_hwpt;
	iommufd_object_finalize(ucmd->ictx, &hwpt->obj);
	goto out_unlock;

out_hwpt:
	iommufd_object_abort_and_destroy(ucmd->ictx, &hwpt->obj);
out_unlock:
	mutex_unlock(&ioas->mutex);
out_free_data:
	kfree(data);
out_put_pt:
	iommufd_put_object(pt_obj);
out_put_idev:
	iommufd_put_object(&idev->obj);
	return rc;
}

MODULE_IMPORT_NS(IOMMUFD_INTERNAL);

int iommufd_hwpt_invalidate(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_invalidate *cmd = ucmd->cmd;
	struct iommufd_hw_pagetable *hwpt;
	u32 user_data_len, klen;
	u64 user_ptr;
	int rc = 0;

	if (!cmd->data_len || cmd->__reserved)
		return -EOPNOTSUPP;

	hwpt = iommufd_get_hwpt(ucmd, cmd->hwpt_id);
	if (IS_ERR(hwpt))
		return PTR_ERR(hwpt);

	/* Do not allow any kernel-managed hw_pagetable */
	if (!hwpt->parent) {
		rc = -EINVAL;
		goto out_put_hwpt;
	}

	klen = hwpt->domain->ops->cache_invalidate_user_data_len;
	if (!hwpt->domain->ops->cache_invalidate_user || !klen) {
		rc = -EOPNOTSUPP;
		goto out_put_hwpt;
	}

	/*
	 * Copy the needed fields before reusing the ucmd buffer, this
	 * avoids memory allocation in this path.
	 */
	user_ptr = cmd->data_uptr;
	user_data_len = cmd->data_len;

	rc = copy_struct_from_user(cmd, klen,
				   u64_to_user_ptr(user_ptr), user_data_len);
	if (rc)
		goto out_put_hwpt;

	rc = hwpt->domain->ops->cache_invalidate_user(hwpt->domain, cmd);
out_put_hwpt:
	iommufd_put_object(&hwpt->obj);
	return rc;
}

int iommufd_hwpt_set_dirty(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_set_dirty *cmd = ucmd->cmd;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_ioas *ioas;
	int rc = -EOPNOTSUPP;
	bool enable;

	hwpt = iommufd_get_hwpt(ucmd, cmd->hwpt_id);
	if (IS_ERR(hwpt))
		return PTR_ERR(hwpt);

	if (!hwpt->enforce_dirty)
		return -EOPNOTSUPP;

	ioas = hwpt->ioas;
	enable = cmd->flags & IOMMU_DIRTY_TRACKING_ENABLED;

	rc = iopt_set_dirty_tracking(&ioas->iopt, hwpt->domain, enable);

	iommufd_put_object(&hwpt->obj);
	return rc;
}

int iommufd_check_iova_range(struct iommufd_ioas *ioas,
			     struct iommufd_dirty_data *bitmap)
{
	unsigned long pgshift, npages;
	size_t iommu_pgsize;
	int rc = -EINVAL;

	pgshift = __ffs(bitmap->page_size);
	npages = bitmap->length >> pgshift;

	if (!npages || (npages > ULONG_MAX))
		return rc;

	iommu_pgsize = 1 << __ffs(ioas->iopt.iova_alignment);

	/* allow only smallest supported pgsize */
	if (bitmap->page_size != iommu_pgsize)
		return rc;

	if (bitmap->iova & (iommu_pgsize - 1))
		return rc;

	if (!bitmap->length || bitmap->length & (iommu_pgsize - 1))
		return rc;

	return 0;
}

int iommufd_hwpt_page_response(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_page_response *cmd = ucmd->cmd;
	struct iommufd_object *obj, *dev_obj;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_device *idev;
	int rc = 0;

	if (cmd->flags)
		return -EOPNOTSUPP;

	/* TODO: more sanity check when the struct is finalized */
	obj = iommufd_get_object(ucmd->ictx, cmd->hwpt_id,
				 IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	hwpt = container_of(obj, struct iommufd_hw_pagetable, obj);

	/* It is not s1 hwpt which doesn't support PRQ */
	if (!hwpt->parent) {
		rc = -EINVAL;
		goto out_put_hwpt;
	}

	dev_obj = iommufd_get_object(ucmd->ictx,
				     cmd->dev_id, IOMMUFD_OBJ_DEVICE);
	if (IS_ERR(dev_obj)) {
		rc = PTR_ERR(obj);
		goto out_put_hwpt;
	}

	idev = container_of(dev_obj, struct iommufd_device, obj);
	rc = iommu_page_response(idev->dev, &cmd->resp);
	iommufd_put_object(dev_obj);
out_put_hwpt:
	iommufd_put_object(obj);
	return rc;
}

static int iommufd_hw_pagetable_eventfd_setup(struct eventfd_ctx **ctx, int fd)
{
	struct eventfd_ctx *efdctx;

	efdctx = eventfd_ctx_fdget(fd);
	if (IS_ERR(efdctx))
		return PTR_ERR(efdctx);
	if (*ctx)
		eventfd_ctx_put(*ctx);
	*ctx = efdctx;
	return 0;
}

static void iommufd_hw_pagetable_eventfd_destroy(struct eventfd_ctx **ctx)
{
	eventfd_ctx_put(*ctx);
	*ctx = NULL;
}

static ssize_t hwpt_fault_fops_read(struct file *filep, char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct iommufd_hw_pagetable *hwpt = filep->private_data;
	loff_t pos = *ppos;
	void *base;
	size_t size;
	int ret = -EFAULT;

	if (WARN_ON(!hwpt->fault))
		return -EINVAL;

	base = hwpt->fault->fault_pages;
	size = hwpt->fault->fault_region_size;

	if (pos >= size)
		return -EINVAL;

	count = min(count, (size_t)(size - pos));

	mutex_lock(&hwpt->fault->fault_queue_lock);
	if (!copy_to_user(buf, base + pos, count)) {
		*ppos += count;
		ret = count;
	}
	mutex_unlock(&hwpt->fault->fault_queue_lock);

	return ret;
}

static ssize_t hwpt_fault_fops_write(struct file *filep,
				     const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct iommufd_hw_pagetable *hwpt = filep->private_data;
	loff_t pos = *ppos;
	void *base;
	struct iommufd_dma_fault *header;
	size_t size;
	u32 new_tail;
	int ret = -EFAULT;

	if (WARN_ON(!hwpt->fault))
		return -EINVAL;

	base = hwpt->fault->fault_pages;
	header = (struct iommufd_dma_fault *)base;
	size = hwpt->fault->fault_region_size;

	if (pos >= size)
		return -EINVAL;

	count = min(count, (size_t)(size - pos));

	mutex_lock(&hwpt->fault->fault_queue_lock);

	/* Only allows write to the tail which locates at offset 0 */
	if (pos != 0 || count != 4) {
		ret = -EINVAL;
		goto unlock;
	}

	if (copy_from_user((void *)&new_tail, buf, count))
		goto unlock;

	/* new tail should not exceed the maximum index */
	if (new_tail > header->nb_entries) {
		ret = -EINVAL;
		goto unlock;
	}

	/* update the tail value */
	header->tail = new_tail;
	ret = count;

unlock:
	mutex_unlock(&hwpt->fault->fault_queue_lock);
	return ret;
}

static const struct file_operations hwpt_fault_fops = {
	.owner		= THIS_MODULE,
	.read		= hwpt_fault_fops_read,
	.write		= hwpt_fault_fops_write,
};

static int iommufd_hw_pagetable_get_fault_fd(struct iommufd_hw_pagetable *hwpt)
{
	struct file *filep;
	int fdno, ret;

	if (WARN_ON(!hwpt->fault))
		return -EINVAL;

	fdno = ret = get_unused_fd_flags(O_CLOEXEC);
	if (ret < 0)
		return ret;

	filep = anon_inode_getfile("[hwpt-fault]", &hwpt_fault_fops,
				   hwpt, O_RDWR);
	if (IS_ERR(filep)) {
		put_unused_fd(fdno);
		return PTR_ERR(filep);
	}

	filep->f_mode |= (FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);
	fd_install(fdno, filep);

	hwpt->fault->fault_file = filep;
	hwpt->fault->fault_fd = fdno;

	return 0;
}

int iommufd_hwpt_get_dirty_iova(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_get_dirty_iova *cmd = ucmd->cmd;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_ioas *ioas;
	int rc = -EOPNOTSUPP;

	if ((cmd->flags & ~(IOMMU_GET_DIRTY_IOVA_NO_CLEAR)) ||
	    cmd->__reserved)
		return -EOPNOTSUPP;

	hwpt = iommufd_get_hwpt(ucmd, cmd->hwpt_id);
	if (IS_ERR(hwpt))
		return PTR_ERR(hwpt);

	if (!hwpt->enforce_dirty)
		return -EOPNOTSUPP;

	ioas = hwpt->ioas;
	rc = iommufd_check_iova_range(ioas, &cmd->bitmap);
	if (rc)
		goto out_put;

	rc = iopt_read_and_clear_dirty_data(&ioas->iopt, hwpt->domain,
					    cmd->flags, &cmd->bitmap);

out_put:
	iommufd_put_object(&hwpt->obj);
	return rc;
}

static enum iommu_page_response_code
iommufd_hw_pagetable_iopf_handler(struct iommu_fault *fault,
				  void *data)
{
	struct iommufd_hw_pagetable *hwpt =
				(struct iommufd_hw_pagetable *)data;
	struct iommufd_dma_fault *header;
	struct iommu_fault *new;
	int head, tail, size;
	enum iommu_page_response_code resp = IOMMU_PAGE_RESP_ASYNC;

	if (WARN_ON(!hwpt->fault))
		return IOMMU_PAGE_RESP_FAILURE;

	header = (struct iommufd_dma_fault *)hwpt->fault->fault_pages;

	if (WARN_ON(!header))
		return IOMMU_PAGE_RESP_FAILURE;

	mutex_lock(&hwpt->fault->fault_queue_lock);

	new = (struct iommu_fault *)(hwpt->fault->fault_pages + header->offset +
				     header->head * header->entry_size);

	pr_debug("%s, enque fault event\n", __func__);
	head = header->head;
	tail = header->tail;
	size = header->nb_entries;

	if (CIRC_SPACE(head, tail, size) < 1) {
		resp = IOMMU_PAGE_RESP_FAILURE;
		goto unlock;
	}

	*new = *fault;
	header->head = (head + 1) % size;
unlock:
	mutex_unlock(&hwpt->fault->fault_queue_lock);
	if (resp != IOMMU_PAGE_RESP_ASYNC)
		return resp;

	mutex_lock(&hwpt->fault->notify_gate);
	pr_debug("%s, signal userspace!\n", __func__);
	if (hwpt->fault->trigger)
		eventfd_signal(hwpt->fault->trigger, 1);
	mutex_unlock(&hwpt->fault->notify_gate);

	return resp;
}

#define DMA_FAULT_RING_LENGTH 512

static int
iommufd_hw_pagetable_dma_fault_init(struct iommufd_hw_pagetable *hwpt,
				    int eventfd)
{
	struct iommufd_dma_fault *header;
	size_t size;
	int rc;

	if (WARN_ON(hwpt->fault))
		return -EINVAL;

	hwpt->fault = kzalloc(sizeof(struct iommufd_fault), GFP_KERNEL);
	if (!hwpt->fault)
		return -ENOMEM;

	mutex_init(&hwpt->fault->fault_queue_lock);
	mutex_init(&hwpt->fault->notify_gate);

	/*
	 * We provision 1 page for the header and space for
	 * DMA_FAULT_RING_LENGTH fault records in the ring buffer.
	 */
	size = ALIGN(sizeof(struct iommu_fault) *
		     DMA_FAULT_RING_LENGTH, PAGE_SIZE) + PAGE_SIZE;

	hwpt->fault->fault_pages = kzalloc(size, GFP_KERNEL);
	if (!hwpt->fault->fault_pages)
		return -ENOMEM;

	header = (struct iommufd_dma_fault *)hwpt->fault->fault_pages;
	header->entry_size = sizeof(struct iommu_fault);
	header->nb_entries = DMA_FAULT_RING_LENGTH;
	header->offset = PAGE_SIZE;
	hwpt->fault->fault_region_size = size;

	rc = iommufd_hw_pagetable_eventfd_setup(&hwpt->fault->trigger, eventfd);
	if (rc)
		goto out_free;

	rc = iommufd_hw_pagetable_get_fault_fd(hwpt);
	if (rc)
		goto out_destroy_eventfd;

	return rc;

out_destroy_eventfd:
	iommufd_hw_pagetable_eventfd_destroy(&hwpt->fault->trigger);
out_free:
	kfree(hwpt->fault->fault_pages);
	return rc;
}

static void
iommufd_hw_pagetable_dma_fault_destroy(struct iommufd_hw_pagetable *hwpt)
{
	struct iommufd_dma_fault *header;

	if (WARN_ON(!hwpt->fault))
		return;

	header = (struct iommufd_dma_fault *)hwpt->fault->fault_pages;
	WARN_ON(header->tail != header->head);
	iommufd_hw_pagetable_eventfd_destroy(&hwpt->fault->trigger);
	kfree(hwpt->fault->fault_pages);
	mutex_destroy(&hwpt->fault->fault_queue_lock);
	mutex_destroy(&hwpt->fault->notify_gate);
}

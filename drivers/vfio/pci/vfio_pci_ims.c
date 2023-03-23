// SPDX-License-Identifier: GPL-2.0-only
/*
 * Interrupt Message Store (IMS) library
 *
 * Copyright (C) 2023 Intel Corporation
 */

#include <linux/device.h>
#include <linux/eventfd.h>
#include <linux/interrupt.h>
#include <linux/irqbypass.h>
#include <linux/irqreturn.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/vfio.h>
#include <linux/xarray.h>

/*
 * Interrupt context. Used for emulated as well as IMS interrupts.
 * @emulated:	(IMS and emulated) true if context belongs to emulated interrupt.
 * @name:	(IMS and emulated) Name of device associated with interrupt.
 *		Provided to request_irq().
 * @trigger:	(IMS and emulated) eventfd associated with interrupt.
 * @producer:	(IMS only) Interrupt's registered IRQ bypass producer.
 * @ims_id:	(IMS only) Interrupt index associated with IMS interrupt.
 * @virq:	(IMS only) Linux IRQ number associated with IMS interrupt.
 * @icookie:	(IMS only) Cookie used by irqchip driver.
 */
struct vfio_pci_ims_ctx {
	bool				emulated;
	char				*name;
	struct eventfd_ctx		*trigger;
	struct irq_bypass_producer	producer;
	int				ims_id;
	int				virq;
	union msi_instance_cookie	icookie;
};

static inline struct vfio_device *ims_to_vdev(struct vfio_pci_ims *ims)
{
	return container_of(ims, struct vfio_device, ims);
}

/*
 * Return IMS index of IMS interrupt backing MSI-X interrupt @vector
 */
int vfio_pci_ims_hwirq(struct vfio_device *vdev, unsigned int vector)
{
	struct vfio_pci_ims *ims = &vdev->ims;
	struct vfio_pci_ims_ctx *ctx;
	int id;

	mutex_lock(&ims->ctx_mutex);
	ctx = xa_load(&ims->ctx, vector);
	if (!ctx || ctx->emulated)
		id = -EINVAL;
	else
		id = ctx->ims_id;
	mutex_unlock(&ims->ctx_mutex);

	return id;
}
EXPORT_SYMBOL_GPL(vfio_pci_ims_hwirq);

/*
 * Send signal to the eventfd.
 * @vdev:	VFIO device
 * @vector:	MSI-X vector of @vdev for which interrupt will be signaled
 *
 * Intended for use to send signal for emulated interrupts.
 */
void vfio_pci_ims_send_signal(struct vfio_device *vdev, unsigned int vector)
{
	struct vfio_pci_ims *ims = &vdev->ims;
	struct vfio_pci_ims_ctx *ctx;

	mutex_lock(&ims->ctx_mutex);
	ctx = xa_load(&ims->ctx, vector);

	if (WARN_ON_ONCE(!ctx || !ctx->emulated || !ctx->trigger)) {
		mutex_unlock(&ims->ctx_mutex);
		return;
	}

	eventfd_signal(ctx->trigger, 1);
	mutex_unlock(&ims->ctx_mutex);
}
EXPORT_SYMBOL_GPL(vfio_pci_ims_send_signal);

static irqreturn_t vfio_pci_ims_irq_handler(int irq, void *arg)
{
	struct eventfd_ctx *trigger = arg;

	eventfd_signal(trigger, 1);
	return IRQ_HANDLED;
}

/*
 * Free the interrupt associated with @ctx.
 *
 * For an emulated interrupt there is nothing to do. For an IMS interrupt
 * the interrupt is freed from the underlying PCI device's IMS domain.
 */
static void vfio_pci_ims_irq_free(struct vfio_pci_ims *ims,
				  struct vfio_pci_ims_ctx *ctx)
{
	struct vfio_device *vdev = ims_to_vdev(ims);
	struct msi_map irq_map = {};

	lockdep_assert_held(&ims->ctx_mutex);

	if (ctx->emulated)
		return;

	irq_map.index = ctx->ims_id;
	irq_map.virq = ctx->virq;
	dev_dbg(&vdev->device, "Freeing IMS interrupt %d virq %d\n",
		irq_map.index, irq_map.virq);
	pci_ims_free_irq(ims->pdev, irq_map);
	ctx->ims_id = -EINVAL;
	ctx->virq = 0;
}

/*
 * Allocate an interrupt for @ctx.
 *
 * For an emulated interrupt there is nothing to do. For an IMS interrupt
 * the interrupt is allocated from the underlying PCI device's IMS domain.
 */
static int vfio_pci_ims_irq_alloc(struct vfio_pci_ims *ims,
				  struct vfio_pci_ims_ctx *ctx)
{
	struct vfio_device *vdev = ims_to_vdev(ims);
	struct msi_map irq_map = {};

	lockdep_assert_held(&ims->ctx_mutex);

	if (ctx->emulated)
		return -EINVAL;

	irq_map = pci_ims_alloc_irq(ims->pdev, &ctx->icookie, NULL);
	if (irq_map.index < 0)
		return irq_map.index;

	ctx->ims_id = irq_map.index;
	ctx->virq = irq_map.virq;
	dev_dbg(&vdev->device, "Allocated IMS interrupt %d virq %d\n",
		irq_map.index, irq_map.virq);

	return 0;
}

/*
 * Return interrupt context for @vector.
 *
 * Interrupt contexts are not freed until shutdown so first
 * check if there is a context associated with @vector that
 * should be returned before allocating new context.
 *
 * Return: pointer to interrupt context, NULL on failure.
 */
static struct vfio_pci_ims_ctx *
vfio_pci_ims_ctx_get(struct vfio_pci_ims *ims, unsigned int vector)
{
	struct vfio_pci_ims_ctx *ctx;
	int ret;

	lockdep_assert_held(&ims->ctx_mutex);

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	ctx = xa_load(&ims->ctx, vector);
	if (ctx)
		return ctx;

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL_ACCOUNT);
	if (!ctx)
		return NULL;

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	ctx->icookie = ims->default_cookie;
	ret = xa_insert(&ims->ctx, vector, ctx, GFP_KERNEL_ACCOUNT);
	if (ret) {
		kfree(ctx);
		return NULL;
	}

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	return ctx;
}

static int vfio_pci_ims_set_vector_signal(struct vfio_device *vdev,
					  unsigned int vector, int fd)
{
	struct vfio_pci_ims *ims = &vdev->ims;
	struct device *dev = &vdev->device;
	struct vfio_pci_ims_ctx *ctx;
	struct eventfd_ctx *trigger;
	int ret;

	lockdep_assert_held(&ims->ctx_mutex);

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	ctx = xa_load(&ims->ctx, vector);

	if (ctx && ctx->trigger) {
		pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
		if (!ctx->emulated) {
			pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
			irq_bypass_unregister_producer(&ctx->producer);
			free_irq(ctx->virq, ctx->trigger);
			vfio_pci_ims_irq_free(ims, ctx);
		}
		kfree(ctx->name);
		ctx->name = NULL;
		eventfd_ctx_put(ctx->trigger);
		ctx->trigger = NULL;
	}

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	if (fd < 0)
		return 0;

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	/* Interrupt contexts remain allocated until shutdown. */
	ctx = vfio_pci_ims_ctx_get(ims, vector);
	if (!ctx)
		return -EINVAL;

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	ctx->name = kasprintf(GFP_KERNEL, "vfio-ims[%d](%s)", vector,
			      dev_name(dev));
	if (!ctx->name)
		return -ENOMEM;

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	trigger = eventfd_ctx_fdget(fd);
	if (IS_ERR(trigger)) {
		ret = PTR_ERR(trigger);
		goto out_free_name;
	}

	ctx->trigger = trigger;

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	if (ctx->emulated)
		return 0;

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	ret = vfio_pci_ims_irq_alloc(ims, ctx);
	if (ret < 0)
		goto out_put_eventfd_ctx;

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	ret = request_irq(ctx->virq, vfio_pci_ims_irq_handler, 0, ctx->name,
			  ctx->trigger);
	if (ret < 0)
		goto out_free_irq;

	pr_debug("%s:%d vector = %u\n", __func__, __LINE__, vector);
	ctx->producer.token = ctx->trigger;
	ctx->producer.irq = ctx->virq;
	ret = irq_bypass_register_producer(&ctx->producer);
	if (unlikely(ret)) {
		dev_info(&vdev->device,
			 "irq bypass producer (token %p) registration fails: %d\n",
			 &ctx->producer.token, ret);
		ctx->producer.token = NULL;
	}

	return 0;

out_free_irq:
	vfio_pci_ims_irq_free(ims, ctx);
out_put_eventfd_ctx:
	eventfd_ctx_put(ctx->trigger);
	ctx->trigger = NULL;
out_free_name:
	kfree(ctx->name);
	ctx->name = NULL;
	return ret;
}

static int vfio_pci_ims_set_block(struct vfio_device *vdev, unsigned int start,
				  unsigned int count, int *fds)
{
	struct vfio_pci_ims *ims = &vdev->ims;
	unsigned int i, j;
	int ret = 0;

	lockdep_assert_held(&ims->ctx_mutex);

	for (i = 0, j = start; i < count && !ret; i++, j++) {
		int fd = fds ? fds[i] : -1;

		ret = vfio_pci_ims_set_vector_signal(vdev, j, fd);
	}

	if (ret) {
		for (i = start; i < j; i++)
			vfio_pci_ims_set_vector_signal(vdev, i, -1);
	}

	return ret;
}

/*
 * Manage Interrupt Message Store (IMS) or emulated interrupts on the
 * host that are backing guest MSI-X vectors.
 *
 * @vdev:	 VFIO device
 * @index:	 Type of guest vectors to set up.  Must be
 *		 VFIO_PCI_MSIX_IRQ_INDEX.
 * @start:	 First vector index.
 * @count:	 Number of vectors.
 * @flags:	 Type of data provided in @data.
 * @data:	 Data as specified by @flags.
 *
 * Caller is required to validate provided range for @vdev.
 *
 * Context: Interrupt context must be initialized via vfio_pci_ims_init()
 *	    before any interrupts can be allocated.
 *	    Can be called from vfio_device_ops->ioctl() or during shutdown via
 *	    vfio_device_ops->close_device().
 *
 * Return: Error code on failure or 0 on success.
 */
int vfio_pci_set_ims_trigger(struct vfio_device *vdev, unsigned int index,
			     unsigned int start, unsigned int count, u32 flags,
			     void *data)
{
	struct vfio_pci_ims *ims = &vdev->ims;
	struct vfio_pci_ims_ctx *ctx;
	unsigned long i;
	int ret;

	if (index != VFIO_PCI_MSIX_IRQ_INDEX)
		return -EINVAL;

	pr_debug("%s:%d index=%u, start=%u, count=%u, flags=0x%X\n",
			__func__, __LINE__, index, start, count, flags);
	mutex_lock(&ims->ctx_mutex);
	if (!count && (flags & VFIO_IRQ_SET_DATA_NONE)) {
		pr_debug("%s:%d\n", __func__, __LINE__);
		dev_dbg(&vdev->device, "Disabling IMS ...\n");
		xa_for_each(&ims->ctx, i, ctx)
			vfio_pci_ims_set_vector_signal(vdev, i, -1);
		ret = 0;
		goto out_unlock;
	}

	if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
		pr_debug("%s:%d\n", __func__, __LINE__);
		ret = vfio_pci_ims_set_block(vdev, start, count, (int *)data);
		goto out_unlock;
	}

	for (i = start; i < start + count; i++) {
		pr_debug("%s:%d\n", __func__, __LINE__);
		ctx = xa_load(&ims->ctx, i);
		if (!ctx || !ctx->trigger)
			continue;
		if (flags & VFIO_IRQ_SET_DATA_NONE) {
			eventfd_signal(ctx->trigger, 1);
		} else if (flags & VFIO_IRQ_SET_DATA_BOOL) {
			u8 *bools = data;

			if (bools[i - start])
				eventfd_signal(ctx->trigger, 1);
		}
	}

	ret = 0;

out_unlock:
	mutex_unlock(&ims->ctx_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(vfio_pci_set_ims_trigger);

/*
 * Initialize the IMS context associated with virtual device.
 *
 * @vdev: VFIO device
 * @pdev: PCI device that owns the IMS domain from where IMS
 *	  interrupts will be allocated.
 * @default_cookie: The default cookie for new IMS instances that do
 *		    not have an instance-specific cookie.
 *
 * Context: Must be called during vfio_device_ops->open_device().
 */
void vfio_pci_ims_init(struct vfio_device *vdev, struct pci_dev *pdev,
		       union msi_instance_cookie *default_cookie)
{
	struct vfio_pci_ims *ims = &vdev->ims;

	pr_debug("%s:%d \n", __func__, __LINE__);
	xa_init(&ims->ctx);
	mutex_init(&ims->ctx_mutex);
	ims->pdev = pdev;
	ims->default_cookie = *default_cookie;
}
EXPORT_SYMBOL_GPL(vfio_pci_ims_init);

/*
 * Free the IMS context associated with virtual device.
 *
 * @vdev: VFIO device
 *
 * Virtual device has to free all allocated interrupts before freeing the
 * IMS context. This is done by triggering a call to disable the index as
 * a whole by triggering vfio_pci_set_ims_trigger() with
 * flags = (DATA_NONE|ACTION_TRIGGER), count = 0.
 *
 * Context: Must be called during vfio_device_ops->close_device() after
 *	    index as a whole has been disabled.
 */
void vfio_pci_ims_free(struct vfio_device *vdev)
{
	struct vfio_pci_ims *ims = &vdev->ims;
	struct vfio_pci_ims_ctx *ctx;
	unsigned long i;

	pr_debug("%s:%d \n", __func__, __LINE__);
	/*
	 * All interrupts should be freed (including free of name and
	 * trigger) before context cleanup.
	 */
	mutex_lock(&ims->ctx_mutex);
	xa_for_each(&ims->ctx, i, ctx) {
		WARN_ON_ONCE(ctx->trigger);
		WARN_ON_ONCE(ctx->name);
		xa_erase(&ims->ctx, i);
		kfree(ctx);
	}
	mutex_unlock(&ims->ctx_mutex);
	ims->pdev = NULL;
	ims->default_cookie = (union msi_instance_cookie) { .value = 0 };
}
EXPORT_SYMBOL_GPL(vfio_pci_ims_free);

/*
 * Set unique cookie for vector.
 *
 * Context: Must be called after vfio_pci_ims_init()
 */
int vfio_pci_ims_set_cookie(struct vfio_device *vdev, unsigned int vector,
			    union msi_instance_cookie *icookie)
{
	struct vfio_pci_ims *ims = &vdev->ims;
	struct vfio_pci_ims_ctx *ctx;
	int ret = 0;

	pr_debug("%s:%d\n", __func__, __LINE__);
	mutex_lock(&ims->ctx_mutex);
	ctx = xa_load(&ims->ctx, vector);
	if (ctx) {
		if (WARN_ON_ONCE(ctx->emulated)) {
			ret = -EINVAL;
			goto out_unlock;
		}
		ctx->icookie = *icookie;
		goto out_unlock;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL_ACCOUNT);
	if (!ctx) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	ctx->icookie = *icookie;
	ret = xa_insert(&ims->ctx, vector, ctx, GFP_KERNEL_ACCOUNT);
	if (ret) {
		kfree(ctx);
		goto out_unlock;
	}

	ret = 0;

out_unlock:
	mutex_unlock(&ims->ctx_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(vfio_pci_ims_set_cookie);

/*
 * Set range of interrupts that will be emulated instead of backed by IMS.
 *
 * Return: error code on failure (-EBUSY if the vector is not available,
 * -ENOMEM on allocation failure), 0 on success
 */
int vfio_pci_ims_set_emulated(struct vfio_device *vdev, unsigned int start,
			      unsigned int count)
{
	struct vfio_pci_ims *ims = &vdev->ims;
	struct vfio_pci_ims_ctx *ctx;
	unsigned long i, j;
	int ret = 0;

	mutex_lock(&ims->ctx_mutex);

	for (i = start; i < start + count; i++) {
		ctx = kzalloc(sizeof(*ctx), GFP_KERNEL_ACCOUNT);
		if (!ctx) {
			ret = -ENOMEM;
			goto out_err;
		}
		ctx->emulated = true;
		ret = xa_insert(&ims->ctx, i, ctx, GFP_KERNEL_ACCOUNT);
		if (ret) {
			kfree(ctx);
			goto out_err;
		}
	}

	mutex_unlock(&ims->ctx_mutex);
	return 0;

out_err:
	for (j = start; j < i; j++) {
		ctx = xa_load(&ims->ctx, j);
		xa_erase(&ims->ctx, j);
		kfree(ctx);
	}
	mutex_unlock(&ims->ctx_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(vfio_pci_ims_set_emulated);

void vfio_dump_ims_entries(struct vfio_device *vdev)
{
	struct vfio_pci_ims *ims = &vdev->ims;
	struct vfio_pci_ims_ctx *ctx;
	unsigned long i;

	dev_dbg(&vdev->device, "IMS entries:\n");
	mutex_lock(&ims->ctx_mutex);
	xa_for_each(&ims->ctx, i, ctx) {
		dev_dbg(&vdev->device, "EventFD %lu: trigger=%px, name=%s, type=%s, ims_id=%d, virq=%d\n",
			i, ctx->trigger, ctx->name,
			ctx->emulated ? "emulated" : "ims", ctx->ims_id,
			ctx->virq);
	}
	mutex_unlock(&ims->ctx_mutex);
}
EXPORT_SYMBOL_GPL(vfio_dump_ims_entries);

/*
 * Return IMS index of IMS interrupt backing MSI-X interrupt @index
 */
int vfio_ims_msi_virq(struct vfio_device *vdev, int index)
{
	struct vfio_pci_ims *ims = &vdev->ims;
	struct vfio_pci_ims_ctx *ctx;
	unsigned long i;
	int virq = -1;

	dev_dbg(&vdev->device, "IMS entries:\n");
	mutex_lock(&ims->ctx_mutex);
	xa_for_each(&ims->ctx, i, ctx) {
		if (!ctx)
			break;

		if (i != index)
			continue;

		dev_dbg(&vdev->device, "EventFD %lu: trigger=%px, name=%s, type=%s, ims_id=%d, virq=%d\n",
			i, ctx->trigger, ctx->name,
			ctx->emulated ? "emulated" : "ims", ctx->ims_id,
			ctx->virq);
		virq = ctx->virq;
		break;
	}
	mutex_unlock(&ims->ctx_mutex);

	return virq;
}
EXPORT_SYMBOL_GPL(vfio_ims_msi_virq);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Intel Corporation");

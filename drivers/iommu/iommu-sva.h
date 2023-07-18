/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SVA library for IOMMU drivers
 */
#ifndef _IOMMU_SVA_H
#define _IOMMU_SVA_H

#include <linux/mm_types.h>

/* I/O Page fault */
struct device;
struct iommu_fault;
struct iopf_queue;

#ifdef CONFIG_IOMMU_SVA
int iommu_queue_iopf(struct iommu_fault *fault, struct device *dev);

int iopf_queue_add_device(struct iopf_queue *queue, struct device *dev);
int iopf_queue_remove_device(struct iopf_queue *queue,
			     struct device *dev);
int iopf_queue_flush_dev(struct device *dev);
struct iopf_queue *iopf_queue_alloc(const char *name);
void iopf_queue_free(struct iopf_queue *queue);
int iopf_queue_discard_partial(struct iopf_queue *queue);
void iopf_free_group(struct iopf_group *group);
int iopf_queue_work(struct iopf_group *group, work_func_t func);
int iommu_sva_handle_iopf_group(struct iopf_group *group);

#else /* CONFIG_IOMMU_SVA */
static inline int iommu_queue_iopf(struct iommu_fault *fault, struct device *dev)
{
	return -ENODEV;
}

static inline int iopf_queue_add_device(struct iopf_queue *queue,
					struct device *dev)
{
	return -ENODEV;
}

static inline int iopf_queue_remove_device(struct iopf_queue *queue,
					   struct device *dev)
{
	return -ENODEV;
}

static inline int iopf_queue_flush_dev(struct device *dev)
{
	return -ENODEV;
}

static inline struct iopf_queue *iopf_queue_alloc(const char *name)
{
	return NULL;
}

static inline void iopf_queue_free(struct iopf_queue *queue)
{
}

static inline int iopf_queue_discard_partial(struct iopf_queue *queue)
{
	return -ENODEV;
}

static inline void iopf_free_group(struct iopf_group *group)
{
}

static inline int iopf_queue_work(struct iopf_group *group, work_func_t func)
{
	return -ENODEV;
}

static inline int iommu_sva_handle_iopf_group(struct iopf_group *group)
{
	return -ENODEV;
}
#endif /* CONFIG_IOMMU_SVA */
#endif /* _IOMMU_SVA_H */

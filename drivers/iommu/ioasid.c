// SPDX-License-Identifier: GPL-2.0
/*
 * I/O Address Space ID allocator. There is one global IOASID space, split into
 * sets. Users create a set with ioasid_set_alloc, then allocate/free IDs
 * with ioasid_alloc, ioasid_put, and ioasid_put.
 */
#define DEBUG
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/ioasid.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>
#include <linux/sched/mm.h>

/* Default to PCIe standard 20 bit PASID */
#define PCI_PASID_MAX 0x100000
//static ioasid_t ioasid_capacity = PCI_PASID_MAX;
static ioasid_t ioasid_capacity_avail = PCI_PASID_MAX;
static DEFINE_XARRAY_ALLOC(ioasid_sets);

/**
 * struct ioasid_data - Meta data about ioasid
 *
 * @id:		Unique ID
 * @spid:	Private ID unique within a set
 * @refs:	Number of active users
 * @set:	ioasid_set of the IOASID belongs to
 * @private:	Private data associated with the IOASID
 * @rcu:	For free after RCU grace period
 */
struct ioasid_data {
	ioasid_t id;
	ioasid_t spid;
	struct ioasid_set *set;
	void *private;
	struct rcu_head rcu;
	refcount_t refs;
};

/*
 * struct ioasid_allocator_data - Internal data structure to hold information
 * about an allocator. There are two types of allocators:
 *
 * - Default allocator always has its own XArray to track the IOASIDs allocated.
 * - Custom allocators may share allocation helpers with different private data.
 *   Custom allocators that share the same helper functions also share the same
 *   XArray.
 * Rules:
 * 1. Default allocator is always available, not dynamically registered. This is
 *    to prevent race conditions with early boot code that want to register
 *    custom allocators or allocate IOASIDs.
 * 2. Custom allocators take precedence over the default allocator.
 * 3. When all custom allocators sharing the same helper functions are
 *    unregistered (e.g. due to hotplug), all outstanding IOASIDs must be
 *    freed. Otherwise, outstanding IOASIDs will be lost and orphaned.
 * 4. When switching between custom allocators sharing the same helper
 *    functions, outstanding IOASIDs are preserved.
 * 5. When switching between custom allocator and default allocator, all IOASIDs
 *    must be freed to ensure unadulterated space for the new allocator.
 *
 * @ops:	allocator helper functions and its data
 * @list:	registered custom allocators
 * @slist:	allocators share the same ops but different data
 * @flags:	attributes of the allocator
 * @xa:		xarray holds the IOASID space
 * @rcu:	used for kfree_rcu when unregistering allocator
 */
struct ioasid_allocator_data {
	struct ioasid_allocator_ops *ops;
	struct list_head list;
	struct list_head slist;
#define IOASID_ALLOCATOR_CUSTOM BIT(0) /* Needs framework to track results */
	unsigned long flags;
	struct xarray xa;
	struct rcu_head rcu;
};

static DEFINE_SPINLOCK(ioasid_allocator_lock);
static LIST_HEAD(allocators_list);

static ioasid_t default_alloc(ioasid_t min, ioasid_t max, void *opaque);
static void default_free(ioasid_t ioasid, void *opaque);

static struct ioasid_allocator_ops default_ops = {
	.alloc = default_alloc,
	.free = default_free,
};

static struct ioasid_allocator_data default_allocator = {
	.ops = &default_ops,
	.flags = 0,
	.xa = XARRAY_INIT(ioasid_xa, XA_FLAGS_ALLOC),
};

static struct ioasid_allocator_data *active_allocator = &default_allocator;

static ioasid_t default_alloc(ioasid_t min, ioasid_t max, void *opaque)
{
	ioasid_t id;

	if (xa_alloc(&default_allocator.xa, &id, opaque, XA_LIMIT(min, max), GFP_ATOMIC)) {
		pr_err("Failed to alloc ioasid from %d to %d\n", min, max);
		return INVALID_IOASID;
	}

	return id;
}

static void default_free(ioasid_t ioasid, void *opaque)
{
	struct ioasid_data *ioasid_data;

	ioasid_data = xa_erase(&default_allocator.xa, ioasid);
	kfree_rcu(ioasid_data, rcu);
}

/* Allocate and initialize a new custom allocator with its helper functions */
static struct ioasid_allocator_data *ioasid_alloc_allocator(struct ioasid_allocator_ops *ops)
{
	struct ioasid_allocator_data *ia_data;

	ia_data = kzalloc(sizeof(*ia_data), GFP_ATOMIC);
	if (!ia_data)
		return NULL;

	xa_init_flags(&ia_data->xa, XA_FLAGS_ALLOC);
	INIT_LIST_HEAD(&ia_data->slist);
	ia_data->flags |= IOASID_ALLOCATOR_CUSTOM;
	ia_data->ops = ops;

	/* For tracking custom allocators that share the same ops */
	list_add_tail(&ops->list, &ia_data->slist);

	return ia_data;
}

static bool use_same_ops(struct ioasid_allocator_ops *a, struct ioasid_allocator_ops *b)
{
	return (a->free == b->free) && (a->alloc == b->alloc);
}

/**
 * ioasid_register_allocator - register a custom allocator
 * @ops: the custom allocator ops to be registered
 *
 * Custom allocators take precedence over the default xarray based allocator.
 * Private data associated with the IOASID allocated by the custom allocators
 * are managed by IOASID framework similar to data stored in xa by default
 * allocator.
 *
 * There can be multiple allocators registered but only one is active. In case
 * of runtime removal of a custom allocator, the next one is activated based
 * on the registration ordering.
 *
 * Multiple allocators can share the same alloc() function, in this case the
 * IOASID space is shared.
 */
int ioasid_register_allocator(struct ioasid_allocator_ops *ops)
{
	struct ioasid_allocator_data *ia_data;
	struct ioasid_allocator_data *pallocator;
	int ret = 0;

	spin_lock(&ioasid_allocator_lock);

	ia_data = ioasid_alloc_allocator(ops);
	if (!ia_data) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/*
	 * No particular preference, we activate the first one and keep
	 * the later registered allocators in a list in case the first one gets
	 * removed due to hotplug.
	 */
	if (list_empty(&allocators_list)) {
		WARN_ON(active_allocator != &default_allocator);
		/* Use this new allocator if default is not active */
		if (xa_empty(&active_allocator->xa)) {
			rcu_assign_pointer(active_allocator, ia_data);
			list_add_tail(&ia_data->list, &allocators_list);
			goto out_unlock;
		}
		pr_warn("Default allocator active with outstanding IOASID\n");
		ret = -EAGAIN;
		goto out_free;
	}

	/* Check if the allocator is already registered */
	list_for_each_entry(pallocator, &allocators_list, list) {
		if (pallocator->ops == ops) {
			pr_err("IOASID allocator already registered\n");
			ret = -EEXIST;
			goto out_free;
		} else if (use_same_ops(pallocator->ops, ops)) {
			/*
			 * If the new allocator shares the same ops,
			 * then they will share the same IOASID space.
			 * We should put them under the same xarray.
			 */
			list_add_tail(&ops->list, &pallocator->slist);
			goto out_free;
		}
	}
	list_add_tail(&ia_data->list, &allocators_list);

	spin_unlock(&ioasid_allocator_lock);
	return 0;
out_free:
	kfree(ia_data);
out_unlock:
	spin_unlock(&ioasid_allocator_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(ioasid_register_allocator);

/**
 * ioasid_unregister_allocator - Remove a custom IOASID allocator ops
 * @ops: the custom allocator to be removed
 *
 * Remove an allocator from the list, activate the next allocator in
 * the order it was registered. Or revert to default allocator if all
 * custom allocators are unregistered without outstanding IOASIDs.
 */
void ioasid_unregister_allocator(struct ioasid_allocator_ops *ops)
{
	struct ioasid_allocator_data *pallocator;
	struct ioasid_allocator_ops *sops;

	spin_lock(&ioasid_allocator_lock);
	if (list_empty(&allocators_list)) {
		pr_warn("No custom IOASID allocators active!\n");
		goto exit_unlock;
	}

	list_for_each_entry(pallocator, &allocators_list, list) {
		if (!use_same_ops(pallocator->ops, ops))
			continue;

		if (list_is_singular(&pallocator->slist)) {
			/* No shared helper functions */
			list_del(&pallocator->list);
			/*
			 * All IOASIDs should have been freed before
			 * the last allocator that shares the same ops
			 * is unregistered.
			 */
			WARN_ON(!xa_empty(&pallocator->xa));
			if (list_empty(&allocators_list)) {
				pr_info("No custom IOASID allocators, switch to default.\n");
				rcu_assign_pointer(active_allocator, &default_allocator);
			} else if (pallocator == active_allocator) {
				rcu_assign_pointer(active_allocator,
						list_first_entry(&allocators_list,
								struct ioasid_allocator_data, list));
				pr_info("IOASID allocator changed");
			}
			kfree_rcu(pallocator, rcu);
			break;
		}
		/*
		 * Find the matching shared ops to delete,
		 * but keep outstanding IOASIDs
		 */
		list_for_each_entry(sops, &pallocator->slist, list) {
			if (sops == ops) {
				list_del(&ops->list);
				break;
			}
		}
		break;
	}

exit_unlock:
	spin_unlock(&ioasid_allocator_lock);
}
EXPORT_SYMBOL_GPL(ioasid_unregister_allocator);

/**
 * ioasid_attach_data - Set private data for an allocated ioasid
 * @ioasid: the ID to set data
 * @data:   the private data
 *
 * For IOASID that is already allocated, private data can be set
 * via this API. Future lookup can be done via ioasid_find.
 */
int ioasid_attach_data(ioasid_t ioasid, void *data)
{
	struct ioasid_data *ioasid_data;
	int ret = 0;

	spin_lock(&ioasid_allocator_lock);
	ioasid_data = xa_load(&active_allocator->xa, ioasid);

	if (!ioasid_data) {
		ret = -ENOENT;
		goto done_unlock;
	}

	if (ioasid_data->private) {
		ret = -EBUSY;
		goto done_unlock;
	}
	rcu_assign_pointer(ioasid_data->private, data);

done_unlock:
	spin_unlock(&ioasid_allocator_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(ioasid_attach_data);

/**
 * ioasid_detach_data - Clear the private data of an ioasid
 *
 * @ioasid: the IOASIDD to clear private data
 */
void ioasid_detach_data(ioasid_t ioasid)
{
	struct ioasid_data *ioasid_data;

	spin_lock(&ioasid_allocator_lock);
	ioasid_data = xa_load(&active_allocator->xa, ioasid);

	if (!ioasid_data) {
		pr_warn("IOASID %u not found to detach data from\n", ioasid);
		goto done_unlock;
	}

	if (ioasid_data->private) {
		rcu_assign_pointer(ioasid_data->private, NULL);
		goto done_unlock;
	}

done_unlock:
	spin_unlock(&ioasid_allocator_lock);
	/*
	 * Wait for readers to stop accessing the old private data,
	 * so the caller can free it.
	 */
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(ioasid_detach_data);

static ioasid_t ioasid_find_by_spid_locked(struct ioasid_set *set, ioasid_t spid, bool get)
{
	ioasid_t ioasid = INVALID_IOASID;
	struct ioasid_data *entry;
	unsigned long index;

	if (!xa_load(&ioasid_sets, set->id)) {
		pr_warn("Invalid set\n");
		goto done;
	}

	xa_for_each(&set->xa, index, entry) {
		if (spid == entry->spid) {
			if (get)
				refcount_inc(&entry->refs);
			ioasid = index;
		}
	}
done:
	return ioasid;
}

/**
 * ioasid_attach_spid - Attach ioasid_set private ID to an IOASID
 *
 * @ioasid: the system-wide IOASID to attach
 * @spid:   the ioasid_set private ID of @ioasid
 *
 * After attching SPID, future lookup can be done via ioasid_find_by_spid().
 */
int ioasid_attach_spid(ioasid_t ioasid, ioasid_t spid)
{
	struct ioasid_data *data;
	int ret = 0;

	if (spid == INVALID_IOASID)
		return -EINVAL;

	spin_lock(&ioasid_allocator_lock);
	data = xa_load(&active_allocator->xa, ioasid);

	if (!data) {
		pr_err("No IOASID entry %d to attach SPID %d\n",
			ioasid, spid);
		ret = -ENOENT;
		goto done_unlock;
	}
	/* Check if SPID is unique within the set */
	if (ioasid_find_by_spid_locked(data->set, spid, false) != INVALID_IOASID) {
		ret = -EINVAL;
		goto done_unlock;
	}
	data->spid = spid;

done_unlock:
	spin_unlock(&ioasid_allocator_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(ioasid_attach_spid);

void ioasid_detach_spid(ioasid_t ioasid)
{
	struct ioasid_data *data;

	spin_lock(&ioasid_allocator_lock);
	data = xa_load(&active_allocator->xa, ioasid);

	if (!data || data->spid == INVALID_IOASID) {
		pr_err("Invalid IOASID entry %d to detach\n", ioasid);
		goto done_unlock;
	}

	data->spid = INVALID_IOASID;
done_unlock:
	spin_unlock(&ioasid_allocator_lock);
}
EXPORT_SYMBOL_GPL(ioasid_detach_spid);

/**
 * ioasid_find_by_spid - Find the system-wide IOASID by a set private ID and
 * its set.
 *
 * @set:	the ioasid_set to search within
 * @spid:	the set private ID
 * @get:	flag indicates whether to take a reference once found
 *
 * Given a set private ID and its IOASID set, find the system-wide IOASID. Take
 * a reference upon finding the matching IOASID if @get is true. Return
 * INVALID_IOASID if the IOASID is not found in the set or the set is not valid.
 */
ioasid_t ioasid_find_by_spid(struct ioasid_set *set, ioasid_t spid, bool get)
{
	ioasid_t ioasid;

	spin_lock(&ioasid_allocator_lock);
	ioasid = ioasid_find_by_spid_locked(set, spid, get);
	spin_unlock(&ioasid_allocator_lock);
	return ioasid;
}
EXPORT_SYMBOL_GPL(ioasid_find_by_spid);

static inline bool ioasid_set_is_valid(struct ioasid_set *set)
{
	return xa_load(&ioasid_sets, set->id) == set;
}

/**
 * ioasid_set_alloc - Allocate a new IOASID set for a given token
 *
 * @token:	An optional arbitrary number that can be associated with the
 *		IOASID set. @token can be NULL if the type is
 *		IOASID_SET_TYPE_NONE
 * @quota:	Quota allowed in this set, 0 indicates no limit for the set
 * @type:	The type of the token used to create the IOASID set
 *
 * IOASID is limited system-wide resource that requires quota management.
 * Token will be stored in the ioasid_set returned. A reference will be taken
 * on the newly created set. Subsequent IOASID allocation within the set need
 * to use the returned ioasid_set pointer.
 */
struct ioasid_set *ioasid_set_alloc(void *token, ioasid_t quota)
{
	struct ioasid_set *set;
	unsigned long index;
	ioasid_t id;

	if (!token)
		return ERR_PTR(-EINVAL);

	/* No limit for the set, use whatever is available on the system */
	if (!quota)
		quota = ioasid_capacity_avail;

	if (quota > ioasid_capacity_avail) {
		pr_warn("Out of IOASID capacity! ask %d, avail %d\n",
			quota, ioasid_capacity_avail);
		set = ERR_PTR(-ENOSPC);
		goto exit_unlock;
	}

	spin_lock(&ioasid_allocator_lock);
	/* Search existing set tokens, reject duplicates */
	xa_for_each(&ioasid_sets, index, set) {
		if (set->token == token) {
			pr_warn("IOASID set exists for this token\n");
			set = ERR_PTR(-EEXIST);
			goto exit_unlock;
		}
	}
	set = kzalloc(sizeof(*set), GFP_ATOMIC);
	if (!set) {
		set = ERR_PTR(-ENOMEM);
		goto exit_unlock;
	}

	if (xa_alloc(&ioasid_sets, &id, set,
		     XA_LIMIT(0, ioasid_capacity_avail),
		     GFP_ATOMIC)) {
		kfree(set);
		set = ERR_PTR(-ENOSPC);
		goto exit_unlock;
	}

	set->token = token;
	set->quota = quota;
	set->id = id;
	atomic_set(&set->nr_ioasids, 0);

	/*
	 * Per set XA is used to store private IDs within the set, get ready
	 * for ioasid_set private ID and system-wide IOASID allocation
	 * results.
	 */
	xa_init(&set->xa);
	ioasid_capacity_avail -= quota;

exit_unlock:
	spin_unlock(&ioasid_allocator_lock);

	return set;
}
EXPORT_SYMBOL_GPL(ioasid_set_alloc);

struct ioasid_set *ioasid_set_alloc_with_mm(struct mm_struct *mm, ioasid_t quota)
{
	struct ioasid_set *iset;

	iset = ioasid_set_alloc(mm, quota);
	if (!IS_ERR(iset)) {
		mmgrab(mm);
		iset->type = IOASID_SET_TYPE_MM;
		pr_debug("%s: set %p id %d", __func__, iset, iset->id);
	}
	return iset;
}
EXPORT_SYMBOL_GPL(ioasid_set_alloc_with_mm);

/**
 * @brief ioasid_find_mm_set - Retrieve IOASID set with mm token
 * 	  mm user reference of the set should be taken if found.
 *
 */
struct ioasid_set *ioasid_find_mm_set(struct mm_struct *token)
{
	struct ioasid_set *set = NULL;
	unsigned long index;

	spin_lock(&ioasid_allocator_lock);

	xa_for_each(&ioasid_sets, index, set) {
		if (set->type == IOASID_SET_TYPE_MM && set->token == token)
			break;
	}
	spin_unlock(&ioasid_allocator_lock);
	pr_debug("%s: set %p", __func__, set);;

	return set;
}
EXPORT_SYMBOL_GPL(ioasid_find_mm_set);

static void __ioasid_set_destroy(struct ioasid_set *set)
{
	pr_debug("%s: ID %d", __func__, set->id);
	xa_destroy(&set->xa);
	xa_erase(&ioasid_sets, set->id);
	if (set->type == IOASID_SET_TYPE_MM)
		mmdrop(set->token);
	kfree_rcu(set, rcu);
}

/**
 * @brief Destroy and free an ioasid_set
 * 	The set is freed immediately, caller should make sure the set is empty.
 * 	IOASID user to drop its references and free data before calling this
 * 	function.
 *
 * @param set to be freed
 */
void ioasid_set_destroy(struct ioasid_set *set)
{
	pr_debug("%s: ID %d", __func__, set->id);

	if (WARN_ON(IS_ERR_OR_NULL(set)))
		return;

	if (WARN_ON(!ioasid_set_is_valid(set)) || set->free_pending)
		return;

	spin_lock(&ioasid_allocator_lock);
	if (atomic_read(&set->nr_ioasids) || !xa_empty(&set->xa)) {
		pr_alert("Destroy non-empty ioasid set %d", set->id);
		/* Mark the set as being destroyed, no new allocations.*/
		set->free_pending = true;
		spin_unlock(&ioasid_allocator_lock);
		return;
	}
	__ioasid_set_destroy(set);
	spin_unlock(&ioasid_allocator_lock);
}
EXPORT_SYMBOL_GPL(ioasid_set_destroy);

/**
 * ioasid_alloc - Allocate an IOASID
 * @set: the IOASID set to allocate from, NULL means allocate from the
 * 	 global pool
 * @min: the minimum ID (inclusive)
 * @max: the maximum ID (inclusive)
 * @private: data private to the caller
 * @spid: set private ID, sub-ID belong to the set namespace, 1:1 mapped
 * 	  to the IOASID allocated.
 *
 * Allocate an ID between @min and @max. The @private pointer is stored
 * internally and can be retrieved with ioasid_find().
 *
 * Return: the allocated ID on success, or %INVALID_IOASID on failure.
 */
ioasid_t ioasid_alloc(struct ioasid_set *set, ioasid_t min, ioasid_t max,
		      void *private, ioasid_t spid)
{
	struct ioasid_data *data;
	void *adata;
	ioasid_t id = INVALID_IOASID;

	spin_lock(&ioasid_allocator_lock);
	/* Check if the IOASID set has been allocated and initialized */
	if (set) {
		if (!ioasid_set_is_valid(set) || set->free_pending) {
			pr_warn("IOASID set is invalid or being freed.");
			goto done_unlock;
		}
		if (set->quota <= atomic_read(&set->nr_ioasids)) {
			pr_err_ratelimited("IOASID set out of quota %d\n",
					   set->quota);
			goto done_unlock;
		}
		if (spid && (ioasid_find_by_spid_locked(set, spid, false) != INVALID_IOASID)) {
			pr_err_ratelimited("SPID exists in IOASID set %d\n",
					   set->id);
			goto done_unlock;
		}
	} else {
		/*
		 * NULL set should not have SPID, no where to store the
		 * mapping between SPID and IOASID.
		 */
		WARN_ON(spid);
		spid = INVALID_IOASID;
	}

	data = kzalloc(sizeof(*data), GFP_ATOMIC);
	if (!data)
		goto done_unlock;

	data->set = set;
	data->private = private;
	refcount_set(&data->refs, 1);

	/*
	 * Custom allocator needs allocator data to perform platform specific
	 * operations.
	 */
	adata = active_allocator->flags & IOASID_ALLOCATOR_CUSTOM ? active_allocator->ops->pdata : data;
	id = active_allocator->ops->alloc(min, max, adata);
	if (id == INVALID_IOASID) {
		pr_err("Failed ASID allocation %lu\n", active_allocator->flags);
		goto exit_free;
	}

	if ((active_allocator->flags & IOASID_ALLOCATOR_CUSTOM) &&
	     xa_alloc(&active_allocator->xa, &id, data, XA_LIMIT(id, id), GFP_ATOMIC)) {
		/* Custom allocator needs framework to store and track allocation results */
		pr_err("Failed to alloc ioasid from %d\n", id);
		active_allocator->ops->free(id, active_allocator->ops->pdata);
		goto exit_free;
	}
	data->id = id;
	data->spid = spid;

	/*
	 * For NULL set, PASID belongs to the global pool, not stored in per
	 * set xa
	 */
	if (!set) {
		pr_debug("%s: IOASID %d no set", __func__, id);
		goto done_unlock;
	}
	/* Store IOASID in the per set data */
	if (xa_err(xa_store(&set->xa, id, data, GFP_ATOMIC))) {
		pr_err_ratelimited("Failed to store ioasid %d in set\n", id);
		active_allocator->ops->free(id, active_allocator->ops->pdata);
		goto exit_free;
	}
	atomic_inc(&set->nr_ioasids);
	pr_debug("%s: IOASID %d SID %d", __func__, id, set->id);

	goto done_unlock;
exit_free:
	kfree(data);
done_unlock:
	spin_unlock(&ioasid_allocator_lock);
	return id;
}
EXPORT_SYMBOL_GPL(ioasid_alloc);

static void ioasid_do_free_locked(struct ioasid_data *data)
{
	struct ioasid_data *ioasid_data;

	pr_debug("%s: IOASID %d", __func__, data->id);
	active_allocator->ops->free(data->id, active_allocator->ops->pdata);
	/* Custom allocator needs additional steps to free the xa element */
	if (active_allocator->flags & IOASID_ALLOCATOR_CUSTOM) {
		ioasid_data = xa_erase(&active_allocator->xa, data->id);
		kfree_rcu(ioasid_data, rcu);
	}
	/* If the IOASID belongs to a set, check if we need to free the set */
	if (!data->set)
		return;

	xa_erase(&data->set->xa, data->id);
	/* If the set is already marked as free_pending, destroy it */
	if (atomic_dec_and_test(&data->set->nr_ioasids) &&
	    data->set->free_pending)
		__ioasid_set_destroy(data->set);
}

int ioasid_get_locked(struct ioasid_set *set, ioasid_t ioasid)
{
	struct ioasid_data *data;

	data = xa_load(&active_allocator->xa, ioasid);
	if (!data) {
		pr_err("Trying to get unknown IOASID %u\n", ioasid);
		return -EINVAL;
	}

	/* Check set ownership if the set is non-null */
	if (set && data->set != set) {
		pr_err("Trying to get IOASID %u outside the set\n", ioasid);
		/* data found but does not belong to the set */
		return -EACCES;
	}
	refcount_inc(&data->refs);

	return 0;
}
EXPORT_SYMBOL_GPL(ioasid_get_locked);

/**
 * ioasid_get - obtain a reference to the IOASID
 * @set:	the ioasid_set to check permission against if not NULL
 * @ioasid:	the IOASID to get reference
 *
 *
 * Return: 0 on success, error if failed.
 */
int ioasid_get(struct ioasid_set *set, ioasid_t ioasid)
{
	int ret;

	spin_lock(&ioasid_allocator_lock);
	ret = ioasid_get_locked(set, ioasid);
	spin_unlock(&ioasid_allocator_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(ioasid_get);

void ioasid_put_locked(struct ioasid_set *set, ioasid_t ioasid)
{
	struct ioasid_data *data;

	data = xa_load(&active_allocator->xa, ioasid);
	if (!data) {
		pr_err_ratelimited("Trying to free unknown IOASID %u\n", ioasid);
		return;
	}

	/* NULL set argument means no ownership check */
	if (set && data->set != set) {
		pr_warn("Cannot free IOASID %u due to set ownership\n", ioasid);
		return;
	}

	/*
	 * If the refcount is 1, it means there is no other users of the IOASID
	 * other than IOASID core itself. There is no need to notify anyone.
	 */
	if (!refcount_dec_and_test(&data->refs))
		return;

	ioasid_do_free_locked(data);
	pr_info("PASID %d freed", ioasid);
}
EXPORT_SYMBOL_GPL(ioasid_put_locked);

/**
 * ioasid_put - Drop reference on an IOASID. Free if refcount drops to 0,
 *               including free from its set and system-wide list.
 * @set:	The ioasid_set to check permission with. If not NULL, IOASID
 *		free will fail if the set does not match.
 * @ioasid:	The IOASID to remove
 *
 * TODO: return true if all references dropped, false if async work is in
 * progress, IOASID is in FREE_PENDING state. wait queue to be used for blocking
 * free task.
 */
void ioasid_put(struct ioasid_set *set, ioasid_t ioasid)
{
	spin_lock(&ioasid_allocator_lock);
	ioasid_put_locked(set, ioasid);
	spin_unlock(&ioasid_allocator_lock);
}
EXPORT_SYMBOL_GPL(ioasid_put);

void __ioasid_put(ioasid_t ioasid)
{
	ioasid_put(NULL, ioasid);
}
EXPORT_SYMBOL_GPL(__ioasid_put);

/**
 * ioasid_put_all_in_set
 *
 * @brief
 * Drop reference to all PASIDs in the ioasid_set
 *
 * Note that some references of the IOASIDs within the set can still
 * be held after this call. The set is still active.
 *
 * @param
 * struct ioasid_set where all IOASIDs within the set will be dropped.
 */
void ioasid_put_all_in_set(struct ioasid_set *set)
{
	struct ioasid_data *entry;
	unsigned long index;

	if (!ioasid_set_is_valid(set))
		return;

	if (xa_empty(&set->xa))
		return;

	if (!atomic_read(&set->nr_ioasids))
		return;
	spin_lock(&ioasid_allocator_lock);
	xa_for_each(&set->xa, index, entry) {
		ioasid_do_free_locked(entry);
		/* Free from per set private pool */
		xa_erase(&set->xa, index);
	}
	spin_unlock(&ioasid_allocator_lock);
}
EXPORT_SYMBOL_GPL(ioasid_put_all_in_set);

/**
 * ioasid_find - Find IOASID data
 * @set: the IOASID set
 * @ioasid: the IOASID to find
 * @getter: function to call on the found object
 *
 * The optional getter function allows to take a reference to the found object
 * under the rcu lock. The function can also check if the object is still valid:
 * if @getter returns false, then the object is invalid and NULL is returned.
 *
 * If the IOASID exists, return the private pointer passed to ioasid_alloc.
 * Private data can be NULL if not set. Return an error if the IOASID is not
 * found, or if @set is not NULL and the IOASID does not belong to the set.
 */
void *ioasid_find(struct ioasid_set *set, ioasid_t ioasid,
		  bool (*getter)(void *))
{
	void *priv;
	struct ioasid_data *ioasid_data;
	struct ioasid_allocator_data *idata;

	rcu_read_lock();
	idata = rcu_dereference(active_allocator);
	ioasid_data = xa_load(&idata->xa, ioasid);
	if (!ioasid_data) {
		priv = ERR_PTR(-ENOENT);
		goto unlock;
	}
	if (set && ioasid_data->set != set) {
		/* data found but does not belong to the set */
		priv = ERR_PTR(-EACCES);
		goto unlock;
	}
	/* Now IOASID and its set is verified, we can return the private data */
	priv = rcu_dereference(ioasid_data->private);
	if (getter && !getter(priv))
		priv = NULL;
unlock:
	rcu_read_unlock();

	return priv;
}
EXPORT_SYMBOL_GPL(ioasid_find);

MODULE_AUTHOR("Jean-Philippe Brucker <jean-philippe.brucker@arm.com>");
MODULE_AUTHOR("Jacob Pan <jacob.jun.pan@linux.intel.com>");
MODULE_DESCRIPTION("IO Address Space ID (IOASID) allocator");
MODULE_LICENSE("GPL");

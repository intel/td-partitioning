// SPDX-License-Identifier: GPL-2.0-only
#include "firmware.h"
struct kvm_firmware *kvm_firmware;

struct kvm_firmware *kvm_register_fw(int fw_id)
{
	struct kvm_firmware *kvm_fw;

	if (kvm_firmware)
		return ERR_PTR(-EEXIST);

	kvm_fw = kzalloc(sizeof(*kvm_fw), GFP_KERNEL);
	if (!kvm_fw)
		return ERR_PTR(-ENOMEM);

	kvm_fw->id = fw_id;
	spin_lock_init(&kvm_fw->lock);
	INIT_LIST_HEAD(&kvm_fw->vm_list);

	kvm_firmware = kvm_fw;
	init_srcu_struct(&kvm_fw->srcu);
	init_completion(&kvm_fw->completion);

	return kvm_fw;
}
EXPORT_SYMBOL_GPL(kvm_register_fw);

int kvm_unregister_fw(struct kvm_firmware *fw)
{
	bool empty;

	spin_lock(&fw->lock);
	empty = list_empty(&fw->vm_list);
	spin_unlock(&fw->lock);

	if (!empty)
		return -EBUSY;

	cleanup_srcu_struct(&fw->srcu);
	kfree(fw);
	kvm_firmware = NULL;

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_unregister_fw);

__weak bool kvm_arch_match_fw(struct kvm *kvm, struct kvm_firmware *fw)
{
	return false;
}

void kvm_attach_fw(struct kvm *kvm)
{
	int fw_idx;
	if (!kvm_arch_match_fw(kvm, kvm_firmware))
		return;

	kvm->fw = kvm_firmware;

	/* Get the firmware to prevent firmware update */
	fw_idx = kvm_get_fw(kvm);
	spin_lock(&kvm_firmware->lock);
	list_add(&kvm->fw_list, &kvm_firmware->vm_list);
	spin_unlock(&kvm_firmware->lock);
	kvm_put_fw(kvm, fw_idx);
}

void kvm_detach_fw(struct kvm *kvm)
{
	int fw_idx;

	/* Get the firmware to prevent firmware update */
	fw_idx = kvm_get_fw(kvm);
	if (kvm->fw) {
		spin_lock(&kvm->fw->lock);
		list_del(&kvm->fw_list);
		spin_unlock(&kvm->fw->lock);
	}
	kvm_put_fw(kvm, fw_idx);
	kvm->fw = NULL;
}

int kvm_get_fw(struct kvm *kvm)
{
	int idx;

	might_sleep();

	if (!kvm->fw)
		return 0;

	idx = srcu_read_lock(&kvm->fw->srcu);
	while (kvm->fw->update) {
		srcu_read_unlock(&kvm->fw->srcu, idx);
		wait_for_completion(&kvm->fw->completion);
		idx = srcu_read_lock(&kvm->fw->srcu);
	}

	return idx;
}

void kvm_put_fw(struct kvm *kvm, int idx)
{
	if (!kvm->fw)
		return;

	srcu_read_unlock(&kvm->fw->srcu, idx);
}

__weak void kvm_arch_start_update_fw(struct kvm *kvm)
{
}

__weak void kvm_arch_end_update_fw(struct kvm *kvm)
{
}

__weak int kvm_arch_update_fw(struct kvm_firmware *fw, bool live_update)
{
	return 0;
}

static void kvm_start_update_fw(struct kvm_firmware *fw)
{
	struct kvm *kvm;

	init_completion(&fw->completion);

	fw->update = true;

	spin_lock(&fw->lock);
	list_for_each_entry(kvm, &fw->vm_list, fw_list)
		kvm_arch_start_update_fw(kvm);
	spin_unlock(&fw->lock);

	synchronize_srcu(&fw->srcu);
}

static void kvm_end_update_fw(struct kvm_firmware *fw)
{
	struct kvm *kvm;

	fw->update = false;
	synchronize_srcu(&fw->srcu);

	complete_all(&fw->completion);

	spin_lock(&fw->lock);
	list_for_each_entry(kvm, &fw->vm_list, fw_list)
		kvm_arch_end_update_fw(kvm);
	spin_unlock(&fw->lock);
}

int kvm_update_fw(struct kvm_firmware *fw)
{
	int ret;
	bool empty;

	if (!fw)
		return -EINVAL;

	/*
	 * Some firmware (e.g., TDX module) update needs virtualization
	 * extension enabled.
	 */
	ret = hardware_enable_all();
	if (ret)
		return ret;

	kvm_start_update_fw(fw);

	spin_lock(&fw->lock);
	empty = list_empty(&fw->vm_list);
	spin_unlock(&fw->lock);

	ret = kvm_arch_update_fw(fw, !empty);

	kvm_end_update_fw(fw);
	hardware_disable_all();

	return ret;
}
EXPORT_SYMBOL_GPL(kvm_update_fw);

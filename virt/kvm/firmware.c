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
	if (!kvm_arch_match_fw(kvm, kvm_firmware))
		return;

	kvm->fw = kvm_firmware;
	spin_lock(&kvm_firmware->lock);
	list_add(&kvm->fw_list, &kvm_firmware->vm_list);
	spin_unlock(&kvm_firmware->lock);
}

void kvm_detach_fw(struct kvm *kvm)
{
	if (kvm->fw) {
		spin_lock(&kvm->fw->lock);
		list_del(&kvm->fw_list);
		spin_unlock(&kvm->fw->lock);
	}
}

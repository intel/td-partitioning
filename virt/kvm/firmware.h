/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_FIRMWARE_H
#define __KVM_FIRMWARE_H
#include <linux/kvm_host.h>

#ifdef CONFIG_HAVE_KVM_FIRMWARE
void kvm_attach_fw(struct kvm *kvm);
void kvm_detach_fw(struct kvm *kvm);
int kvm_get_fw(struct kvm *kvm);
void kvm_put_fw(struct kvm *kvm, int idx);
#else
static inline void kvm_attach_fw(struct kvm *kvm) {}
static inline void kvm_detach_fw(struct kvm *kvm) {}
static inline int kvm_get_fw(struct kvm *kvm) { return 0; }
static inline void kvm_put_fw(struct kvm *kvm, int idx) {}
#endif

#endif

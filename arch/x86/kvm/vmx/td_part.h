/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TD_PART_H
#define __KVM_X86_TD_PART_H

extern bool enable_td_part;

#ifdef CONFIG_INTEL_TD_PART_GUEST
static inline bool is_td_part(struct kvm *kvm)
{
	return kvm->arch.vm_type == KVM_X86_TD_PART_VM;
}

static inline bool is_td_part_vcpu(struct kvm_vcpu *vcpu)
{
	return is_td_part(vcpu->kvm);
}

#else /* CONFIG_INTEL_TD_PART_GUEST */

static inline bool is_td_part(struct kvm *kvm) { return false; }
static inline bool is_td_part_vcpu(struct kvm_vcpu *vcpu) { return false; }
#endif /* CONFIG_INTEL_TD_PART_GUEST */

#endif /* __KVM_X86_TD_PART_H */

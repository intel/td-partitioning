// SPDX-License-Identifier: GPL-2.0

#include "x86_ops.h"
#include "vmx.h"
#include "common.h"
#include "td_part.h"

bool td_part_is_vm_type_supported(unsigned long type)
{
	return type == KVM_X86_TD_PART_VM;
}

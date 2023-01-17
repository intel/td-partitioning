/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/asm-offsets.h>
#include <asm/tdx.h>
#include <asm/asm.h>

/*
 * TDCALL and SEAMCALL are supported in Binutils >= 2.36.
 */
#define tdcall		.byte 0x66,0x0f,0x01,0xcc
#define seamcall	.byte 0x66,0x0f,0x01,0xcf

/*
 * TDX_MODULE_CALL - common helper macro for both
 *                 TDCALL and SEAMCALL instructions.
 *
 * TDCALL   - used by TDX guests to make requests to the
 *            TDX module and hypercalls to the VMM.
 * SEAMCALL - used by TDX hosts to make requests to the
 *            TDX module.
 */
.macro TDX_MODULE_CALL host:req
	/*
	 * R15 will be used as temporary storage for struct tdx_module_output
	 * pointer. Since R14-R15 registers are not used by TDCALL/SEAMCALL
	 * services supported by this function, it can be reused.
	 */

	/* Callee saved, so preserve it */
	push %r10
	push %r11
	push %r12
	push %r13
	push %r15

	/* Move output pointer to R15 */
	mov (FRAME_OFFSET+0x48)(%rsp), %r15

	/* Mangle function call ABI into TDCALL/SEAMCALL ABI: */
	/* Move Leaf ID to RAX */
	mov (FRAME_OFFSET+0x40)(%rsp), %r13
	mov (FRAME_OFFSET+0x38)(%rsp), %r12
	mov (FRAME_OFFSET+0x30)(%rsp), %r11
	mov %rdi, %rax
	mov %r9,  %r10	/* Move input 5 to R10 */
	/* Move input 4 to R9 */
	mov %r8,  %r9
	/* Move input 3 to R8 */
	mov %rcx, %r8
	/* Move input 1 to RCX */
	mov %rsi, %rcx
	/* Leave input param 2 in RDX */

	.if \host
1:
	seamcall

	jnz .Lno_vmfailvalid
	mov $TDX_SEAMCALL_VMFAILVALID, %rax
.Lno_vmfailvalid:

	/*
	 * SEAMCALL instruction is essentially a VMExit from VMX root
	 * mode to SEAM VMX root mode.  VMfailInvalid (CF=1) indicates
	 * that the targeted SEAM firmware is not loaded or disabled,
	 * or P-SEAMLDR is busy with another SEAMCALL.  %rax is not
	 * changed in this case.
	 *
	 * Set %rax to TDX_SEAMCALL_VMFAILINVALID for VMfailInvalid.
	 * This value will never be used as actual SEAMCALL error code as
	 * it is from the Reserved status code class.
	 */
	jnc .Lseamcall_out
	mov $TDX_SEAMCALL_VMFAILINVALID, %rax
	jmp .Lseamcall_out
2:
	/*
	 * SEAMCALL caused #GP or #UD.  By reaching here %eax contains
	 * the trap number.  Convert the trap number to the TDX error
	 * code by setting TDX_SW_ERROR to the high 32-bits of %rax.
	 *
	 * Note cannot OR TDX_SW_ERROR directly to %rax as OR instruction
	 * only accepts 32-bit immediate at most.
	 */
	mov $TDX_SW_ERROR, %r12
	orq %r12, %rax

	_ASM_EXTABLE_FAULT(1b, 2b)
.Lseamcall_out:
	.else
	tdcall
	.endif

	/*
	 * Fetch output pointer from stack to R15 (It is used
	 * as temporary storage)
	 */
	/*pop %r15*/

	/*
	 * Since this macro can be invoked with NULL as an output pointer,
	 * check if caller provided an output struct before storing output
	 * registers.
	 *
	 * Update output registers, even if the call failed (RAX != 0).
	 * Other registers may contain details of the failure.
	 */
	test %r15, %r15
	jz .Lno_output_struct

	/* Copy result registers to output struct: */
	movq %rcx, TDX_MODULE_rcx(%r15)
	movq %rdx, TDX_MODULE_rdx(%r15)
	movq %r8,  TDX_MODULE_r8(%r15)
	movq %r9,  TDX_MODULE_r9(%r15)
	movq %r10, TDX_MODULE_r10(%r15)
	movq %r11, TDX_MODULE_r11(%r15)
	movq %r12, TDX_MODULE_r12(%r15)
	movq %r13, TDX_MODULE_r13(%r15)

.Lno_output_struct:
	/* Restore the state of R12 register */
	pop %r15
	pop %r13
	pop %r12
	pop %r11
	pop %r10
.endm

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __X86_COCO_TDX_H__
#define __X86_COCO_TDX_H__

#include <linux/pci-tdisp.h>

int tdx_get_dev_context(u32 devid, u32 *func_id,
			u64 *nonce0, u64 *nonce1, u64 *nonce2, u64 *nonce3);
int tdx_get_dev_info(struct pci_tdi *tdi, void **buf_ptr,
		     unsigned int *actual_sz);
int tdx_devif_validate(u64 func_id, u64 pkh5, u64 pkh4, u64 pkh3, u64 pkh2, u64 pkh1, u64 pkh0);
int tdx_devif_read(u64 func_id, u64 field, u64 field_parm, u64 *value);
int tdx_devif_tdisp(struct pci_tdi *tdi, struct tdisp_request_parm *parm);
int tdx_dmar_accept(u64 func_id, u64 gpasid, u64 parm0, u64 parm1, u64 parm2, u64 parm3,
		    u64 parm4, u64 parm5, u64 parm6, u64 parm7);

#endif /* __X86_COCO_TDX_H__ */

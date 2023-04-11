/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_PCI_IDE_H
#define _ASM_X86_PCI_IDE_H

#include <linux/pci.h>
#include <asm/kvm_host.h>

#define KCB_CAP_NUM_STREAM_SUPPORTED	0x000000FF
#define KCB_CAP_NUM_TX_KEY_SLOTS	0x000FFC00
#define KCB_CAP_NUM_RX_KEY_SLOTS	0x3FF00000

#define IDE_KM_PARAM_KSET         0x01
#define IDE_KM_PARAM_DIR          0x02
#define IDE_KM_PARAM_SUB_STREAM   0xF0

struct stream_create_param {
	/*
	 * Bit 7: 0  - IDE_ID      ID of the RP IDE config. register block
	 * Bit 15:8  - RP_DF_NUM   Device and fn. number of RP
	 * Bit 23:16 - KEY_ID     ID of key config bar stream registers
	 * Bit 30:24   Reserved
	 * Bit 31      STREAM_TYPE      0: LINK_IDE, 1: SEL_IDE
	 */
#define STREAM_CFG_IDE_ID		0x00000000FFULL
#define STREAM_CFG_RP_DF_NUM		0x000000FF00ULL
#define STREAM_CFG_KEY_ID		0x0000FF0000ULL
#define STREAM_CFG_TYPE			0x0080000000ULL
	u64 ide_stream_cfg;

	/* IDE Stream Control Register */
	u32 ide_stream_ctrl;
	/* IDE RID Association Register 1 */
	u32 rid_assoc1;
	/* IDE RID Association Register 2 */
	u32 rid_assoc2;
	/* IDE Address Association Register 1 */
	u32 addr_assoc1;
	/* IDE Address Association Register 2 */
	u32 addr_assoc2;
	/* IDE Address Association Register 3 */
	u32 addr_assoc3;
	u64 stream_exinfo;
};

#endif /* _ASM_X86_PCI_IDE_H */

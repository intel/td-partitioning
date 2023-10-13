// SPDX-License-Identifier: GPL-2.0
/*
 * Race Point Beach(RPB) driver.
 */
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rpb.h>
#include <linux/bitfield.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>

static bool autotest;
module_param(autotest, bool, 0644);
static uint autotest_loops = 1;
module_param(autotest_loops, uint, 0644);

static int force_upper_vector = 1;
module_param(force_upper_vector, int, 0644);

#define DEFAULT_TRUST_BIT	1000
static int trust_bit = DEFAULT_TRUST_BIT;
module_param(trust_bit, int, 0644);

#define MAX_ERROR_COUNT		8
#define DEFAULT_VM_ID		0
#define DEFAULT_STREAM_CTRL_BLK	0
#define MAX_VECTOR_NUM		2048
/*
 * RPB needs 3 vectors to transfer one page size data
 * in the worst situation
 * one prefix vector, one upper address vector and
 * one memory read/write vector
 *
 * So simply assuming 4 vectors for one page size data
 */
#define VM_MAX_TRANSFER_SIZE	((MAX_VECTOR_NUM / 4) * PAGE_SIZE)

/* VTC: Selective IDE Stream Control Reg is in config space */
#define VTC_SEL_IDE_STREAM_CTRL_OFFSET	0xC50

/* IDE related Registers for RPB, in BAR0 */
#define STREAM_CAP_OFFSET		0x00
#define  NUM_RX_KEY_SLOTS	GENMASK(29, 20)
#define  NUM_TX_KEY_SLOTS	GENMASK(19, 10)
#define  NUM_STREAMS		GENMASK(8, 0)

/* Only use Stream Control Block A */
/* Stream Control Block */
#define STREAM_CTRL_BLK_OFFSET(_x)	(0x04 + (_x) * 0x24)
#define STREAM_CTRL_OFFSET		0x00
#define  STREAM_ENABLE		BIT(0)
/* We don't set PCRC and TC */
//#define   PCRC_ENABLE		BIT(8)
//#define   TC			GENMASK(21, 19)
#define  STREAM_ID		GENMASK(31, 24)

#define STREAM_TX_CTRL_OFFSET		0x04
#define  TX_PRIME_KEY_SET_1	BIT(16)
#define  TX_PRIME_KEY_SET_0	BIT(8)
#define  TX_KEY_SET_SELECT	GENMASK(1, 0)

#define STREAM_TX_STS_OFFSET		0x08
#define  TX_READY_KEY_SET_1	BIT(9)
#define  TX_READY_KEY_SET_0	BIT(8)
#define  TX_KEY_SET_STATUS	GENMASK(1, 0)

#define STREAM_RX_CTRL_OFFSET		0xC
#define  RX_PRIME_KEY_SET_1	BIT(16)
#define  RX_PRIME_KEY_SET_0	BIT(8)

#define STREAM_RX_STS_OFFSET		0x10
#define  RX_READY_KEY_SET_1	BIT(9)
#define  RX_READY_KEY_SET_0	BIT(8)
#define  RX_LAST_RECV_SET_CPL	GENMASK(5, 4)
#define  RX_LAST_RECV_SET_NPR	GENMASK(3, 2)
#define  RX_LAST_RECV_SET_PR	GENMASK(1, 0)

#define STREAM_TX_KS_0_IDX_OFFSET	0x14
#define  TX_CPL_SET_0_KS_INDEX	GENMASK(29, 20)
#define  TX_NPR_SET_0_KS_INDEX	GENMASK(19, 10)
#define  TX_PR_SET_0_KS_INDEX	GENMASK(9, 0)

#define STREAM_TX_KS_1_IDX_OFFSET	0x18
#define  TX_CPL_SET_1_KS_INDEX	GENMASK(29, 20)
#define  TX_NPR_SET_1_KS_INDEX	GENMASK(19, 10)
#define  TX_PR_SET_1_KS_INDEX	GENMASK(9, 0)

#define STREAM_RX_KS_0_IDX_OFFSET	0x1C
#define  RX_CPL_SET_0_KS_INDEX	GENMASK(29, 20)
#define  RX_NPR_SET_0_KS_INDEX	GENMASK(19, 10)
#define  RX_PR_SET_0_KS_INDEX	GENMASK(9, 0)

#define STREAM_RX_KS_1_IDX_OFFSET	0x20
#define  RX_CPL_SET_1_KS_INDEX	GENMASK(29, 20)
#define  RX_NPR_SET_1_KS_INDEX	GENMASK(19, 10)
#define  RX_PR_SET_1_KS_INDEX	GENMASK(9, 0)
/* end of Stream Control Block A */
/* end of IDE related Registers for RPB */

/* VMx Master Mode Register */
#define VMX_MODE		GENMASK(1, 0)
#define VMX_ENABLE		BIT(2)
#define VMX_END_INT_ENABLE	BIT(3)
#define VMX_END_STS		BIT(4)
#define VMX_ARAM_P_CLR		BIT(5)
#define VMX_SM			BIT(6)
#define VMX_EC			BIT(7)
#define VMX_START		BIT(16)
#define VMX_TRUST		BIT(17)

/* VMx Error Control Register */
#define VMX_FAILED_TLP_TYPE	GENMASK(3, 0)
#define VMX_ERROR_IDX		GENMASK(10, 8)
#define VMX_VALID_STRM_ID	BIT(13)
#define VMX_STRM_ID		GENMASK(15, 14)
#define VMX_ERR_VALID_STRM0	BIT(16)
#define VMX_ERR_VALID_STRM1	BIT(17)
#define VMX_ERR_VALID_STRM2	BIT(18)
#define VMX_ERR_VALID_STRM3	BIT(19)
#define VMX_CLR_MWBC0		BIT(20)
#define VMX_CLR_MWBC1		BIT(21)
#define VMX_CLR_MWBC2		BIT(22)
#define VMX_CLR_MWBC3		BIT(23)
#define VMX_EIE0		BIT(24)
#define VMX_EIE1		BIT(25)
#define VMX_EIE2		BIT(26)
#define VMX_EIE3		BIT(27)

/* VMx Error Lower Address Register */
#define VMX_64bit_TLP		BIT(0)
#define VMX_UPPER_ADDR_NOZERO	BIT(1)
#define VMX_LOWER_ADDR		GENMASK(31, 2)

/* VMx Error Upper Address Register */
#define VMX_UPPER_ADDR		GENMASK(31, 0)

/* VMx Error Actual Data Register */
#define VMX_ACTUAL_DATA		GENMASK(31, 0)

/* VMx Error Expected Data Register */
#define VMX_EXPECTED_DATA	GENMASK(31, 0)

/* VMx Abort/Unsupport Counter Register */
#define UNSUPPORT_REQ_CNT_STRM0	GENMASK(3, 0)
#define ABORT_COUNTER_STRM0	GENMASK(7, 4)
#define UNSUPPORT_REQ_CNT_STRM1	GENMASK(11, 8)
#define ABORT_COUNTER_STRM1	GENMASK(15, 12)
#define UNSUPPORT_REQ_CNT_STRM2	GENMASK(19, 16)
#define ABORT_COUNTER_STRM2	GENMASK(23, 20)
#define UNSUPPORT_REQ_CNT_STRM3	GENMASK(27, 24)
#define ABORT_COUNTER_STRM3	GENMASK(31, 28)

/* Offset in BAR0 */
enum rpb_mem_offset {
	VM0_VECTOR_OFFSET	= 0x000000,
	VM1_VECTOR_OFFSET	= 0x020000,
	VM2_VECTOR_OFFSET	= 0x040000,
	VM3_VECTOR_OFFSET	= 0x060000,
	/* 0xC2000 - 0xE0000 is a hole */
	CONFIG_OFFSET		= 0x0E0000,
	VTC_STREAM_KS_OFFSET	= 0x0E3000,
	VM0_REG_OFFSET		= 0x0E5000,
	VM1_REG_OFFSET		= 0x0E7000,
	VM2_REG_OFFSET		= 0x0E9000,
	VM3_REG_OFFSET		= 0x0EB000,
	/* for RWF */
	PCIE_EP_IDE_OFFSET	= 0x100000,
};

enum vm_register_offset {
	MMR			= 0x0,
	ERR_CTRL		= 0x20,
	WRITE_BYTE_CNT_0	= 0x30,
	WRITE_BYTE_CNT_1	= 0x34,
	WRITE_BYTE_CNT_2	= 0x38,
	WRITE_BYTE_CNT_3	= 0x3C,
	ERR_LOWER_ADDR		= 0x40,
	ERR_UPPER_ADDR		= 0x44,
	ERR_ACTUAL_DATA		= 0x48,
	ERR_EXPECT_DATA		= 0x4C,
	ABORT_CNT		= 0x74,
};

enum sub_stream_slot_index {
	PR_KS0_SLOT_IDX		= 0,
	NPR_KS0_SLOT_IDX	= 1,
	CPL_KS0_SLOT_IDX	= 2,
	PR_KS1_SLOT_IDX		= 3,
	NPR_KS1_SLOT_IDX	= 4,
	CPL_KS1_SLOT_IDX	= 5,
	SLOT_PER_SUB_STREAM	= 6,
};

/* Selective IDE Registers in CONFIG_OFFSET of BAR0 */
enum sel_ide_registers_offset {
	/* RPB KEY SLOT */
	RPB_SEL_STREAM_TX_PR_KEY_SLOT	= PCIE_EP_IDE_OFFSET + 0x94,
	RPB_SEL_STREAM_TX_NPR_KEY_SLOT	= RPB_SEL_STREAM_TX_PR_KEY_SLOT + 32,
	RPB_SEL_STREAM_TX_CPL_KEY_SLOT	= RPB_SEL_STREAM_TX_NPR_KEY_SLOT + 32,
	RPB_SEL_STREAM_RX_PR_KEY_SLOT	= PCIE_EP_IDE_OFFSET + 0x2EC,
	RPB_SEL_STREAM_RX_NPR_KEY_SLOT	= RPB_SEL_STREAM_RX_PR_KEY_SLOT + 32,
	RPB_SEL_STREAM_RX_CPL_KEY_SLOT	= RPB_SEL_STREAM_RX_NPR_KEY_SLOT + 32,
	/* RPB IFV SLOT */
	RPB_SEL_STREAM_TX_PR_IFV_SLOT	= PCIE_EP_IDE_OFFSET + 0x274,
	RPB_SEL_STREAM_TX_NPR_IFV_SLOT	= RPB_SEL_STREAM_TX_PR_IFV_SLOT + 8,
	RPB_SEL_STREAM_TX_CPL_IFV_SLOT	= RPB_SEL_STREAM_TX_NPR_IFV_SLOT + 8,
	RPB_SEL_STREAM_RX_PR_IFV_SLOT	= PCIE_EP_IDE_OFFSET + 0x4CC,
	RPB_SEL_STREAM_RX_NPR_IFV_SLOT	= RPB_SEL_STREAM_RX_PR_IFV_SLOT + 8,
	RPB_SEL_STREAM_RX_CPL_IFV_SLOT	= RPB_SEL_STREAM_RX_NPR_IFV_SLOT + 8,

	/* VTC KEY SLOT */
	VTC_SEL_STREAM_TX_PR_KEY_SLOT	= VTC_STREAM_KS_OFFSET + 0xE78,
	VTC_SEL_STREAM_TX_NPR_KEY_SLOT	= VTC_STREAM_KS_OFFSET + 0xEA0,
	VTC_SEL_STREAM_TX_CPL_KEY_SLOT	= VTC_STREAM_KS_OFFSET + 0xEC8,
	VTC_SEL_STREAM_RX_PR_KEY_SLOT	= VTC_STREAM_KS_OFFSET + 0xF68,
	VTC_SEL_STREAM_RX_NPR_KEY_SLOT	= VTC_STREAM_KS_OFFSET + 0xF90,
	VTC_SEL_STREAM_RX_CPL_KEY_SLOT	= VTC_STREAM_KS_OFFSET + 0xFB8,
	/* VTC IFV SLOT */
	VTC_SEL_STREAM_TX_PR_IFV_SLOT	= VTC_STREAM_KS_OFFSET + 0xE98,
	VTC_SEL_STREAM_TX_NPR_IFV_SLOT	= VTC_STREAM_KS_OFFSET + 0xEC0,
	VTC_SEL_STREAM_TX_CPL_IFV_SLOT	= VTC_STREAM_KS_OFFSET + 0xEE8,
	VTC_SEL_STREAM_RX_PR_IFV_SLOT	= VTC_STREAM_KS_OFFSET + 0xF88,
	VTC_SEL_STREAM_RX_NPR_IFV_SLOT	= VTC_STREAM_KS_OFFSET + 0xFB0,
	VTC_SEL_STREAM_RX_CPL_IFV_SLOT	= VTC_STREAM_KS_OFFSET + 0xFD8,
};

static u32 vtc_key_slot_offset[PCI_IDE_SUB_STREAM_NUM][PCI_IDE_SUB_STREAM_DIRECTION_NUM] = {
	{VTC_SEL_STREAM_RX_PR_KEY_SLOT, VTC_SEL_STREAM_TX_PR_KEY_SLOT},
	{VTC_SEL_STREAM_RX_NPR_KEY_SLOT, VTC_SEL_STREAM_TX_NPR_KEY_SLOT},
	{VTC_SEL_STREAM_RX_CPL_KEY_SLOT, VTC_SEL_STREAM_TX_CPL_KEY_SLOT},
};

static u32 vtc_ifv_slot_offset[PCI_IDE_SUB_STREAM_NUM][PCI_IDE_SUB_STREAM_DIRECTION_NUM] = {
	{VTC_SEL_STREAM_RX_PR_IFV_SLOT, VTC_SEL_STREAM_TX_PR_IFV_SLOT},
	{VTC_SEL_STREAM_RX_NPR_IFV_SLOT, VTC_SEL_STREAM_TX_NPR_IFV_SLOT},
	{VTC_SEL_STREAM_RX_CPL_IFV_SLOT, VTC_SEL_STREAM_TX_CPL_IFV_SLOT},
};

static u32 rpb_key_slot_offset[PCI_IDE_SUB_STREAM_NUM][PCI_IDE_SUB_STREAM_DIRECTION_NUM] = {
	{RPB_SEL_STREAM_RX_PR_KEY_SLOT, RPB_SEL_STREAM_TX_PR_KEY_SLOT},
	{RPB_SEL_STREAM_RX_NPR_KEY_SLOT, RPB_SEL_STREAM_TX_NPR_KEY_SLOT},
	{RPB_SEL_STREAM_RX_CPL_KEY_SLOT, RPB_SEL_STREAM_TX_CPL_KEY_SLOT},
};

static u32 rpb_ifv_slot_offset[PCI_IDE_SUB_STREAM_NUM][PCI_IDE_SUB_STREAM_DIRECTION_NUM] = {
	{RPB_SEL_STREAM_RX_PR_IFV_SLOT, RPB_SEL_STREAM_TX_PR_IFV_SLOT},
	{RPB_SEL_STREAM_RX_NPR_IFV_SLOT, RPB_SEL_STREAM_TX_NPR_IFV_SLOT},
	{RPB_SEL_STREAM_RX_CPL_IFV_SLOT, RPB_SEL_STREAM_TX_CPL_IFV_SLOT},
};

#pragma pack(push, 1)
struct upper_addr_vector {
	/* Byte 0 */
	u8 type:5;
	u8 reserevd:1;
	u8 end:1;
	u8 reserved1:1;
	/* Byte 1 */
	u8 bus_num;
	/* Byte 2 */
	u8 reserved2:6;
	u8 vec_to_fab:1;
	u8 reserved3:1;
	/* Byte 3 */
	u8 posted_tag:5;
	u8 steering_tag:3;
	/* Byte 4 */
	u8 ts_idx:3;
	u8 obbf_o:1;
	u8 ts_cmd:4;
	/* Byte 5 */
	u8 func_num:3;
	u8 dev_num:5;
	/* Byte 6,7 */
	u16 pat_gen:11;
	u16 reserved4:1;
	u16 atom_idx:3;
	u16 steering_tt_sel:1;
	/* Byte 8,9,10,11 */
	u32 reserved5:12;
	u32 tl_err_type:4;
	u32 tl_side_band:12;
	u32 atom:2;
	u32 th:1;
	u32 nc:1;
	/* Byte 12,13,14,15 */
	u32 upper_addr;
};

struct memory_write_vector {
	/* Byte 0 */
	u8 type:5;
	u8 reserevd1:1;
	u8 end:1;
	u8 lock_first:1;
	/* Byte 1 */
	u8 lock_last:1;
	u8 mbc_enable:1;
	u8 mbc_sel:2;
	u8 tag:1;
	u8 reserved2:3;
	/* Byte 2 */
	u8 ph:2;
	u8 address_type:2;
	u8 lightweight:1;
	u8 id_bo:1;
	u8 tag_bit8:1;
	u8 tag_bit9:1;
	/* Byte 3 */
	u8 repeat1;
	/* Byte 4 */
	u8 first_dw_be:4;
	u8 last_dw_be:4;
	/* Byte 5 */
	u8 ri:1;
	u8 pg:1;
	u8 bo:1;
	u8 reserved3:1;
	u8 zero_len_write:1;
	u8 traffic_class:3;
	/* Byte 6 */
	u8 loop_modifier:1;
	u8 no_snoop_attr0:1;
	u8 ordering_attr1:1;
	u8 next_length:2;
	u8 addr_size:1;
	u8 reserved4:2;
	/* Byte 7 */
	u8 wait_count:6;
	u8 nwc:2;
	/* Byte 8,9,10,11 */
	u32 poisoned:1;
	u32 digest:1;
	u32 address:30;
	/* Byte 12,13 */
	u16 nbe_first_dw:2;
	u16 nbe_last_dw:2;
	u16 next_addr_adv:2;
	u16 addr_adv:10;
	/* Byte 14,15 */
	u16 data_pattern:2;
	u16 next_data_pattern:2;
	u16 length:10;
	u16 reserved5:1;
	u16 tgen_vector:1;
};

struct memory_read_vector {
	/* Byte 0[7] */
	u8 type:5;
	u8 reserevd1:1;
	u8 end:1;
	u8 lock_first:1;
	/* Byte 1 */
	u8 lock_last:1;
	u8 tgt_range_sel:2;
	u8 to:1;
	u8 tag:1;
	u8 poll:1;
	u8 update_sticky_buf:1;
	u8 ev_buf_update:1;
	/* Byte 2 */
	u8 ph:2;
	u8 address_type:2;
	u8 lightweight:1;
	u8 id_bo:1;
	u8 tag_bit8:1;
	u8 tag_bit9:1;
	/* Byte 3 */
	u8 repeat;
	/* Byte 4 */
	u8 first_dw_be:4;
	u8 last_dw_be:4;
	/* Byte 5 */
	u8 ri:1;
	u8 pg:1;
	u8 bo:1;
	u8 lt:1;
	u8 zero_len_read:1;
	u8 traffic_class:3;
	/* Byte 6 */
	u8 loop_modifier:1;
	u8 no_snoop_attr0:1;
	u8 ordering_attr1:1;
	u8 next_length:2;
	u8 addr_size:1;
	u8 mem_read_lock_req:1;
	u8 reserved2:1;
	/* Byte 7 */
	u8 wait_count:6;
	u8 nwc:2;
	/* Byte 8, 9, 10, 11 */
	u32 poisoned:1;
	u32 digest:1;
	u32 address:30;
	/* Byte 12, 13 */
	u16 nbe_first_dw:2;
	u16 nbe_last_dw:2;
	u16 next_addr_adv:2;
	u16 addr_adv:10;
	/* Byte 14, 15 */
	u16 data_pattern:2;
	u16 next_data_pattern:2;
	u16 length:10;
	u16 reserved3:1;
	u16 tgen_vector:1;
};

struct vm_vector {
	union {
		union {
			struct {
				u8 type:5;
				u8 reserevd1:1;
				u8 end:1;
				u8 reserved2:1;
			};

			struct memory_write_vector mem_write;
			struct memory_read_vector mem_read;
			struct upper_addr_vector ua_vec;
		};
		u64 data[2];
	};
};

#pragma pack(pop)

static u32 pattern_mask[] = {
	0xffffffff, 0xffffff00,
	0xffff00ff, 0xffff0000,
	0xff00ffff, 0xff00ff00,
	0xff0000ff, 0xff000000,
	0x00ffffff, 0x00ffff00,
	0x00ff00ff, 0x00ff0000,
	0x0000ffff, 0x0000ff00,
	0x000000ff, 0x00000000
};

struct rpb_vector {
	unsigned long virt_addr;
	dma_addr_t dma_addr;
	unsigned long len;

	struct vm_vector prefix;
	struct vm_vector upper_addr;
	struct vm_vector vec;
};

struct rpb_device {
	/* per VM members */
	int next_vec;
	struct rpb_vector vecs[MAX_VECTOR_NUM];
	struct mutex test_lock;

	void __iomem *bar0_base;
	void __iomem *kcb_base;
	void __iomem *ide_stream_a_block;

	struct vm_vector __iomem *vectors;
	void __iomem *vm_regs;

	struct pci_dev *pdev;

	/* mem operation attributes */
	unsigned int mem_op;
	unsigned int mem_attr;
	unsigned int mem_size;
	unsigned long long mmio_addr;
};

struct rpb_mem_test {
	unsigned int mem_op;
	unsigned int mem_attr;
	unsigned int mem_size;
	unsigned long mmio_addr;
};

#define RPB_MEM_OP_NONE			0
#define RPB_MEM_OP_READ			1
#define RPB_MEM_OP_WRITE		2
#define RPB_MEM_OP_P2P_MMIO_READ	3
#define RPB_MEM_OP_P2P_MMIO_WRITE	4
#define RPB_MEM_OP_MAX			5

#define RPB_MEM_ATTR_NONE		0
#define RPB_MEM_ATTR_DEFAULT		1
#define RPB_MEM_ATTR_SHARED		2
#define RPB_MEM_ATTR_MAX		3

#define RPB_MEM_SIZE_MAX		VM_MAX_TRANSFER_SIZE

static inline u32 rpb_readl(void __iomem *addr)
{
	u32 v = readl(addr);

	pr_debug("%s: addr: 0x%llx v: 0x%x\n", __func__, (unsigned long long)addr, v);
	return v;
}

static inline void rpb_writel(u32 data, void __iomem *addr)
{
	writel(data, addr);
	pr_debug("%s: addr: 0x%llx v: 0x%x\n", __func__, (unsigned long long)addr, data);
}

static inline u64 rpb_readq(void __iomem *addr)
{
	u64 v = readq(addr);

	pr_debug("%s: addr: 0x%llx v: 0x%llx\n", __func__, (unsigned long long)addr, v);
	return v;
}

static inline void rpb_writeq(u64 data, void __iomem *addr)
{
	writeq(data, addr);
	pr_debug("%s: addr: 0x%llx v: 0x%llx\n", __func__, (unsigned long long)addr, data);
}

static inline void __iomem *vm_reg_addr(struct rpb_device *rdev, u32 reg)
{
	return rdev->vm_regs + reg;
}

static int get_vm_reg_block_offset(struct pci_dev *pdev, u32 vm_id)
{
	switch (vm_id) {
	case 0:
		return VM0_REG_OFFSET;
	case 1:
		return VM1_REG_OFFSET;
	case 2:
		return VM2_REG_OFFSET;
	case 3:
		return VM3_REG_OFFSET;
	default:
		dev_err(&pdev->dev, "%s: Unknown VM ID %d\n", __func__, vm_id);
		return -EINVAL;
	}
}

static const char *mem_op_to_string(unsigned int mem_op)
{
	switch (mem_op) {
	case RPB_MEM_OP_NONE:
		return "None";
	case RPB_MEM_OP_READ:
		return "Memory Read";
	case RPB_MEM_OP_WRITE:
		return "Memory Write";
	case RPB_MEM_OP_P2P_MMIO_READ:
		return "P2P MMIO Read";
	case RPB_MEM_OP_P2P_MMIO_WRITE:
		return "P2P MMIO Write";
	}

	return "Invalid Memory Operation";
}

static const char *mem_attr_to_string(unsigned int mem_attr)
{
	switch (mem_attr) {
	case RPB_MEM_ATTR_NONE:
		return "None";
	case RPB_MEM_ATTR_DEFAULT:
		return "Default";
	case RPB_MEM_ATTR_SHARED:
		return "Shared";
	}

	return "Invalid Memory Attribute";
}

static void vtc_disable_sel_stream(struct rpb_ide *ide)
{
	u32 val;

	pci_read_config_dword(ide->pdev, VTC_SEL_IDE_STREAM_CTRL_OFFSET, &val);
	val &= ~STREAM_ENABLE;
	pci_write_config_dword(ide->pdev, VTC_SEL_IDE_STREAM_CTRL_OFFSET, val);
}

static void __rpb_disable_sel_stream(struct rpb_ide *ide)
{
	u32 __iomem *pos;
	u32 val;

	/* Stream Disable */
	pos = ide->bar0_base + PCIE_EP_IDE_OFFSET +
	      STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
	      STREAM_CTRL_OFFSET;
	val = rpb_readl(pos);
	val &= ~STREAM_ENABLE;
	rpb_writel(val, pos);

	/* Disable Rx Key Set 0 */
	pos = ide->bar0_base + PCIE_EP_IDE_OFFSET +
	      STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
	      STREAM_RX_CTRL_OFFSET;
	val = 0;
	rpb_writel(val, pos);

	/* Disable Tx Key Set 0 */
	pos = ide->bar0_base + PCIE_EP_IDE_OFFSET +
	      STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
	      STREAM_TX_CTRL_OFFSET;
	val &= ~(TX_PRIME_KEY_SET_0 | TX_KEY_SET_SELECT);
	rpb_writel(val, pos);
}

void _rpb_disable_sel_stream(struct rpb_ide *ide)
{
	if (is_vtc_device(ide->pdev))
		vtc_disable_sel_stream(ide);
	else
		__rpb_disable_sel_stream(ide);
	ide->sel_stream_enabled = false;
}
EXPORT_SYMBOL_GPL(_rpb_disable_sel_stream);

static int vtc_set_sel_stream_id(struct rpb_ide *ide)
{
	u32 val;

	if (pci_read_config_dword(ide->pdev, VTC_SEL_IDE_STREAM_CTRL_OFFSET, &val))
		return -ENODEV;
	val &= ~STREAM_ID;
	val |= FIELD_PREP(STREAM_ID, ide->sel_stream_id);
	if (pci_write_config_dword(ide->pdev, VTC_SEL_IDE_STREAM_CTRL_OFFSET, val))
		return -ENODEV;

	return 0;
}

static void rpb_set_sel_stream_id(struct rpb_ide *ide)
{
	u32 val;

	val = rpb_readl(ide->bar0_base + PCIE_EP_IDE_OFFSET +
			STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
			STREAM_CTRL_OFFSET);
	val &= ~STREAM_ID;
	val |= FIELD_PREP(STREAM_ID, ide->sel_stream_id);
	rpb_writel(val, ide->bar0_base + PCIE_EP_IDE_OFFSET +
		   STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
		   STREAM_CTRL_OFFSET);
}

static void rpb_ide_program_key(struct rpb_ide *ide, u32 sub_stream,
				u8 direction)
{
	u32 __iomem *key_slot_addr;
	u32 __iomem *ifv_slot_addr;
	u32 *key;
	u32 *ifv;
	int i;

	key_slot_addr = ide->bar0_base +
			ide->key_slot_offset[sub_stream][direction];
	ifv_slot_addr = ide->bar0_base +
			ide->ifv_slot_offset[sub_stream][direction];
	key = ide->keys[sub_stream][direction];
	ifv = ide->ifv[sub_stream][direction];

	dev_dbg(&ide->pdev->dev, "Program key to sub stream %d dir %d\n",
		sub_stream, direction);
	for (i = 0; i < 8; i++)
		dev_dbg(&ide->pdev->dev, "Offset 0x%x Key %d: 0x%08x\n",
			ide->key_slot_offset[sub_stream][direction] + i * 4,
			i, key[i]);
	for (i = 0; i < 2; i++)
		dev_dbg(&ide->pdev->dev, "Offset 0x%x IFV Key %d: 0x%08x\n",
			ide->ifv_slot_offset[sub_stream][direction] + i * 4,
			i, ifv[i]);

	if (is_vtc_device(ide->pdev)) {
		for (i = 0; i < 4; i++)
			rpb_writel(((u64 *)key)[i], &((u64 __iomem *)key_slot_addr)[i]);
		rpb_writeq(*(u64 *)ifv, ifv_slot_addr);
	} else {
		for (i = 0; i < 8; i++)
			rpb_writel(key[i], &key_slot_addr[i]);
		for (i = 0; i < 2; i++)
			rpb_writel(ifv[i], &ifv_slot_addr[i]);
	}
}

static int vtc_enable_sel_stream(struct rpb_ide *ide)
{
	u32 sub_stream;
	u32 val;
	u8 dir;

	if (vtc_set_sel_stream_id(ide))
		return -ENODEV;

	for (sub_stream = 0; sub_stream < PCI_IDE_SUB_STREAM_NUM; sub_stream++) {
		for (dir = 0; dir < PCI_IDE_SUB_STREAM_DIRECTION_NUM; dir++)
			rpb_ide_program_key(ide, sub_stream, dir);
	}

	if (pci_read_config_dword(ide->pdev, VTC_SEL_IDE_STREAM_CTRL_OFFSET, &val))
		return -ENODEV;

	val |= FIELD_PREP(STREAM_ENABLE, 1);
	if (pci_write_config_dword(ide->pdev, VTC_SEL_IDE_STREAM_CTRL_OFFSET, val))
		return -ENODEV;

	ide->sel_stream_enabled = true;
	return 0;
}

static int __rpb_enable_sel_stream(struct rpb_ide *ide)
{
	u32 __iomem *pos;
	u32 sub_stream;
	u32 val;
	u8 dir;

	/* Print Stream Tx Status */
	pos = ide->bar0_base + PCIE_EP_IDE_OFFSET +
	      STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
	      STREAM_TX_STS_OFFSET;
	val = rpb_readl(pos);
	dev_dbg(&ide->pdev->dev, "%s Stream Tx Status 0x%x\n",
		__func__, val);

	/* Print Stream Rx Status */
	pos = ide->bar0_base + PCIE_EP_IDE_OFFSET +
	      STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
	      STREAM_RX_STS_OFFSET;
	val = rpb_readl(pos);
	dev_dbg(&ide->pdev->dev, "%s: Stream Rx Status 0x%x\n",
		__func__, val);

	/* Set Stream ID */
	rpb_set_sel_stream_id(ide);

	/* Set Keys and IFIV into slots */
	for (sub_stream = 0; sub_stream < PCI_IDE_SUB_STREAM_NUM; sub_stream++) {
		for (dir = 0; dir < PCI_IDE_SUB_STREAM_DIRECTION_NUM; dir++)
			rpb_ide_program_key(ide, sub_stream, dir);
	}

	/* Set Tx Key Slot of Key Set 0 */
	pos = ide->bar0_base + PCIE_EP_IDE_OFFSET +
	      STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
	      STREAM_TX_KS_0_IDX_OFFSET;
	val = FIELD_PREP(TX_PR_SET_0_KS_INDEX, PR_KS0_SLOT_IDX) |
	      FIELD_PREP(TX_NPR_SET_0_KS_INDEX, NPR_KS0_SLOT_IDX) |
	      FIELD_PREP(TX_CPL_SET_0_KS_INDEX, CPL_KS0_SLOT_IDX);
	rpb_writel(val, pos);
	dev_dbg(&ide->pdev->dev, "%s: STRMTXKS0IDX 0x%x\n",
		__func__, val);

	/* Set Rx Key Slot of Key Set 0 */
	pos = ide->bar0_base + PCIE_EP_IDE_OFFSET +
	      STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
	      STREAM_RX_KS_0_IDX_OFFSET;
	val = FIELD_PREP(RX_PR_SET_0_KS_INDEX, PR_KS0_SLOT_IDX) |
	      FIELD_PREP(RX_NPR_SET_0_KS_INDEX, NPR_KS0_SLOT_IDX) |
	      FIELD_PREP(RX_CPL_SET_0_KS_INDEX, CPL_KS0_SLOT_IDX);
	rpb_writel(val, pos);
	dev_dbg(&ide->pdev->dev, "%s: STRMRXKS0IDX 0x%x\n",
		__func__, val);

	/* Enable Tx Key Set 0 */
	pos = ide->bar0_base + PCIE_EP_IDE_OFFSET +
	      STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
	      STREAM_TX_CTRL_OFFSET;
	val = FIELD_PREP(TX_PRIME_KEY_SET_0, 1) |
	      FIELD_PREP(TX_KEY_SET_SELECT, 1);
	rpb_writel(val, pos);
	dev_dbg(&ide->pdev->dev, "%s: STRMTXCTL.TXPKEYS0 0x%x\n",
		__func__, val);

	/* Enable Rx Key Set 0 */
	pos = ide->bar0_base + PCIE_EP_IDE_OFFSET +
	      STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
	      STREAM_RX_CTRL_OFFSET;
	val = FIELD_PREP(RX_PRIME_KEY_SET_0, 1);
	rpb_writel(val, pos);
	dev_dbg(&ide->pdev->dev, "%s: STRMTXCTL.RXPKEYS0 0x%x\n",
		__func__, val);

	/* Stream Enable */
	pos = ide->bar0_base + PCIE_EP_IDE_OFFSET +
	      STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
	      STREAM_CTRL_OFFSET;
	val = rpb_readl(pos);
	val |= FIELD_PREP(STREAM_ENABLE, 1);
	rpb_writel(val, pos);
	dev_dbg(&ide->pdev->dev, "%s: STREAM CTRL 0x%x\n",
		__func__, val);

	ide->sel_stream_enabled = true;

	/* Check Rx Key Set 0 status */
	pos = ide->bar0_base + PCIE_EP_IDE_OFFSET +
	      STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
	      STREAM_RX_STS_OFFSET;
	val = rpb_readl(pos);
	dev_info(&ide->pdev->dev, "%s: Stream Rx Status 0x%x\n",
		 __func__, val);

	/* Check Tx Key Set 0 status */
	pos = ide->bar0_base + PCIE_EP_IDE_OFFSET +
	      STREAM_CTRL_BLK_OFFSET(ide->ctrl_blk_id) +
	      STREAM_TX_STS_OFFSET;
	val = rpb_readl(pos);
	dev_info(&ide->pdev->dev, "%s: Stream Tx Status 0x%x\n",
		 __func__, val);

	return 0;
}

int _rpb_enable_sel_stream(struct rpb_ide *ide)
{
	if (is_vtc_device(ide->pdev))
		return vtc_enable_sel_stream(ide);
	else
		return __rpb_enable_sel_stream(ide);
}
EXPORT_SYMBOL_GPL(_rpb_enable_sel_stream);

int _rpb_set_trust_bit(struct rpb_ide *ide, bool trust)
{
	u32 offset;
	u32 val;

	dev_dbg(&ide->pdev->dev, "Set trust bit to %d\n", !!trust);
	offset = get_vm_reg_block_offset(ide->pdev, DEFAULT_VM_ID) + MMR;
	val = rpb_readl(ide->bar0_base + offset);
	if (trust)
		val |= FIELD_PREP(VMX_TRUST, 1);
	else
		val &= ~VMX_TRUST;
	rpb_writel(val, ide->bar0_base + offset);
	ide->trust_bit_enabled = trust;

	return 0;
}
EXPORT_SYMBOL_GPL(_rpb_set_trust_bit);

struct rpb_ide *_rpb_ide_init(struct pci_dev *pdev, int ide_id,
			      u8 stream_id)
{
	struct rpb_ide *ide;

	ide = kzalloc(sizeof(*ide), GFP_KERNEL);
	if (!ide)
		return ERR_PTR(-ENOMEM);

	ide->bar0_base = ioremap(pci_resource_start(pdev, 0),
				 pci_resource_len(pdev, 0));
	if (!ide->bar0_base) {
		kfree(ide);
		return ERR_PTR(-EFAULT);
	}

	ide->ctrl_blk_id = DEFAULT_STREAM_CTRL_BLK;
	ide->ide_id = ide_id;
	ide->sel_stream_id = stream_id;
	ide->pdev = pdev;
	if (is_vtc_device(pdev)) {
		memcpy(ide->key_slot_offset, vtc_key_slot_offset,
		       sizeof(ide->key_slot_offset));
		memcpy(ide->ifv_slot_offset, vtc_ifv_slot_offset,
		       sizeof(ide->ifv_slot_offset));
	} else {
		memcpy(ide->key_slot_offset, rpb_key_slot_offset,
		       sizeof(ide->key_slot_offset));
		memcpy(ide->ifv_slot_offset, rpb_ifv_slot_offset,
		       sizeof(ide->ifv_slot_offset));
	}

	return ide;
}
EXPORT_SYMBOL_GPL(_rpb_ide_init);

void _rpb_ide_release(struct rpb_ide *ide)
{
	if (ide) {
		if (ide->trust_bit_enabled || ide->sel_stream_enabled)
			dev_warn(&ide->pdev->dev, "%s: trust_bit_enabled=%d, sel_stream_enabled=%d\n",
				 __func__, ide->trust_bit_enabled,
				 ide->sel_stream_enabled);
		iounmap(ide->bar0_base);
		kfree(ide);
	}
}
EXPORT_SYMBOL_GPL(_rpb_ide_release);

static ssize_t mem_op_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t len)
{
	struct rpb_device *rdev = dev_get_drvdata(dev);
	u32 mem_op;

	if (kstrtou32(buf, 0, &mem_op))
		return -EINVAL;

	if (mem_op >= RPB_MEM_OP_MAX)
		return -EINVAL;

	rdev->mem_op = mem_op;
	return len;
}

static ssize_t mem_op_show(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct rpb_device *rdev = dev_get_drvdata(dev);

	return sprintf(buf, "%s\n", mem_op_to_string(rdev->mem_op));
}
static DEVICE_ATTR_RW(mem_op);

static ssize_t mem_attr_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t len)
{
	struct rpb_device *rdev = dev_get_drvdata(dev);
	unsigned int mem_attr;

	if (kstrtou32(buf, 0, &mem_attr))
		return -EINVAL;

	if (mem_attr >= RPB_MEM_ATTR_MAX)
		return -EINVAL;

	/* FIXME: add checking, RPB_MEM_ATTR_SHARED only works for TDXIO */

	rdev->mem_attr = mem_attr;
	return len;
}

static ssize_t mem_attr_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct rpb_device *rdev = dev_get_drvdata(dev);

	return sprintf(buf, "%s\n", mem_attr_to_string(rdev->mem_attr));
}
static DEVICE_ATTR_RW(mem_attr);

static ssize_t mem_size_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t len)
{
	struct rpb_device *rdev = dev_get_drvdata(dev);
	u32 mem_size;

	if (kstrtou32(buf, 0, &mem_size))
		return -EINVAL;

	if (mem_size % 4 || mem_size > RPB_MEM_SIZE_MAX)
		return -EINVAL;

	rdev->mem_size = mem_size;
	return len;
}

static ssize_t mem_size_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct rpb_device *rdev = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", rdev->mem_size);
}
static DEVICE_ATTR_RW(mem_size);

static ssize_t mmio_addr_store(struct device *dev, struct device_attribute *attr,
			       const char *buf, size_t len)
{
	struct rpb_device *rdev = dev_get_drvdata(dev);
	u64 mmio_addr;

	if (kstrtou64(buf, 0, &mmio_addr))
		return -EINVAL;

	if (mmio_addr % 4)
		return -EINVAL;

	rdev->mmio_addr = mmio_addr;
	return len;
}

static ssize_t mmio_addr_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct rpb_device *rdev = dev_get_drvdata(dev);

	return sprintf(buf, "0x%016llx\n", rdev->mmio_addr);
}
static DEVICE_ATTR_RW(mmio_addr);

#define rpb_test_start(rdev)	mutex_lock(&(rdev)->test_lock)
#define rpb_test_end(rdev)	mutex_unlock(&(rdev)->test_lock)

static inline void rpb_vector_pos_reset(struct rpb_device *rdev)
{
	rdev->next_vec = 0;
}

static struct rpb_vector *rpb_vm_get_next_vector(struct rpb_device *rdev)
{
	struct rpb_vector *rvec;

	if (rdev->next_vec >= MAX_VECTOR_NUM)
		return NULL;

	rvec = &rdev->vecs[rdev->next_vec];
	memset(rvec, 0, sizeof(*rvec));
	rvec->dma_addr = DMA_MAPPING_ERROR;

	rdev->next_vec++;
	return rvec;
}

static void rpb_vm_dma_buffer_unmap(struct rpb_device *rdev,
				    enum dma_data_direction dir)
{
	struct device *dev = &rdev->pdev->dev;
	struct rpb_vector *rvec;
	int i;

	for (i = 0; i < rdev->next_vec; i++) {
		rvec = &rdev->vecs[i];
		if (!dma_mapping_error(dev, rvec->dma_addr))
			dma_unmap_single(dev, rvec->dma_addr, rvec->len, dir);
	}
}

static int rpb_vm_dma_buffer_map(struct rpb_device *rdev,
				 enum dma_data_direction dir,
				 bool force_shared)
{
	struct device *dev = &rdev->pdev->dev;
	struct rpb_vector *rvec;
	dma_addr_t dma_addr;
	int i;

	if (dev->authorized == MODE_SECURE)
		dev_info(dev, "Auth - private mode, %s memory is used\n",
			 force_shared ? "force-shared" : "private");
	else
		dev_info(dev, "Auth - shared mode, uses bounce buffer\n");

	for (i = 0; i < rdev->next_vec; i++) {
		rvec = &rdev->vecs[i];

		if (dev->authorized == MODE_SECURE && force_shared)
			dma_addr = dma_map_single_attrs(dev, (void *)rvec->virt_addr,
							rvec->len, dir,
							DMA_ATTR_FORCEUNENCRYPTED);
		else
			dma_addr = dma_map_single(dev, (void *)rvec->virt_addr,
						  rvec->len, dir);
		if (dma_mapping_error(dev, dma_addr)) {
			dev_err(dev, "Failed to map DMA\n");
			return -ENOMEM;
		}

		rvec->dma_addr = dma_addr;
	}

	return 0;
}

static void rpb_vm_dma_buffer_free(struct rpb_device *rdev)
{
	struct rpb_vector *rvec;
	int i;

	for (i = 0; i < rdev->next_vec; i++) {
		rvec = &rdev->vecs[i];

		if (rvec->virt_addr) {
			free_page(rvec->virt_addr);
			rvec->virt_addr = 0;
		}
	}
}

static int rpb_vm_dma_buffer_alloc(struct rpb_device *rdev, int total_size)
{
	unsigned long virt_addr, vec_size, cur_size = total_size;
	struct device *dev = &rdev->pdev->dev;
	struct rpb_vector *rvec;

	while (cur_size) {
		vec_size = min(PAGE_SIZE, cur_size);

		rvec = rpb_vm_get_next_vector(rdev);

		virt_addr = get_zeroed_page(GFP_KERNEL);
		if (!virt_addr) {
			dev_err(dev, "Failed to allocate buffer\n");
			goto free_buffer;
		}

		rvec->len = vec_size;
		rvec->virt_addr = virt_addr;

		cur_size -= vec_size;
	}

	return 0;

free_buffer:
	rpb_vm_dma_buffer_free(rdev);
	return -ENOMEM;
}

static u32 get_increment_pattern(u32 pattern_gen_addr)
{
	return (0x00010000 | ((pattern_gen_addr & 0x0001fffc) >>  1) |
	       ((pattern_gen_addr & 0x00001ffc) << 15) |
	       ((pattern_gen_addr & 0x003c0000) << 10));
}

static void gen_increment_pattern_for_mem_read(struct rpb_device *rdev,
					       struct rpb_vector *rvec)
{
	struct device *dev = &rdev->pdev->dev;
	dma_addr_t pattern_gen_addr;
	u32 pattern, data, len;
	u8 fbe, lbe;
	int i;

	len = round_up(rvec->len, 4) / 4;
	pattern_gen_addr = rvec->dma_addr;

	dev_dbg(dev, "Generate Increment pattern for dma_addr:0x%llx len=%lu\n",
		rvec->dma_addr, rvec->len);

	fbe = rvec->vec.mem_read.first_dw_be;
	lbe = rvec->vec.mem_read.last_dw_be;

	dma_sync_single_for_cpu(dev, rvec->dma_addr, rvec->len, DMA_TO_DEVICE);
	for (i = 0; i < len; i++) {
		pattern = get_increment_pattern(pattern_gen_addr);

		if (i == 0) {
			data = ((pattern & pattern_mask[fbe]) |
				       (~pattern & pattern_mask[~fbe & 0xf]));
		} else if (i == len - 1) {
			data = ((pattern & pattern_mask[lbe]) |
				       (~pattern & pattern_mask[~lbe & 0xf]));
		} else {
			data = pattern;
		}

		*((u32 *)rvec->virt_addr + i) = cpu_to_le32(data);
		pattern_gen_addr += 4;
	}
	dma_sync_single_for_device(dev, rvec->dma_addr, rvec->len, DMA_TO_DEVICE);
}

static void rpb_vm_data_pattern_generate(struct rpb_device *rdev, bool write)
{
	int i;

	/* No need to prepare data pattern manually for write operation */
	if (write)
		return;

	/* increment data pattern generated for memory read operation */
	for (i = 0; i < rdev->next_vec; i++)
		gen_increment_pattern_for_mem_read(rdev, &rdev->vecs[i]);
}

static int check_error_regs(struct rpb_device *rdev)
{
	u32 actual_data[MAX_ERROR_COUNT] = { 0 };
	u32 expect_data[MAX_ERROR_COUNT] = { 0 };
	int err = 0;
	u8 stream_id;
	u64 err_addr;
	u32 tmp_data;
	u32 data;
	int i;

	/* Check VMx Error Control Register */
	data = rpb_readl(vm_reg_addr(rdev, ERR_CTRL));
	if (FIELD_GET(VMX_VALID_STRM_ID, data)) {
		stream_id = FIELD_GET(VMX_STRM_ID, data);
		if (!(data & (1 << (16 + stream_id))))
			return 0;

		err = -EFAULT;
		dev_err(&rdev->pdev->dev, "%s: stream %d has error\n",
			__func__, stream_id);
		data = rpb_readl(vm_reg_addr(rdev, ERR_LOWER_ADDR));
		err_addr = FIELD_GET(VMX_LOWER_ADDR, data) << 2;
		if (FIELD_GET(VMX_UPPER_ADDR_NOZERO, data)) {
			data = rpb_readl(vm_reg_addr(rdev, ERR_UPPER_ADDR));
			err_addr |= FIELD_GET(VMX_UPPER_ADDR, data) << 32;
		}

		dev_err(&rdev->pdev->dev, "%s: Error address: 0x%llx\n", __func__, err_addr);
		data = rpb_readl(vm_reg_addr(rdev, ERR_CTRL));
		data &= ~VMX_ERROR_IDX;
		data &= ~(VMX_ERR_VALID_STRM0 | VMX_ERR_VALID_STRM1 | VMX_ERR_VALID_STRM2 |
			  VMX_ERR_VALID_STRM3 | VMX_CLR_MWBC0 | VMX_CLR_MWBC1 | VMX_CLR_MWBC2 |
			  VMX_CLR_MWBC3);
		for (i = 0; i < MAX_ERROR_COUNT; i++) {
			tmp_data = data & ~VMX_ERROR_IDX;
			tmp_data |= FIELD_PREP(VMX_ERROR_IDX, i);
			rpb_writel(tmp_data, vm_reg_addr(rdev, ERR_CTRL));
			actual_data[i] = rpb_readl(vm_reg_addr(rdev, ERR_ACTUAL_DATA));
			expect_data[i] = rpb_readl(vm_reg_addr(rdev, ERR_EXPECT_DATA));
			dev_err(&rdev->pdev->dev, "%s: IDX: %d Actual data: 0x%08x, expected data: 0x%08x\n",
				__func__, i, actual_data[i], expect_data[i]);
		}
	}
	/* Check VMx Abort/Unsupport Counter Register */
	data = rpb_readl(vm_reg_addr(rdev, ABORT_CNT));
	if (data) {
		dev_err(&rdev->pdev->dev, "%s: VM Abort/Unsupport Counter: 0x%x",
			__func__, data);
		err = -EFAULT;
	}

	return err;
}

static int rpb_vm_verify_mem_read_result(struct rpb_device *rdev)
{
	return check_error_regs(rdev);
}

static int rpb_vm_verify_mem_write_result(struct rpb_device *rdev, int size)
{
	struct device *dev = &rdev->pdev->dev;
	struct rpb_vector *rvec;
	dma_addr_t pattern_gen_addr;
	u32 actual_data;
	u32 expect_data;
	u32 hit = 0;
	u32 pattern;
	u16 length;
	u16 len;
	int err;
	u8 fbe;
	u8 lbe;
	int i;
	int count = 0;

	err = check_error_regs(rdev);
	if (err) {
		dev_err(dev, "%s: Skip data verification\n",  __func__);
		return err;
	}

	for (i = 0; i < rdev->next_vec; i++) {
		rvec = &rdev->vecs[i];

		pattern_gen_addr = rvec->dma_addr;
		length = round_up(rvec->len, 4) / 4;
		fbe = rvec->vec.mem_write.first_dw_be;
		lbe = rvec->vec.mem_write.last_dw_be;

		dev_dbg(dev, "%s: Start to verify Data of DMA range 0x%llx - 0x%llx\n",
			__func__, rvec->dma_addr, rvec->dma_addr + rvec->len);
		for (len = 0; len < length; len++) {
			actual_data = *((u32 *)rvec->virt_addr + len);
			pattern = get_increment_pattern(pattern_gen_addr);

			if (len == 0) {
				expect_data = ((pattern & pattern_mask[fbe]) |
					       (~pattern & pattern_mask[~fbe & 0xf]));
			} else if (len == (length - 1)) {
				expect_data = ((pattern & pattern_mask[lbe]) |
					       (~pattern & pattern_mask[~lbe & 0xf]));
			} else {
				expect_data = pattern;
			}
			if (expect_data != actual_data) {
				dev_err(&rdev->pdev->dev, "%s: dma_addr=0x%llx, virt_addr=0x%llx, expect_data=0x%08x, actual_data=0x%08x\n",
					__func__, pattern_gen_addr,
					(u64)((u32 *)rvec->virt_addr + len),
					expect_data, actual_data);
			} else {
				hit++;
			}
			pattern_gen_addr += 4;
		}
	}

	count = hit * 4;

	if (count != size) {
		dev_dbg(dev, "write verify fail - hit %d actual %d\n", size, count);
		return -EFAULT;
	}

	return 0;
}

static int rpb_vm_verify_result(struct rpb_device *rdev, int size, bool write)
{
	struct device *dev = &rdev->pdev->dev;
	int ret = -EFAULT;

	if (write)
		ret = rpb_vm_verify_mem_write_result(rdev, size);
	else
		ret = rpb_vm_verify_mem_read_result(rdev);

	dev_info(dev, "result verification done: %s[%d]\n", ret ? "Fail" : "Pass", ret);
	return ret;
}

static inline void copy_to_vm_vector(struct vm_vector *vmvec, struct vm_vector *hvec)
{
	rpb_writeq(hvec->data[0], &vmvec->data[0]);
	rpb_writeq(hvec->data[1], &vmvec->data[1]);
}

static inline void mark_end_vector(struct vm_vector *vmvec)
{
	struct vm_vector tmp;

	tmp.data[0] = rpb_readq(&vmvec->data[0]);
	tmp.end = 1;
	rpb_writeq(tmp.data[0], &vmvec->data[0]);
}

static int install_vectors(struct rpb_device *rdev)
{
	int pos = 0;
	int i;

	for (i = 0; i < rdev->next_vec; i++) {
		if (rdev->vecs[i].prefix.type) {
			copy_to_vm_vector(&rdev->vectors[pos], &rdev->vecs[i].prefix);
			dev_dbg(&rdev->pdev->dev, "%s: prefix vector pos %d, u64_1: 0x%llx, u64_2: 0x%llx\n",
				__func__, pos,
				rdev->vectors[pos].data[0],
				rdev->vectors[pos].data[1]);
			pos++;
		}
		if (rdev->vecs[i].upper_addr.type) {
			copy_to_vm_vector(&rdev->vectors[pos], &rdev->vecs[i].upper_addr);
			dev_dbg(&rdev->pdev->dev, "%s: upper addr vector pos %d, u64_1: 0x%llx, u64_2: 0x%llx\n",
				__func__, pos,
				rdev->vectors[pos].data[0],
				rdev->vectors[pos].data[1]);
			pos++;
		}
		if (rdev->vecs[i].vec.type) {
			copy_to_vm_vector(&rdev->vectors[pos], &rdev->vecs[i].vec);
			dev_dbg(&rdev->pdev->dev, "%s: read/write vector pos %d, u64_1: 0x%llx, u64_2: 0x%llx\n",
				__func__, pos,
				rdev->vectors[pos].data[0],
				rdev->vectors[pos].data[1]);
			pos++;
		}
	}

	if (pos == 0)
		return 0;
	mark_end_vector(&rdev->vectors[pos - 1]);
	dev_dbg(&rdev->pdev->dev, "%s: Set pos %d as the last vector\n",
		__func__, pos - 1);

	return pos;
}

static u8 gen_dw_be_field(u64 address, u16 length, bool first)
{
	u8 res = 0;

	if (first && address % 4) {
		/* generate first dw enable field */
		res = GENMASK((address % 4) - 1, 0);
	} else if (!first && (address + length) % 4) {
		address += length;
		if (address % 4) {
			/* generate last dw enable field */
			res = ~GENMASK((address % 4) - 1, 0);
		}
	}

	return res;
}

static void gen_upper_addr_vec(struct rpb_device *rdev,
			       struct rpb_vector *rvec)
{
	struct upper_addr_vector *vec;

	vec = &rvec->upper_addr.ua_vec;

	/* Byte 0 */
	rvec->upper_addr.type = 0x06;
	rvec->upper_addr.end = 0;
	/* Byte 1 */
	vec->bus_num = rdev->pdev->bus->number;
	/* Byte 2 */
	vec->vec_to_fab = 0;	/* TODO */
	/* Byte 3 */
	vec->posted_tag = 0;	/* TODO */
	vec->steering_tag = 0;	/* TODO */
	/* Byte 4 */
	vec->ts_idx = 0;
	vec->obbf_o = 0;	/* TODO */
	vec->ts_cmd = 0;
	/* Byte 5 */
	vec->func_num = 0;
	vec->dev_num = 0;
	/* Byte6,7 */
	vec->pat_gen = FIELD_GET(GENMASK(21, 2), rvec->dma_addr);
	vec->atom_idx = 0;
	vec->steering_tt_sel = 0;
	/* Byte 8,9,10,11 */
	vec->tl_err_type = 0;
	vec->tl_side_band = 0;	/* TODO */
	vec->atom = 0;
	vec->th = 0;
	vec->nc = 0;		/* Data compare */
	/* Byte 12,13,14,15 */
	vec->upper_addr = FIELD_GET(GENMASK(63, 32), rvec->dma_addr);
}

static void gen_mem_write_vec(struct rpb_device *rdev,
			      struct rpb_vector *rvec)
{
	struct memory_write_vector *mm_write = &rvec->vec.mem_write;

	/* Byte 0 */
	rvec->vec.type = 0x9;
	rvec->vec.end = 0;
	mm_write->lock_first = 0;

	/* Byte 1 */
	mm_write->lock_last = 0;
	mm_write->mbc_enable = 1;	/* Master Byte counter */
	mm_write->mbc_sel = 0;
	mm_write->tag = 0;		/* Vector Tag */

	/* Byte 2 */
	mm_write->ph = 0;	/* Processing Hint */
	mm_write->address_type = 0;
	mm_write->lightweight = 0;
	mm_write->id_bo = 0;		/* ID-Based Ordering */
	mm_write->tag_bit8 = 0;
	mm_write->tag_bit9 = 0;

	/* Byte 3 */
	mm_write->repeat1 = 0;

	/* Byte 4 */
	mm_write->first_dw_be = gen_dw_be_field(rvec->dma_addr,
						rvec->len, true);
	mm_write->last_dw_be = gen_dw_be_field(rvec->dma_addr,
					       rvec->len, false);

	/* Byte 5 */
	mm_write->ri = 0;
	mm_write->pg = 0;
	mm_write->bo = 0;		/* Bus Master Override */
	mm_write->zero_len_write = 0;
	mm_write->traffic_class = 0;

	/* Byte 6 */
	mm_write->loop_modifier = 0;
	mm_write->no_snoop_attr0 = 0;
	mm_write->ordering_attr1 = 0;
	mm_write->next_length = 0;
	if (rvec->dma_addr & GENMASK(63, 32))
		mm_write->addr_size = 1;
	else
		mm_write->addr_size = 0;

	/* Byte 7 */
	mm_write->wait_count = 0;
	mm_write->nwc = 0;

	/* Byte 8,9,10,11 */
	mm_write->poisoned = 0;
	mm_write->digest = 0;
	mm_write->address = (rvec->dma_addr & GENMASK(31, 2)) >> 2;

	/* Byte 12,13 */
	mm_write->nbe_first_dw = 0;
	mm_write->nbe_last_dw = 0;
	mm_write->next_addr_adv = 0;
	mm_write->addr_adv = 0;

	/* Byte 14,15 */
	mm_write->data_pattern = 0;	/* Increment */
	mm_write->next_data_pattern = 0;

	mm_write->length = round_up(rvec->len, 4) / 4 - 1;
	mm_write->tgen_vector = 0;
	dev_dbg(&rdev->pdev->dev, "%s: mem write, addr 0x%x, len 0x%x\n",
		__func__, mm_write->address, mm_write->length);
}

static void gen_mem_read_vec(struct rpb_device *rdev,
			     struct rpb_vector *rvec)
{
	struct memory_read_vector *mm_read = &rvec->vec.mem_read;

	/* Byte 0 */
	rvec->vec.type = 0x8;
	rvec->vec.end = 0;
	mm_read->lock_first = 0;

	/* Byte 1 */
	mm_read->lock_last = 0;
	mm_read->tgt_range_sel = 0;
	mm_read->to = 0;
	mm_read->tag = 0;
	mm_read->poll = 0;
	mm_read->update_sticky_buf = 0;
	mm_read->ev_buf_update = 0;

	/* Byte 2 */
	mm_read->ph = 0;
	mm_read->address_type = 0;
	mm_read->lightweight = 0;
	mm_read->id_bo = 0;
	mm_read->tag_bit8 = 0;
	mm_read->tag_bit9 = 0;

	/* Byte 3 */
	mm_read->repeat = 0;

	/* Byte 4 */
	mm_read->first_dw_be = gen_dw_be_field(rvec->dma_addr, rvec->len, true);
	mm_read->last_dw_be = gen_dw_be_field(rvec->dma_addr, rvec->len, false);

	/* Byte 5 */
	mm_read->ri = 0;
	mm_read->pg = 0;
	mm_read->bo = 0;
	mm_read->lt = 0;
	mm_read->zero_len_read = 0;
	mm_read->traffic_class = 0;

	/* Byte 6 */
	mm_read->loop_modifier = 0;
	mm_read->no_snoop_attr0 = 0;
	mm_read->ordering_attr1 = 0;
	mm_read->next_length = 0;
	if (rvec->dma_addr & GENMASK(63, 32))
		mm_read->addr_size = 1;
	else
		mm_read->addr_size = 0;
	mm_read->mem_read_lock_req = 0;

	/* Byte 7 */
	mm_read->wait_count = 0;
	mm_read->nwc = 0;

	/* Byte 8,9,10,11 */
	mm_read->poisoned = 0;
	mm_read->digest = 0;
	mm_read->address = (rvec->dma_addr & GENMASK(31, 2)) >> 2;

	/* Byte 12,13 */
	mm_read->nbe_first_dw = 0;
	mm_read->nbe_last_dw = 0;
	mm_read->next_addr_adv = 0;
	mm_read->addr_adv = 0;

	/* Byte 14,15 */
	mm_read->data_pattern = 0;	/* Increment */
	mm_read->next_data_pattern = 0;

	mm_read->length = round_up(rvec->len, 4) / 4 - 1;
	mm_read->tgen_vector = 0;
	dev_dbg(&rdev->pdev->dev, "%s: mem read, addr 0x%x, len 0x%x\n",
		__func__, mm_read->address, mm_read->length);
}

static int generate_mem_vectors(struct rpb_device *rdev, bool write)
{
	struct rpb_vector *rvec;
	int i;

	for (i = 0; i < rdev->next_vec; i++) {
		rvec = &rdev->vecs[i];

		if (rvec->dma_addr > U32_MAX || force_upper_vector)
			gen_upper_addr_vec(rdev, rvec);

		if (write)
			gen_mem_write_vec(rdev, rvec);
		else
			gen_mem_read_vec(rdev, rvec);
	}

	install_vectors(rdev);

	return 0;
}

static void rpb_start_vm(struct rpb_device *rdev)
{
	u32 data = rpb_readl(vm_reg_addr(rdev, MMR));

	data &= ~(VMX_START | VMX_END_STS);
	data |= FIELD_PREP(VMX_START, 1);
	rpb_writel(data, vm_reg_addr(rdev, MMR));
	dev_info(&rdev->pdev->dev, "VM - Trust bit %d\n",
		 !!FIELD_GET(VMX_TRUST, data));
}

static bool rpb_check_done(struct rpb_device *rdev)
{
	int timeout_limited = 1000;
	u32 data;

	do {
		data = rpb_readl(vm_reg_addr(rdev, MMR));
		if (data & VMX_END_STS)
			return true;
		dev_dbg(&rdev->pdev->dev, "%s: MMR=0x%08x\n", __func__, data);
		data = rpb_readl(vm_reg_addr(rdev, ERR_CTRL));
		msleep(20);
	} while (timeout_limited-- > 0);

	return false;
}

static void rpb_reset_vm(struct rpb_device *rdev)
{
	u32 data;

	rpb_writel(0, vm_reg_addr(rdev, ABORT_CNT));
	data = rpb_readl(vm_reg_addr(rdev, ERR_CTRL));
	data |= FIELD_PREP(VMX_CLR_MWBC0, 1) | FIELD_PREP(VMX_CLR_MWBC1, 1) |
		FIELD_PREP(VMX_CLR_MWBC2, 1) | FIELD_PREP(VMX_CLR_MWBC3, 1);
	rpb_writel(data, vm_reg_addr(rdev, ERR_CTRL));
	data = rpb_readl(vm_reg_addr(rdev, MMR));
	data |= FIELD_PREP(VMX_ARAM_P_CLR, 1);
	data |= FIELD_PREP(VMX_END_STS, 1);

	rpb_writel(data, vm_reg_addr(rdev, MMR));

	pr_debug("%s: memset VM0 vector area, addr=0x%llx, size=0x%lx\n",
		__func__, (unsigned long long)rdev->vectors,
		sizeof(*rdev->vectors) * MAX_VECTOR_NUM);
	memset(rdev->vectors, 0, sizeof(*rdev->vectors) * MAX_VECTOR_NUM);
}

static void rpb_stop_vm(struct rpb_device *rdev)
{
	u32 data;

	data = rpb_readl(vm_reg_addr(rdev, MMR));
	data &= ~VMX_ENABLE;
	rpb_writel(data, vm_reg_addr(rdev, MMR));
}

static int rpb_run_vm(struct rpb_device *rdev)
{
	/* STEP 2: Start VM */
	rpb_start_vm(rdev);

	/* STEP 3: Check VM done */
	if (!rpb_check_done(rdev)) {
		dev_err(&rdev->pdev->dev, "%s: VM is timeout\n", __func__);
		return -ETIMEDOUT;
	}

	return 0;
}

static int rpb_start_mem_wl(struct rpb_device *rdev, bool write)
{
	u32 data;
	int ret;

	rpb_reset_vm(rdev);
	data = rpb_readl(vm_reg_addr(rdev, MMR));
	if (FIELD_GET(VMX_END_STS, data)) {
		dev_err(&rdev->pdev->dev, "Cannot start Workload, END_STS is set\n");
		return -EBUSY;
	}
	generate_mem_vectors(rdev, write);

	ret = rpb_run_vm(rdev);
	if (ret)
		return ret;

	return 0;
}

static int rpb_vm_mem_ops(struct rpb_device *rdev, int mem_size,
			  unsigned int mem_attr, unsigned int mem_op)
{
	enum dma_data_direction dir;
	bool write, force_shared;
	int ret;

	if (mem_op == RPB_MEM_OP_READ) {
		dir = DMA_TO_DEVICE;
		write = false;
	} else {
		dir = DMA_FROM_DEVICE;
		write = true;
	}

	if (mem_attr == RPB_MEM_ATTR_SHARED)
		force_shared = true;
	else
		force_shared = false;

	/*
	 * Memory operation steps
	 *
	 * Reset SW Vector Position.
	 * Allocate buffers.
	 * Data pattern preparation.
	 * do DMA mapping.
	 * Reset Vector Machine State.
	 * Memory operation process.
	 * do DMA unmapping.
	 * Memory operation result verification (check data pattern).
	 * Free buffers.
	 */

	rpb_vector_pos_reset(rdev);

	ret = rpb_vm_dma_buffer_alloc(rdev, mem_size);
	if (ret)
		return ret;

	rpb_vm_dma_buffer_map(rdev, dir, force_shared);

	rpb_vm_data_pattern_generate(rdev, write);

	ret = rpb_start_mem_wl(rdev, write);

	rpb_vm_dma_buffer_unmap(rdev, dir);

	if (!ret)
		ret = rpb_vm_verify_result(rdev, mem_size, write);

	rpb_vm_dma_buffer_free(rdev);

	return ret;
}

static int rpb_mem_test_check(struct rpb_mem_test test)
{
	if (test.mem_op == RPB_MEM_OP_NONE || test.mem_op >= RPB_MEM_OP_MAX)
		return -EINVAL;

	if (test.mem_attr == RPB_MEM_ATTR_NONE ||
	    test.mem_attr >= RPB_MEM_ATTR_MAX)
		return -EINVAL;

	if (test.mem_size == 0 || test.mem_size % 4 ||
	    test.mem_size >= RPB_MEM_SIZE_MAX)
		return -EINVAL;
	if ((test.mem_op == RPB_MEM_OP_P2P_MMIO_READ ||
	    test.mem_op == RPB_MEM_OP_P2P_MMIO_WRITE) &&
	    test.mem_size != 4)
		return -EINVAL;

	return 0;
}

static int rpb_vm_p2p_mmio_ops(struct rpb_device *rdev, phys_addr_t mmio_addr,
			       int mmio_size, unsigned int mem_attr,
			       unsigned int mem_ops)
{
	struct device *dev = &rdev->pdev->dev;
	enum dma_data_direction dir;
	struct rpb_vector *rvec;
	dma_addr_t dma_addr;
	bool target_addr_shared;
	void *virt_addr;
	bool write;
	int ret;

	if (mem_ops == RPB_MEM_OP_P2P_MMIO_WRITE) {
		dir = DMA_FROM_DEVICE;
		write = true;
	} else {
		dir = DMA_TO_DEVICE;
		write = false;
	}

	if (mem_attr == RPB_MEM_ATTR_SHARED)
		target_addr_shared = true;
	else
		target_addr_shared = false;

	rpb_vector_pos_reset(rdev);

	rvec = rpb_vm_get_next_vector(rdev);

	dev_info(dev, "Auth - Source device is in %s mode, target MMIO address is a %s address\n",
		 dev->authorized == MODE_SECURE ? "private" : "shared",
		 target_addr_shared ? "shared" : "private");

	if (target_addr_shared)
		virt_addr = ioremap_driver_hardened(mmio_addr, mmio_size);
	else
		virt_addr = ioremap_encrypted_flag(mmio_addr, mmio_size,
						   _PAGE_CACHE_MODE_UC_MINUS);
	if (!virt_addr)
		return -EFAULT;

	if (target_addr_shared)
		dma_addr = dma_map_resource(dev, mmio_addr, mmio_size, dir,
					    DMA_ATTR_FORCEUNENCRYPTED);
	else
		dma_addr = dma_map_resource(dev, mmio_addr, mmio_size, dir, 0);
	if (dma_mapping_error(dev, dma_addr)) {
		dev_err(dev, "Failed to map P2P MMIO\n");
		return -EFAULT;
	}

	rpb_writel(0, virt_addr);

	rvec->virt_addr = (unsigned long)virt_addr;
	rvec->dma_addr = dma_addr;
	rvec->len = 4;

	rpb_vm_data_pattern_generate(rdev, write);

	ret = rpb_start_mem_wl(rdev, write);

	dma_unmap_resource(dev, dma_addr, mmio_size, dir, 0);

	if (!ret)
		ret = rpb_vm_verify_result(rdev, rvec->len, write);

	iounmap(virt_addr);

	dev_info(dev, "P2P MMIO test done, %s[%d]\n", ret ? "Fail" : "Pass", ret);
	return ret;
}

static int rpb_start_p2p_mmio(struct rpb_device *rdev, struct rpb_mem_test test)
{
	int ret;

	rpb_test_start(rdev);

	ret = rpb_vm_p2p_mmio_ops(rdev, test.mmio_addr, test.mem_size,
				  test.mem_attr, test.mem_op);

	rpb_test_end(rdev);

	return ret;
}

static int rpb_start_mem_test(struct rpb_device *rdev)
{
	struct device *dev = &rdev->pdev->dev;
	struct rpb_mem_test t;
	int ret = -EINVAL;

	t.mem_op = rdev->mem_op;
	t.mem_attr = rdev->mem_attr;
	t.mem_size = rdev->mem_size;
	t.mmio_addr = rdev->mmio_addr;

	if (t.mem_op == RPB_MEM_OP_P2P_MMIO_READ ||
	    t.mem_op == RPB_MEM_OP_P2P_MMIO_WRITE) {
		dev_info(dev, "Start Test: OP[%s] MEM[%s] ADDR[0x%lx] SIZE[0x%x]\n",
			 mem_op_to_string(t.mem_op), mem_attr_to_string(t.mem_attr),
			 t.mmio_addr, t.mem_size);
	} else {
		dev_info(dev, "Start Test: OP[%s] MEM[%s] SIZE[0x%x]\n",
			 mem_op_to_string(t.mem_op),
			 mem_attr_to_string(t.mem_attr), t.mem_size);
	}

	if (rpb_mem_test_check(t)) {
		dev_info(dev, "Bad Test Parameter\n");
		return -EINVAL;
	}

	if (t.mem_op == RPB_MEM_OP_P2P_MMIO_READ ||
	    t.mem_op == RPB_MEM_OP_P2P_MMIO_WRITE) {
		ret = rpb_start_p2p_mmio(rdev, t);
		goto done;
	}

	rpb_test_start(rdev);

	ret = rpb_vm_mem_ops(rdev, t.mem_size, t.mem_attr, t.mem_op);

	rpb_test_end(rdev);

done:
	dev_info(dev, "Test result: %s[%d]\n", ret ? "Fail" : "Pass", ret);
	return ret;
}

static ssize_t run_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t len)
{
	struct rpb_device *rdev = dev_get_drvdata(dev);
	bool run;

	if (kstrtobool(buf, &run))
		return -EINVAL;

	if (run)
		rpb_start_mem_test(rdev);

	return len;
}
static DEVICE_ATTR_WO(run);

static struct attribute *rpb_attrs[] = {
	&dev_attr_mem_op.attr,
	&dev_attr_mem_attr.attr,
	&dev_attr_mem_size.attr,
	&dev_attr_mmio_addr.attr,
	&dev_attr_run.attr,
	NULL
};

static const struct attribute_group rpb_attr_grp = {
	.name = "testcase",
	.attrs = rpb_attrs,
};

static const struct attribute_group *rpb_attr_grps[] = {
	&rpb_attr_grp,
	NULL
};

static int rpb_initialize(struct rpb_device *rdev)
{
	u32 data;

	data = rpb_readl(vm_reg_addr(rdev, MMR));

	/* VM uses default mode */
	data &= ~VMX_MODE;
	data |= FIELD_PREP(VMX_MODE, 0);
	/* VM stop when read data mismatch */
	data |= FIELD_PREP(VMX_SM, 1);
	data |= FIELD_PREP(VMX_END_STS, 1);
	data |= FIELD_PREP(VMX_ENABLE, 1);
	if (trust_bit == 0)
		data &= ~VMX_TRUST;
	else if (trust_bit == 1)
		data |= FIELD_PREP(VMX_TRUST, 1);
	rpb_writel(data, vm_reg_addr(rdev, MMR));

	return 0;
}

#define DRV_NAME "rpb"

static int rpb_map_bars(struct rpb_device *rdev)
{
	struct pci_dev *pdev = rdev->pdev;

	if (pci_resource_len(pdev, 0) == 0 ||
	    pci_resource_flags(pdev, 0) & IORESOURCE_UNSET)
		return -ENODEV;

	if (pcim_iomap_regions(pdev, BIT(0), DRV_NAME)) {
		dev_err(&pdev->dev, "Failed to map bars\n");
		return -ENODEV;
	}

	rdev->bar0_base = pcim_iomap_table(pdev)[0];
	pr_info("%s: bar0_base = 0x%llx\n", __func__,
		(unsigned long long)rdev->bar0_base);
	return 0;
}

static long rpb_autotest_run(struct rpb_device *rdev,
			     unsigned int mem_op,
			     unsigned int mem_attr,
			     unsigned int mem_size)
{
	long failure_cnt = 0;
	unsigned long i;

	for (i = 0; i < autotest_loops; i++) {
		rdev->mem_op = mem_op;
		rdev->mem_attr = mem_attr;
		rdev->mem_size = mem_size;
		if (rpb_start_mem_test(rdev))
			failure_cnt++;
	}

	return failure_cnt;
}

static void rpb_autotest(struct rpb_device *rdev)
{
	/* Failure cases counter */
	unsigned long ret, priv_wr = 0, priv_rd = 0, shared_wr = 0, shared_rd = 0;

	if (rdev->pdev->dev.authorized == MODE_SECURE) {
		/* Private Memory Write Test */
		priv_wr = rpb_autotest_run(rdev, RPB_MEM_OP_WRITE,
					   RPB_MEM_ATTR_DEFAULT, 4096);

		/* Private Memory Read Test */
		priv_rd = rpb_autotest_run(rdev, RPB_MEM_OP_READ,
					   RPB_MEM_ATTR_DEFAULT, 4096);
	}

	/* Shared Memory Write Test */
	shared_wr = rpb_autotest_run(rdev, RPB_MEM_OP_WRITE,
				     RPB_MEM_ATTR_SHARED, 4096);

	/* Shared Memory Read Test */
	shared_rd = rpb_autotest_run(rdev, RPB_MEM_OP_READ,
				     RPB_MEM_ATTR_SHARED, 4096);

	ret = priv_wr + priv_rd + shared_wr + shared_rd;
	if (rdev->pdev->dev.authorized == MODE_SECURE)
		dev_info(&rdev->pdev->dev, "Autotest result: %s    Priv Mem WR[%lu/%u] Priv Mem RD[%lu/%u] Shared Mem WR[%lu/%u] Shared Mem RD[%lu/%u]\n",
			 ret ? "Fail" : "Pass",
			 autotest_loops - priv_wr, autotest_loops,
			 autotest_loops - priv_rd, autotest_loops,
			 autotest_loops - shared_wr, autotest_loops,
			 autotest_loops - shared_rd, autotest_loops);
	else
		dev_info(&rdev->pdev->dev, "Autotest result: %s    Shared Mem WR[%lu/%u] Shared Mem RD[%lu/%u]\n",
			 ret ? "Fail" : "Pass",
			 autotest_loops - shared_wr, autotest_loops,
			 autotest_loops - shared_rd, autotest_loops);
}

static int rpb_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct rpb_device *rdev;
	int offset;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret < 0)
		return ret;

	pci_set_master(pdev);
	pci_aer_clear_nonfatal_status(pdev);
	dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));

	rdev = devm_kzalloc(&pdev->dev, sizeof(*rdev), GFP_KERNEL);
	if (!rdev)
		return -ENOMEM;

	mutex_init(&rdev->test_lock);
	rdev->pdev = pdev;

	ret = rpb_map_bars(rdev);
	if (ret)
		return ret;

	offset = get_vm_reg_block_offset(pdev, DEFAULT_VM_ID);
	if (offset < 0)
		return offset;

	/* Only initialize DEFAULT VM for testing */
	rdev->vectors = rdev->bar0_base + DEFAULT_VM_ID * 1024 * 32;
	rdev->vm_regs = rdev->bar0_base + offset;

	ret = rpb_initialize(rdev);
	if (ret)
		return ret;

	pci_set_drvdata(pdev, rdev);

	if (autotest)
		rpb_autotest(rdev);

	return ret;
}

static void rpb_remove(struct pci_dev *pdev)
{
	struct rpb_device *rdev = pci_get_drvdata(pdev);

	rpb_reset_vm(rdev);
	rpb_stop_vm(rdev);
}

static pci_ers_result_t rpb_error_detected(struct pci_dev *pdev,
					   pci_channel_state_t state)
{
	if (state == pci_channel_io_normal)
		return PCI_ERS_RESULT_CAN_RECOVER;

	dev_warn(&pdev->dev, "Error State 0x%x\n", state);
	return PCI_ERS_RESULT_NEED_RESET;
}

static const struct pci_error_handlers rpb_err_handler = {
	.error_detected = rpb_error_detected,
};

static const struct pci_device_id rpb_id_table[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCIE_DEVICE_ID_CAMBRIA),},
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, rpb_id_table);
static struct pci_driver rpb_driver = {
	.name		= DRV_NAME,
	.id_table	= rpb_id_table,
	.probe		= rpb_probe,
	.remove		= rpb_remove,
	.dev_groups	= rpb_attr_grps,
	.err_handler	= &rpb_err_handler,
};

static inline void *__rpb_ide_init(struct pci_dev *pdev, uint8_t stream_id)
{
	return _rpb_ide_init(pdev, 0, stream_id);
}

static inline int rpb_key_prog(void *private_data, u32 sub_stream,
			       u8 direction, u32 *key, u32 *iv_key)
{
	struct rpb_ide *ide;

	ide = private_data;
	rpb_ide_key_prog(ide, sub_stream, direction, key, iv_key);

	return 0;
}

static inline int rpb_key_set_go(void *private_data)
{
	struct rpb_ide *ide;

	ide = private_data;

	return _rpb_enable_sel_stream(ide);
}

static inline int rpb_key_set_stop(void *private_data)
{
	struct rpb_ide *ide;

	ide = private_data;
	_rpb_disable_sel_stream(ide);

	return 0;
}

static inline void __rpb_ide_deinit(void *private_data)
{
	struct rpb_ide *ide;

	ide = private_data;

	return _rpb_ide_release(ide);
}

static inline int adisp_start_intf_mmio(void *private_data)
{
	struct rpb_ide *ide;

	ide = private_data;

	return _rpb_set_trust_bit(ide, true);
}

static inline int adisp_start_intf_dma(void *private_data)
{
	struct rpb_ide *ide;

	ide = private_data;

	return _rpb_set_trust_bit(ide, true);
}

static inline int adisp_stop_intf(void *private_data)
{
	struct rpb_ide *ide;

	ide = private_data;

	return _rpb_set_trust_bit(ide, false);
}

static inline int tdisp_start_intf(void *private_data)
{
	struct rpb_ide *ide;

	ide = private_data;

	return _rpb_set_trust_bit(ide, true);
}

static inline int tdisp_stop_intf(void *private_data)
{
	struct rpb_ide *ide;

	ide = private_data;

	return _rpb_set_trust_bit(ide, false);
}

static int __init rpb_init(void)
{
	BUILD_BUG_ON(sizeof(struct vm_vector) != 16);

	return pci_register_driver(&rpb_driver);
}

static void __exit rpb_exit(void)
{
	pci_unregister_driver(&rpb_driver);
}

module_init(rpb_init);
module_exit(rpb_exit);

MODULE_DESCRIPTION("RPB driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");

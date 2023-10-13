/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_RPB_H
#define LINUX_RPB_H

#define PCIE_DEVICE_ID_CAMBRIA	0x0d52

struct rpb_ide {
	void __iomem *bar0_base;
	/*
	 * Put trust_bit_enabled here temporarily,
	 * trust bit is per Vector Machine, that means
	 * actually trust bit is irrelavent with IDE,
	 * but rpb driver only support one VM and one IDE at present,
	 * there isn't a conflict between IDE and trust bit.
	 */
	bool trust_bit_enabled;

	/*
	 * Currently, RPB only supports enabling an Selective IDE stream
	 * on Stream Control Block A
	 */
	int ide_id;
	u8 ctrl_blk_id;
	bool sel_stream_enabled;
	u8 sel_stream_id;
	u32 key_slot_offset[PCI_IDE_SUB_STREAM_NUM][PCI_IDE_SUB_STREAM_DIRECTION_NUM];
	u32 ifv_slot_offset[PCI_IDE_SUB_STREAM_NUM][PCI_IDE_SUB_STREAM_DIRECTION_NUM];

	u32 keys[PCI_IDE_SUB_STREAM_NUM][PCI_IDE_SUB_STREAM_DIRECTION_NUM][8];
	u32 ifv[PCI_IDE_SUB_STREAM_NUM][PCI_IDE_SUB_STREAM_DIRECTION_NUM][2];

	struct pci_dev *pdev;
};

static inline bool is_rpb_device(struct pci_dev *pdev)
{
	return (pdev->vendor == PCI_VENDOR_ID_INTEL &&
		pdev->device == PCIE_DEVICE_ID_CAMBRIA);
}

static inline bool is_vtc_device(struct pci_dev *pdev)
{
	u8 val;

	if (pci_read_config_byte(pdev, PCI_REVISION_ID, &val))
		return false;

	return is_rpb_device(pdev) && val == 0x1;
}

struct rpb_ide *_rpb_ide_init(struct pci_dev *pdev, int ide_id,
			      u8 stream_id);
void _rpb_ide_release(struct rpb_ide *ide);
int _rpb_set_trust_bit(struct rpb_ide *ide, bool trust);
void _rpb_disable_sel_stream(struct rpb_ide *ide);
int _rpb_enable_sel_stream(struct rpb_ide *ide);

static inline struct rpb_ide *rpb_ide_init(struct pci_dev *pdev, int ide_id,
					   u8 stream_id)
{
	struct rpb_ide *(*fn)(struct pci_dev *pdev, int ide_id, u8 stream_id);
	struct rpb_ide *ide;

	if (!pdev)
		return ERR_PTR(-EINVAL);
	if (!is_rpb_device(pdev))
		return ERR_PTR(-EINVAL);

	fn = symbol_get(_rpb_ide_init);
	if (!fn)
		return ERR_PTR(-ENOENT);
	ide = fn(pdev, ide_id, stream_id);
	symbol_put(_rpb_ide_init);

	return ide;
}

static inline void rpb_ide_release(struct rpb_ide *ide)
{
	void (*fn)(struct rpb_ide *ide);

	if (!ide)
		return;
	fn = symbol_get(_rpb_ide_release);
	if (!fn)
		return;
	fn(ide);
	symbol_put(_rpb_ide_release);
}

static inline int rpb_enable_sel_stream(struct rpb_ide *ide)
{
	int (*fn)(struct rpb_ide *ide);
	int ret;

	fn = symbol_get(_rpb_enable_sel_stream);
	if (!fn)
		return -ENOENT;
	ret = fn(ide);
	symbol_put(_rpb_enable_sel_stream);

	return ret;
}

static inline void rpb_disable_sel_stream(struct rpb_ide *ide)
{
	void (*fn)(struct rpb_ide *ide);

	fn = symbol_get(_rpb_disable_sel_stream);
	if (!fn)
		return;
	fn(ide);
	symbol_put(_rpb_disable_sel_stream);
}

static inline int rpb_ide_key_prog(struct rpb_ide *ide, u32 sub_stream,
				   u8 direction, u32 *key, u32 *ifv)
{
	if (!ide)
		return -EINVAL;
	if (sub_stream >= PCI_IDE_SUB_STREAM_NUM)
		return -EINVAL;
	if (direction >= PCI_IDE_SUB_STREAM_DIRECTION_NUM)
		return -EINVAL;

	memcpy(ide->keys[sub_stream][direction], key, sizeof(u32) * 8);
	memcpy(ide->ifv[sub_stream][direction], ifv, sizeof(u32) * 2);

	return 0;
}

static inline int rpb_set_trust_bit(struct rpb_ide *ide, bool trust)
{
	int (*fn)(struct rpb_ide *ide, bool trust);
	int ret;

	if (ide->trust_bit_enabled && trust)
		return 0;
	if (!ide->trust_bit_enabled && !trust)
		return 0;

	fn = symbol_get(_rpb_set_trust_bit);
	if (!fn)
		return -ENOENT;
	ret = fn(ide, trust);
	symbol_put(_rpb_set_trust_bit);

	return ret;
}

#endif /* LINUX_RPB_H */

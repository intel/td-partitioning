// SPDX-License-Identifier: GPL-2.0

#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/bitfield.h>
#include <linux/pci-doe.h>
#include <linux/rpb.h>

#include "pci.h"

static inline bool is_pcie_ide_supported(struct pci_dev *dev)
{
	/* WA for VTC */
	if (is_vtc_device(dev))
		return true;

	return !!dev->ide_support;
}

static int pci_ide_id_alloc(struct pci_dev *dev, enum pci_ide_stream_type type)
{
	int min, max;

	if (type == PCI_IDE_STREAM_TYPE_LINK) {
		max = dev->ide_lnk_num - 1;
		min = 0;
	} else {
		max = dev->ide_lnk_num + dev->ide_sel_num - 1;
		min = dev->ide_lnk_num;
	}

	return ida_alloc_range(&dev->ide_ids, min, max, GFP_KERNEL);
}

static void pci_ide_id_free(struct pci_dev *dev, int ide_id)
{
	ida_free(&dev->ide_ids, ide_id);
}

static void dump_pci_ide_info(struct pci_dev *dev)
{
	int pos = dev->ide_pos;
	u32 ide_cap;

	pci_read_config_dword(dev, pos + PCI_IDE_CAP, &ide_cap);
	dev_info(&dev->dev, "IDE CAP = %x\n", ide_cap);
}

static struct pci_ide_stream *pci_ide_stream_alloc(struct pci_dev *rp_dev,
						   struct pci_dev *dev,
						   struct spdm_session *sess,
						   enum pci_ide_stream_type type,
						   enum pci_ide_stream_algorithm algorithm,
						   u32 flags)
{
	struct pci_ide_stream *stm;
	int ret;

	if (!is_pcie_ide_supported(dev) || !is_pcie_ide_supported(rp_dev))
		return ERR_PTR(-EINVAL);
	if (!pci_ide_type_is_valid(type))
		return ERR_PTR(-EINVAL);
	if (!pci_ide_type_is_supported(dev, type))
		return ERR_PTR(-EINVAL);
	if (!pci_ide_type_is_supported(rp_dev, type))
		return ERR_PTR(-EINVAL);
	if (!pci_ide_algorithm_is_valid(algorithm))
		return ERR_PTR(-EINVAL);

	dump_pci_ide_info(rp_dev);
	/* WA - VTC does not have IDE ECAP */
	if (!is_vtc_device(dev))
		dump_pci_ide_info(dev);

	stm = kzalloc(sizeof(*stm), GFP_KERNEL);
	if (!stm)
		return ERR_PTR(-ENOMEM);

	stm->rp_dev = rp_dev;
	stm->dev = dev;
	stm->flags = flags;
	stm->type = type;
	stm->algo = algorithm;

	/* allocate a steam id which can be used on both ports */
	ret = pci_ide_stream_id_alloc(rp_dev, dev, flags);
	if (ret < 0)
		goto err_stm_free;
	stm->stream_id = ret;

	dev_info(&stm->dev->dev, "Get new stream ID %d\n", stm->stream_id);

	ret = pci_ide_id_alloc(stm->rp_dev, stm->type);
	if (ret < 0)
		goto err_stream_id_free;
	stm->rp_ide_id = ret;

	ret = pci_ide_id_alloc(stm->dev, stm->type);
	if (ret < 0)
		goto err_rp_ide_id_free;
	stm->ide_id = ret;

	stm->sess = sess;
	/*
	 * record this stream data structure in both devices
	 */
	rp_dev->ide_stm = stm;
	dev->ide_stm = stm;
	return stm;

err_rp_ide_id_free:
	pci_ide_id_free(stm->rp_dev, stm->rp_ide_id);
err_stream_id_free:
	dev_info(&stm->dev->dev, "Free stream ID %d\n", stm->stream_id);
	pci_ide_stream_id_free(stm->rp_dev, stm->dev, stm->stream_id);
err_stm_free:
	kfree(stm);

	return ERR_PTR(ret);
}

static void pci_ide_stream_free(struct pci_ide_stream *stm)
{
	pci_ide_id_free(stm->rp_dev, stm->rp_ide_id);
	pci_ide_id_free(stm->dev, stm->ide_id);

	dev_info(&stm->dev->dev, "Free stream ID %d\n", stm->stream_id);
	pci_ide_stream_id_free(stm->rp_dev, stm->dev, stm->stream_id);
	kfree(stm);
}

static struct pci_dev *pci_ide_dev_get(struct pci_dev *dev)
{
	dev = pci_physfn(dev);

	if (dev->multifunction && PCI_FUNC(dev->devfn))
		return pci_get_slot(dev->bus,
				    PCI_DEVFN(PCI_SLOT(dev->devfn), 0));

	return pci_dev_get(dev);
}

static struct pci_dev *pci_ide_rp_dev_get(struct pci_dev *dev)
{
	return pci_dev_get(pcie_find_root_port(dev));
}

static void pci_ide_dev_put(struct pci_dev *dev)
{
	pci_dev_put(dev);
}

#define PCI_DOE_VID_PCISIG		0x1
#define PCI_DOE_PCISIG_SECURE_SPDM	0x2

struct pci_ide_stream *pci_ide_stream_setup(struct pci_dev *dev,
					    struct spdm_session *sess,
					    u32 flags)
{
	struct pci_dev *rp_dev, *target_dev;
	struct pci_ide_stream *stm;
	int ret;

	dev_info(&dev->dev, "%s: request %s stream %s mode\n", __func__,
		 flags & PCI_IDE_FLAG_LINK ? "Link" : "Selective",
		 flags & PCI_IDE_FLAG_TEE ? "TEE" : "non-TEE");

	if (flags & PCI_IDE_FLAG_LINK) {
		dev_err(&dev->dev, "Link IDE stream is not supported yet\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (!(flags & PCI_IDE_FLAG_TEE)) {
		dev_err(&dev->dev, "non TEE mode is not supported yet\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	rp_dev = pci_ide_rp_dev_get(dev);
	if (!rp_dev)
		return ERR_PTR(-ENODEV);

	target_dev = pci_ide_dev_get(dev);
	if (!target_dev) {
		ret = -ENODEV;
		goto exit_rp_dev_put;
	}

	if (!is_pcie_ide_supported(rp_dev) ||
	    !is_pcie_ide_supported(target_dev)) {
		dev_err(&dev->dev,
			"%s: RP or device does not support IDE capability\n",
			__func__);
		ret = -EINVAL;
		goto exit_target_dev_put;
	}

	dev_info(&dev->dev, "%s: Start to create IDE stream between %s and %s\n",
		 __func__, dev_name(&rp_dev->dev), dev_name(&target_dev->dev));
	stm = pci_ide_stream_alloc(rp_dev, target_dev, sess,
				   PCI_IDE_STREAM_TYPE_SEL,
				   PCI_IDE_ALGO_AES_GCM_256_96B_MAC, flags);
	if (IS_ERR(stm)) {
		ret = PTR_ERR(stm);
		goto exit_target_dev_put;
	}

	ret = pci_arch_ide_stream_setup(stm);
	if (ret)
		goto exit_free_stream;

	dev_info(&dev->dev, "%s: request done\n", __func__);
	return stm;

exit_free_stream:
	pci_ide_stream_free(stm);
exit_target_dev_put:
	pci_ide_dev_put(target_dev);
exit_rp_dev_put:
	pci_ide_dev_put(rp_dev);

	dev_info(&dev->dev, "%s: Failed to set up IDE Stream\n", __func__);

	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(pci_ide_stream_setup);

void pci_ide_stream_remove(struct pci_ide_stream *stm)
{
	struct pci_dev *rp_dev = stm->rp_dev;
	struct pci_dev *dev = stm->dev;

	if (!pci_arch_ide_stream_remove(stm))
		pci_ide_stream_free(stm);

	pci_ide_dev_put(dev);
	pci_ide_dev_put(rp_dev);
}
EXPORT_SYMBOL_GPL(pci_ide_stream_remove);

void pci_ide_stream_save(struct pci_dev *dev)
{
	/* TODO */
	return;
}
EXPORT_SYMBOL_GPL(pci_ide_stream_save);

void pci_ide_stream_restore(struct pci_dev *dev)
{
	/* TODO */
	return;
}
EXPORT_SYMBOL_GPL(pci_ide_stream_restore);

static int ide_init(struct pci_dev *dev, int pos)
{
	int lnk_num = 0;
	int sel_num = 0;
	int ret;
	u32 cap;

	dev_info(&dev->dev, "%s\n", __func__);

	/*
	 * Check IDE Capability
	 *
	 * For Endpoint device, it must implement IDE_KM Responder role
	 * via DOE mailbox.
	 */

	if (is_vtc_device(dev)) {
		lnk_num = 1;
		sel_num = 1;
	} else {
		pci_read_config_dword(dev, pos + PCI_IDE_CAP, &cap);

		if (!(cap & (PCI_IDE_CAP_LNK | PCI_IDE_CAP_SEL))) {
			dev_info(&dev->dev, "IDE cap didn`t support link and selective stream\n");
			return 0;
		}

		if (cap & PCI_IDE_CAP_LNK)
			lnk_num = 1 + FIELD_GET(PCI_IDE_CAP_LNK_NUM, cap);
		if (cap & PCI_IDE_CAP_SEL)
			sel_num = 1 + FIELD_GET(PCI_IDE_CAP_SEL_NUM, cap);
	}

	ret = pci_ide_dev_init(dev);
	if (!ret) {
		dev->ide_support = true;
		dev->ide_pos = pos;
		dev->ide_lnk_num = lnk_num;
		dev->ide_sel_num = sel_num;
		ida_init(&dev->ide_ids);
	}

	return ret;
}

static void ide_remove(struct pci_dev *dev)
{
	dev_info(&dev->dev, "%s\n", __func__);

	WARN(!ida_is_empty(&dev->ide_ids), "%s: IDE IDs isn`t empty.", dev_name(&dev->dev));
	ida_destroy(&dev->ide_ids);
}

int pci_ide_init(struct pci_dev *dev)
{
	int pos;

	if (!pci_is_pcie(dev))
		return -ENODEV;

	/* WA - VTC does not have IDE ECAP */
	if (is_vtc_device(dev))
		return ide_init(dev, 0);

	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_IDE);
	if (pos)
		return ide_init(dev, pos);

	return -ENODEV;
}

void pci_ide_release(struct pci_dev *dev)
{
	if (dev->ide_support) {
		pci_ide_dev_release(dev);
		ide_remove(dev);
	}
}

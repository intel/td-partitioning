// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Intel Corporation
 */
#define pr_fmt(fmt) "TDX: " fmt

#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/cc_platform.h>
#include <linux/export.h>
#include <uapi/linux/virtio_ids.h>
#include <crypto/hash.h>

#include <asm/tdx.h>
#include <asm/tdxio.h>
#include <asm/cmdline.h>
#include "tdx.h"
#include "device-attest.h"

#define CMDLINE_MAX_NODES		100
#define CMDLINE_MAX_LEN			1000

/*
 * struct authorize_node - Device authorization node
 *
 * @bus: Name of the bus
 * @dev_list: device allow list per bus device type (eg:
 *            struct pci_device_id). If NULL, allow all
 *            devices.
 */
struct authorize_node {
	const char *bus;
	void *dev_list;
};

/*
 * Memory to store data passed via command line options
 * authorize_allow_devs.
 */
static char cmd_authorized_devices[CMDLINE_MAX_LEN];
static struct authorize_node cmd_allowed_nodes[CMDLINE_MAX_NODES];
static struct pci_device_id cmd_pci_ids[CMDLINE_MAX_NODES];
static int cmd_pci_nodes_len;
static int cmd_allowed_nodes_len;
static char acpi_allowed[CMDLINE_MAX_LEN];

/* Set true if authorize_allow_devs is used */
static bool filter_overridden;

static bool no_dev_attest;

#define PCI_DEVICE_DATA2(vend, dev, data) \
	.vendor = vend, .device = dev, \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID, 0, 0, \
	.driver_data = (kernel_ulong_t)(data)

/*
 * Allow list for PCI bus
 *
 * NOTE: Device ID is duplicated here. But for small list
 * of devices, it is easier to maintain the duplicated list
 * here verses exporting the device ID table from the driver
 * and use it.
 */
struct pci_device_id pci_allow_ids[] = {
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_NET, MODE_AUTH_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_BLOCK, MODE_AUTH_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_CONSOLE, MODE_AUTH_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_9P, MODE_AUTH_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_NET, MODE_AUTH_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_BLOCK, MODE_AUTH_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_CONSOLE, MODE_AUTH_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_9P, MODE_AUTH_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_VSOCK, MODE_AUTH_SHARED) },
	{ 0, },
};

/* List of ACPI HID allow list */
static char *acpi_allow_hids[] = {
	"LNXPWRBN",
	"ACPI0013",
};

/* List of PLATFORM HID allow list */
static char *platform_allow_hids[] = {
	"ACPI0013",
	"tdx_guest"
};

static struct authorize_node allow_list[] = {
	/* Allow devices in pci_allow_list in "pci" bus */
	{ "pci", pci_allow_ids },
	/* Allow devices in acpi_allow_hids in "acpi" bus */
	{ "acpi", acpi_allow_hids },
	/* Allow devices in platform_allow_hids in "platform" bus */
	{ "platform", platform_allow_hids },
};

static bool dev_is_acpi(struct device *dev)
{
	return !strcmp(dev_bus_name(dev), "acpi");
}

static bool dev_is_platform(struct device *dev)
{
       return !strcmp(dev_bus_name(dev), "platform");
}

#define DEVICE_INFO_DATA_BUF_SZ		(8 * PAGE_SIZE)

static int tdxio_devif_get_dev_info(struct pci_tdi *tdi)
{
	struct tpa_dev_info_data *info;
	unsigned int size;
	void *buf_ptr;
	int ret;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	ret = tdx_get_dev_info(tdi, &buf_ptr, &size);
	if (ret)
		return ret;

	parse_tpa_dev_info_data(info, buf_ptr);

	tdi->priv = info;
	tdi->identities = buf_ptr;
	tdi->identities_len = size;

	tdi->version                  = info->tdisp_info.tdisp_version;
	tdi->cap.dsm_caps             = info->tdisp_info.dsm_caps;
	tdi->cap.req_msgs_supported_l = info->tdisp_info.req_msgs_supported_l;
	tdi->cap.req_msgs_supported_h = info->tdisp_info.req_msgs_supported_h;
	tdi->cap.lock_flags_supported = info->tdisp_info.lock_flags_supported;
	tdi->cap.dev_addr_width       = info->tdisp_info.dev_addr_width;
	tdi->cap.num_req_this         = info->tdisp_info.num_req_this;
	tdi->cap.num_req_all          = info->tdisp_info.num_req_all;
	return ret;
}

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);
	sdesc->shash.tfm = alg;
	return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
		     const unsigned char *data, unsigned int datalen,
		     unsigned char *digest)
{
	struct sdesc *sdesc;
	int ret;

	sdesc = init_sdesc(alg);
	if (IS_ERR(sdesc)) {
		pr_info("can't alloc sdesc\n");
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
	kfree(sdesc);
	return ret;
}

static int sha384_hash(const unsigned char *data, unsigned int datalen,
		       unsigned char *digest)
{
	struct crypto_shash *alg;
	char *hash_alg_name = "sha384";
	int ret;

	alg = crypto_alloc_shash(hash_alg_name, 0, 0);
	if (IS_ERR(alg)) {
		pr_info("can't alloc alg %s\n", hash_alg_name);
		return PTR_ERR(alg);
	}
	ret = calc_hash(alg, data, datalen, digest);
	crypto_free_shash(alg);
	return ret;
}

static int tdxio_devif_validate(struct pci_tdi *tdi)
{
	u64 result[6];
	int ret;

	ret = sha384_hash(tdi->identities, tdi->identities_len, (char *)result);
	if (ret)
		return ret;

	/* currently use SHA384 HASH for dev pub key hash */
	return tdx_devif_validate(tdi->intf_id.func_id, result[5], result[4],
				  result[3], result[2], result[1], result[0]);
}

static int tdxio_devif_get_state(struct pci_tdi *tdi)
{
	struct tdisp_request_parm parm = { 0 };
	struct device *dev = &tdi->pdev->dev;
	int ret;

	parm.message = TDISP_GET_DEVIF_STATE;

	ret = tdx_devif_tdisp(tdi, &parm);
	if (ret)
		return ret;

	dev_dbg(dev, "%s: current TDI state is %u\n", __func__, tdi->state);
	return 0;
}

static int tdxio_devif_get_report(struct pci_tdi *tdi)
{
	struct tdisp_request_parm parm = { 0 };
	unsigned int max_len = PAGE_SIZE - 49;
	int ret;

	parm.message = TDISP_GET_DEVIF_REPORT;
	parm.get_devif_report.offset = 0;
	parm.get_devif_report.length = max_len;

	ret = tdx_devif_tdisp(tdi, &parm);
	if (ret)
		return ret;

	if (tdi->report_len == tdi->report_offset)
		return 0;

	/*
	 * as remaining length is not zero, copy devif report in one
	 * buffer for later phasing.
	 */
	while (tdi->report_offset < tdi->report_len) {
		unsigned int remain = tdi->report_len - tdi->report_offset;

		parm.message = TDISP_GET_DEVIF_REPORT;
		parm.get_devif_report.offset = tdi->report_offset;
		parm.get_devif_report.length = min(max_len, remain);

		ret = tdx_devif_tdisp(tdi, &parm);
		if (ret)
			goto done;
	}

done:
	return ret;
}

static u16 devif_rp_readw(void *data, u32 offset)
{
	return *(u16 *)(data + offset);
}

static u32 devif_rp_readl(void *data, u32 offset)
{
	return *(u32 *)(data + offset);
}

static u64 devif_rp_read_mmio_addr(void *data, u32 index)
{
	return devif_rp_readl(data, DEVIF_RP_MMIO_ADDR_LO(index)) |
	 ((u64)devif_rp_readl(data, DEVIF_RP_MMIO_ADDR_HI(index)) << 32);
}

static u32 devif_rp_read_mmio_pages(void *data, u32 index)
{
	return devif_rp_readl(data, DEVIF_RP_MMIO_PAGES(index));
}

static u32 devif_rp_read_mmio_attr(void *data, u32 index)
{
	return devif_rp_readl(data, DEVIF_RP_MMIO_ATTR(index));
}

static int tdxio_devif_parse_report(struct pci_tdi *tdi)
{
	u32 table_bir = ~1U, table_start = ~1U, table_end = ~1U, pba_bir = ~1U, pba_start = ~1U, pba_end = ~1U;
	int msix_cap;
	u32 i, bar, bar_prev = -1;
	u64 gpa, size, offset = 0;
	struct pci_dev *pdev = tdi->pdev;
	struct device *dev = &pdev->dev;
	struct pci_tdi_mmio *mmio;
	void *data = tdi->report;
	bool ismsix;

	tdi->interface_info = devif_rp_readw(data, DEVIF_RP_INTF_INFO);
	tdi->msix_ctrl = devif_rp_readw(data, DEVIF_RP_MSIX_CTRL);
	tdi->lnr_ctrl = devif_rp_readw(data, DEVIF_RP_LNR_CTRL);
	tdi->tph_ctrl = devif_rp_readl(data, DEVIF_RP_TPH_CTRL);

	tdi->mmio_range_num = devif_rp_readl(data, DEVIF_RP_MMIO_NUM);
	dev_info(dev, "%s: mmio_range_num %d\n", __func__, tdi->mmio_range_num);

	if (tdi->mmio_range_num > MAX_TDI_MMIO_RANGE)
		return -ENOMEM;

	msix_cap = pci_find_capability(pdev, PCI_CAP_ID_MSIX);
	if (msix_cap) {
		u16 control, vec_cnt;

		pci_read_config_word(pdev, msix_cap + PCI_MSIX_FLAGS, &control);
		vec_cnt = (control & PCI_MSIX_FLAGS_QSIZE) + 1;

		pci_read_config_dword(pdev, msix_cap + PCI_MSIX_TABLE, &table_start);
		table_end = table_start + vec_cnt * PCI_MSIX_ENTRY_SIZE;
		table_bir = (u8)(table_start & PCI_MSIX_TABLE_BIR);
		table_end = ALIGN(table_end, PAGE_SIZE);
		table_start = ALIGN_DOWN(table_start, PAGE_SIZE);

		pci_read_config_dword(pdev, msix_cap + PCI_MSIX_PBA, &pba_start);
		pba_end = pba_start + vec_cnt * PCI_MSIX_ENTRY_SIZE;
		pba_bir = (u8)(pba_start & PCI_MSIX_PBA_BIR);
		pba_end = ALIGN(pba_end, PAGE_SIZE);
		pba_start = ALIGN_DOWN(pba_start, PAGE_SIZE);

		dev_info(dev, "msix table_size=%x, table_bir=%x, table_start=%x, table_end=%x\n", table_end - table_start, table_bir, table_start, table_end);
		dev_info(dev, "msix pba_size=%x, pba_bir=%x, pba_start=%x, pba_end=%x\n", pba_end - pba_start, pba_bir, pba_start, pba_end);
	}

	for (i = 0; i < tdi->mmio_range_num; i++) {
		u32 attr;

		mmio = &tdi->mmio[i];

		attr = devif_rp_read_mmio_attr(data, i);

		mmio->haddr = devif_rp_read_mmio_addr(data, i);
		mmio->pages = devif_rp_read_mmio_pages(data, i);
		mmio->attr = (u16)attr;
		mmio->id = (u16)(attr >> 16);
		size = (u64)mmio->pages << PAGE_SHIFT;

		dev_info(dev, "%s: range[%u]: haddr 0x%016llx pages 0x%x, attr 0x%x\n",
			 __func__, i, mmio->haddr, mmio->pages, mmio->attr);

		/* TODO here just skip msix regions as it's falsely reported in devif report
		 * in future, if msix regions are included in devif report, it should be
		 * accepted as private mmio
		 */
		ismsix = !!(mmio->attr & (DEVIF_RP_MMIO_ATTR_PBA | DEVIF_RP_MMIO_ATTR_MSIX));
		if (ismsix)
			mmio->is_tee = false;
		else
			mmio->is_tee = is_pci_tdi_mmio_tee(mmio);

		bar = mmio->id;
		if (bar != bar_prev) {
			offset = 0;
			bar_prev = bar;
		}

		gpa = pci_resource_start(tdi->pdev, bar) + offset;
		if (gpa + size - 1 > pci_resource_end(tdi->pdev, bar))
			return -EINVAL;

		mmio->gpa = gpa;

		dev_info(dev, "%s: mmio[%u](%s)(%s): haddr 0x%llx gpa 0x%llx size 0x%llx id 0x%x attr 0x%x\n", __func__,
			 i, is_pci_tdi_mmio_tee(mmio) ? "TEE" : "non-TEE",
			 ismsix ? "MSIX" : "non-MSIX",
			 mmio->haddr, mmio->gpa, size, mmio->id, mmio->attr);

		offset += size;
	};

	return 0;
}

static bool is_tdxio_devif_report_valid(struct pci_tdi *tdi)
{
	struct device *dev = &tdi->pdev->dev;

	dev_dbg(dev, "intf_info 0x%x\n", tdi->interface_info);
	dev_dbg(dev, "msix_ctrl 0x%x\n", tdi->msix_ctrl);
	dev_dbg(dev, "lnr_ctrl 0x%x\n",  tdi->lnr_ctrl);
	dev_dbg(dev, "tph_ctrl 0x%x\n",  tdi->tph_ctrl);

	if ((tdi->interface_info & TDI_INTF_INFO_DMA_NO_PASID) == 0 ||
	    (tdi->interface_info & TDI_INTF_INFO_DMA_PASID) != 0 ||
	    (tdi->interface_info & TDI_INTF_INFO_ATS) != 0 ||
	    (tdi->interface_info & TDI_INTF_INFO_PRS) != 0) {
		dev_err(dev, "bad intf info - 0x%x\n", tdi->interface_info);
		return false;
	}

	if (tdi->msix_ctrl != 0) {
		dev_err(dev, "bad msix_ctrl - 0x%x\n", tdi->msix_ctrl);
		return false;
	}

	if (tdi->lnr_ctrl != 0) {
		dev_err(dev, "bad lnr_ctrl - 0x%x\n", tdi->lnr_ctrl);
		return false;
	}

	if (tdi->tph_ctrl != 0) {
		dev_err(dev, "bad tph_ctrl - 0x%x\n", tdi->tph_ctrl);
		return false;
	}

	return true;
}

static bool is_tdi_devif_report_valid(struct pci_tdi *tdi)
{
	struct pci_dev *pdev = tdi->pdev;
	struct device *dev = &pdev->dev;
	int i, j;

	/*
	 * Generic checking of device interface report
	 *
	 * 1.MMIO ranges match with pci_device (bar id and size)
	 */

	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		u64 haddr_start = 0, haddr_end = 0;
		size_t size, mmio_size;
		unsigned long flags;

		flags = pci_resource_flags(pdev, i);
		if (flags & IORESOURCE_IO)
			continue;

		size = pci_resource_len(pdev, i);
		if (!size)
			continue;

		for (j = 0; j < tdi->mmio_range_num; j++) {
			if (tdi->mmio[j].id != i)
				continue;

			mmio_size = tdi->mmio[j].pages << PAGE_SHIFT;

			if (!haddr_start) {
				haddr_start = tdi->mmio[j].haddr;
				haddr_end = haddr_start + mmio_size;
			} else {
				/* mmio ranges should not have holes */
				if (tdi->mmio[j].haddr != haddr_end) {
					dev_err(dev, "holes found in tdi mmio ranges\n");
					return false;
				}

				haddr_end += mmio_size;
			}
		}

		if (!haddr_start) {
			dev_err(dev, "bar %d not found in tdi mmio ranges\n", i);
			return false;
		}

		if (size != (haddr_end - haddr_start)) {
			dev_err(dev, "bar %d size not match\n", i);
			return false;
		}
	}

	return true;
}

static int tdxio_devif_verify(struct pci_tdi *tdi)
{
	struct pci_dev *pdev = tdi->pdev;
	bool attested;

	if (no_dev_attest) {
		dev_info(&pdev->dev, "Skip device attestation\n");
		return 0;
	}

	if (!is_tdxio_devif_report_valid(tdi)) {
		dev_err(&pdev->dev, "invalid devif report for tdxio\n");
		return -EINVAL;
	}

	if (!is_tdi_devif_report_valid(tdi)) {
		dev_err(&pdev->dev, "invalid devif report, not matching pci_dev\n");
		return -EFAULT;
	}

	/* TODO: adding checking for pci_dev per device interface report */
	attested = tdx_attest_device(tdi);

	dev_info(&pdev->dev, "Device attestation for %04x:%04x(%s) done: %s",
		 pdev->vendor, pdev->device, dev_name(&pdev->dev), attested ? "PASS" : "FAIL");

	return attested ? 0 : -ENOTSUPP;
}

static int tdxio_devif_tdisp(struct pci_tdi *tdi, u8 message)
{
	struct tdisp_request_parm parm = { 0 };

	parm.message = message;

	return tdx_devif_tdisp(tdi, &parm);
}

static int tdxio_devif_dmar_accept(struct pci_tdi *tdi)
{
	return tdx_dmar_accept(tdi->intf_id.func_id, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

static int tdxio_devif_accept_mmios(struct pci_tdi *tdi)
{
	struct device *dev = &tdi->pdev->dev;
	struct pci_tdi_mmio *mmio;
	u32 i;

	/* for each mmio range */
	for (i = 0; i < tdi->mmio_range_num; i++) {
		mmio = &tdi->mmio[i];

		if (!mmio->is_tee)
			continue;

		dev_info(dev, "accept mmio range bar %x gpa=0x%llx haddr=0x%llx nr_pages=0x%x",
			 mmio->id, mmio->gpa, mmio->haddr, mmio->pages);

		tdx_map_private_mmio(mmio->gpa, mmio->haddr, mmio->pages);
	}
	return 0;
}

static int tdxio_devif_accept(struct pci_tdi *tdi)
{
	struct device *dev = &tdi->pdev->dev;
	int ret;

	ret = tdxio_devif_dmar_accept(tdi);
	if (ret) {
		dev_err(dev, "Fail to accept DMAR %d\n", ret);
		return ret;
	}

	ret = tdxio_devif_accept_mmios(tdi);
	if (ret) {
		dev_err(dev, "Fail to accept MMIO %d\n", ret);
		return ret;
	}

	ret = tdxio_devif_tdisp(tdi, TDISP_START_INTF_REQ);
	if (ret) {
		dev_err(dev, "Fail to issue START INTF REQ %d\n", ret);
		return ret;
	}

	return ret;
}

static int tdx_guest_dev_attest(struct pci_dev *pdev, unsigned int enum_mode)
{
	u32 func_id, devid = pci_dev_id(pdev);
	u64 nonce0, nonce1, nonce2, nonce3;
	int ret, result = MODE_UNAUTHORIZED;
	struct pci_tdi_parm parm = { 0 };
	struct device *dev = &pdev->dev;
	struct pci_tdi *tdi;

	/*
	 * Step 0: Get pci_tdi context from Host/VMM
	 */
	ret = tdx_get_dev_context(devid, &func_id,
				  &nonce0, &nonce1, &nonce2, &nonce3);
	if (ret) {
		if (enum_mode != MODE_SECURE)
			return MODE_AUTH_SHARED;

		dev_err(dev, "failed to get dev context\n");
		return result;
	}

	/* If invalid handle, means this pci_dev is a non-TDISP device */
	if (!func_id) {
		if (enum_mode == MODE_AUTH_SHARED || enum_mode == MODE_UNAUTHORIZED) {
			pdev->untrusted = true;
			dev_info(dev, "return MODE SHARED\n");
			return MODE_AUTH_SHARED;
		}

		dev_info(dev, "no func_id but require PRIVATE Mode return UNAUTHORIZED\n");
		return result;
	}

	/* uses TDI in shared mode is not possible as TDI may be locked already */
	if (enum_mode == MODE_AUTH_SHARED)
		return result;

	/*
	 * Step 1: Pre-allocate pci_tdi data structure
	 */
	tdi = pci_tdi_alloc_and_init(pdev, parm);
	if (!tdi) {
		dev_err(dev, "failed to alloc TDI\n");
		return result;
	}

	tdi->intf_id.func_id = func_id;
	tdi->nonce[0] = nonce0;
	tdi->nonce[1] = nonce1;
	tdi->nonce[2] = nonce2;
	tdi->nonce[3] = nonce3;

	/*
	 * Step 2: Device Data Collection for TDI
	 *
	 * 2.1 Get DEVICE_INFO_DATA by TDVMCALL from VMM
	 * 2.2 TDG.DEVIF.VALIDATE
	 *   ensure DEVIF is locked and DEVICE_INFO_DATA is trusted
	 * 2.3 Get TDISP DEVIF report
	 */
	ret = tdxio_devif_get_dev_info(tdi);
	if (ret) {
		dev_err(dev, "Fail to get DEVICE_INFO_DATA %d\n", ret);
		goto done;
	}

	ret = tdxio_devif_validate(tdi);
	if (ret) {
		dev_err(dev, "Fail to validate DEVICE_INFO_DATA %d\n", ret);
		goto done;
	}

	ret = tdxio_devif_get_state(tdi);
	if (ret) {
		dev_err(dev, "Fail to GET_DEVIF_STATE %d\n", ret);
		goto done;
	}

	ret = tdxio_devif_get_report(tdi);
	if (ret) {
		dev_err(dev, "Fail to get TDISP DEVIF Report %d\n", ret);
		goto done;
	}

	ret = tdxio_devif_parse_report(tdi);
	if (ret) {
		dev_err(dev, "Fail to parse TDISP DEVIF Report %d\n", ret);
		goto done;
	}

	/*
	 * Step 3: Device Verify
	 *
	 * Verify with evidence: DEVICE_INFO_DATA + TDISP DEVIF report
	 */
	ret = tdxio_devif_verify(tdi);
	if (ret) {
		dev_err(dev, "Fail to verify TDISP DEVIF %d\n", ret);
		goto done;
	}

	/*
	 * Step 4: Additional Steps to accept TDISP DEVIF into TCB
	 *
	 * Including DMAR Accept, MMIO Accept, move DEVIF to TDISP RUN state.
	 */
	ret = tdxio_devif_accept(tdi);
	if (ret) {
		dev_err(dev, "Fail to accept TDISP DEVIF %d\n", ret);
		goto done;
	}

	ret = tdxio_devif_get_state(tdi);
	if (ret) {
		dev_err(dev, "Fail to GET_DEVIF_STATE %d\n", ret);
		goto done;
	}

	/*
	 * Step 5: last preparation steps before driver probing.
	 *
	 * Mark PCI device is trusted
	 *
	 * TODO:also mark PCI device is a TDISP Device in Run state
	 * (configuration is locked). PCI device driver may need to check this
	 * flag to prevent operations which may break the configuration and
	 * cause device entering error state (see TDISP spec, 11.2.6).
	 */
	pdev->untrusted = false;
	result = MODE_SECURE;
	return result;

done:
	pci_tdi_uinit_and_free(tdi);
	return result;
}

static int authorized_node_match(struct device *dev,
				 struct authorize_node *node)
{
	int i;

	/* If bus matches "ALL" and dev_list is NULL, return true */
	if (!strcmp(node->bus, "ALL") && !node->dev_list)
		return MODE_AUTH_SHARED;

	/*
	 * Since next step involves bus specific comparison, make
	 * sure the bus name matches with filter node. If not
	 * return false.
	 */
	if (strcmp(node->bus, dev->bus->name))
		return MODE_UNAUTHORIZED;

	/* If dev_list is NULL, allow all and return true */
	if (!node->dev_list)
		return MODE_AUTH_SHARED;

	/*
	 * Do bus specific device ID match. Currently only PCI
	 * and ACPI bus is supported.
	 */
	if (dev_is_pci(dev)) {
		struct pci_dev *pdev = to_pci_dev(dev);
		const struct pci_device_id *id;
		int status;

		id = pci_match_id((struct pci_device_id *)node->dev_list, pdev);
		if (id && (id->driver_data == MODE_AUTH_SHARED))
			status = MODE_AUTH_SHARED;
		else if (id)
			status = tdx_guest_dev_attest(pdev, id->driver_data);
		else
			status = MODE_UNAUTHORIZED;

		pr_info("PCI vendor:%x device:%x %s %s\n", pdev->vendor,
			pdev->device, status ? "allowed" : "blocked",
			status == MODE_SECURE ? "trusted" : "untrusted");

		if (status != MODE_UNAUTHORIZED)
			return status;

		/*
		 * Prevent any config space accesses in initcalls.
		 * No locking needed here because it's a fresh device.
		 */
		if (pci_pcie_type(pdev) != PCI_EXP_TYPE_ROOT_PORT)
			pdev->error_state = pci_channel_io_perm_failure;
	} else if (dev_is_acpi(dev)) {
		for (i = 0; i < ARRAY_SIZE(acpi_allow_hids); i++) {
			if (!strncmp(acpi_allow_hids[i], dev_name(dev),
						strlen(acpi_allow_hids[i])))
				return MODE_AUTH_SHARED;
		}
	} else if (dev_is_platform(dev)) {
		for (i = 0; i < ARRAY_SIZE(platform_allow_hids); i++) {
			if (!strncmp(platform_allow_hids[i], dev_name(dev),
						strlen(platform_allow_hids[i])))
				return MODE_AUTH_SHARED;
		}
	}

	return MODE_UNAUTHORIZED;
}

static struct pci_device_id *parse_pci_id(char *ids)
{
	unsigned int subdevice = PCI_ANY_ID, class = 0, class_mask = 0;
	unsigned int vendor, device, subvendor = PCI_ANY_ID;
	char *p, *id;
	int fields;

	p = ids;
	while ((id = strsep(&p, ","))) {
		if (!strlen(id))
			continue;
		fields = sscanf(id, "%x:%x:%x:%x:%x:%x", &vendor, &device,
				&subvendor, &subdevice, &class, &class_mask);
		if (fields < 2)
			continue;
		cmd_pci_ids[cmd_pci_nodes_len].vendor = vendor;
		cmd_pci_ids[cmd_pci_nodes_len].device = device;
		cmd_pci_ids[cmd_pci_nodes_len].subvendor = subvendor;
		cmd_pci_ids[cmd_pci_nodes_len].subdevice = subdevice;
		cmd_pci_nodes_len++;
	}

	return cmd_pci_ids;
}

static void *parse_device_id(const char *bus, char *ids)
{
	if (!strcmp(ids, "ALL"))
		return NULL;

	if (!strcmp(bus, "pci"))
		return parse_pci_id(ids);
	else
		return ids;
}

static __init void add_authorize_nodes(char *p)
{
	struct authorize_node *n;
	int j = 0;
	char *k;

	while ((k = strsep(&p, ";")) != NULL) {
		if (j >= CMDLINE_MAX_NODES) {
			pr_err("Authorize nodes exceeds MAX allowed\n");
			break;
		}
		n = &cmd_allowed_nodes[j++];
		n->bus = strsep(&k, ":");
		n->dev_list = parse_device_id(n->bus, k);
	}

	if (j)
		cmd_allowed_nodes_len = j;
}

static __init int allowed_cmdline_setup(char *buf)
{
	if (strlen(buf) >= CMDLINE_MAX_LEN)
		pr_warn("Authorized allowed devices list exceed %d chars\n",
			CMDLINE_MAX_LEN);

	strscpy(cmd_authorized_devices, buf, CMDLINE_MAX_LEN);

	add_authorize_nodes(cmd_authorized_devices);

	filter_overridden = true;

	return 0;
}
__setup("authorize_allow_devs=", allowed_cmdline_setup);

static int no_dev_attestation_setup(char *str)
{
	no_dev_attest = true;

	return 1;
}
__setup("no_dev_attest", no_dev_attestation_setup);

int dev_authorized_init(void)
{
	if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST) &&
			cc_filter_enabled())
		return MODE_UNAUTHORIZED;

	return MODE_AUTH_SHARED;
}

int arch_dev_authorized(struct device *dev)
{
	int i, authorized;

	if (!cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return MODE_AUTH_SHARED;

	if (!cc_filter_enabled())
		return MODE_AUTH_SHARED;

	if (!dev->bus)
		return dev->authorized;

	/* Lookup arch allow list */
	for (i = 0;  i < ARRAY_SIZE(allow_list); i++) {
		authorized = authorized_node_match(dev, &allow_list[i]);
		if (authorized)
			return authorized;
	}

	/* Lookup command line allow list */
	for (i = 0; i < cmd_allowed_nodes_len; i++) {
		authorized = authorized_node_match(dev, &cmd_allowed_nodes[i]);
		if (authorized)
			return authorized;
	}

	return false;
}

bool tdx_allowed_port(int port)
{
	if (tdx_debug_enabled() && !cc_filter_enabled())
		return true;

	switch (port) {
	/* MC146818 RTC */
	case 0x70 ... 0x71:
	/* i8237A DMA controller */
	case 0x80 ... 0x8f:
	/* PCI */
	case 0xcd8 ... 0xcdf:
	case 0xcf8 ... 0xcff:
		return true;
	/* PCIE hotplug device state for Q35 machine type */
	case 0xcc4:
	case 0xcc8:
		return true;
	/* ACPI ports list:
	 * 0600-0603 : ACPI PM1a_EVT_BLK
	 * 0604-0605 : ACPI PM1a_CNT_BLK
	 * 0608-060b : ACPI PM_TMR
	 * 0620-062f : ACPI GPE0_BLK
	 */
	case 0x600 ... 0x62f:
		return true;
	/* serial */
	case 0x2e8 ... 0x2ef:
	case 0x2f8 ... 0x2ff:
	case 0x3e8 ... 0x3ef:
	case 0x3f8 ... 0x3ff:
		return tdx_debug_enabled();
	default:
		return false;
	}
}

void __init tdx_filter_init(void)
{
	char a_allowed[60];
	char *allowed;

	if (!cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return;

	if (!cc_platform_has(CC_ATTR_GUEST_DEVICE_FILTER))
		return;

	if (cmdline_find_option_bool(boot_command_line, "noccfilter"))
		cc_set_filter_status(false);

	if (!cc_filter_enabled()) {
		pr_info("Disabled TDX guest filter support\n");
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
		return;
	}

	if (filter_overridden) {
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
		pr_debug("Device filter is overridden\n");
	}

	allowed = "XSDT,FACP,DSDT,FACS,APIC,SVKL,CCEL,SRAT";
	if (cmdline_find_option(boot_command_line, "tdx_allow_acpi",
				a_allowed, sizeof(a_allowed)) >= 0) {
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
		snprintf(acpi_allowed, sizeof(acpi_allowed), "%s,%s", allowed,
			 a_allowed);
		allowed = acpi_allowed;
	}
	acpi_tbl_allow_setup(allowed);

	pr_info("Enabled TDX guest device filter\n");
}

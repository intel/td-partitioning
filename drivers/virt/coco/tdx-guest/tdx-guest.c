// SPDX-License-Identifier: GPL-2.0
/*
 * TDX guest user interface driver
 *
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/acpi.h>
#include <linux/cpu.h>
#include <crypto/sha2.h>
#include <linux/tpm.h>

#include <uapi/linux/tdx-guest.h>

#include <asm/cpu_device_id.h>
#include <asm/tdx.h>

#define EV_NO_ACTION		0x03
#define EV_EVENT_TAG		0x00000006U
#define CC_INVALID_RTMR_IDX	0xFFFFFFFF

struct cc_event_head {
	u32 mr_idx;
	u32 event_type;
	u32 count;
};

struct cc_event_data {
	u32 size;
	u8 data[];
} __packed;

struct cc_sha384_event {
	struct cc_event_head head;
	u16 algo_id;
	u8 digest[SHA384_DIGEST_SIZE];
	struct cc_event_data data;
} __packed;

struct spec_id_head {
	u8 signature[16];
	u32 platform_class;
	u8 minor_ver;
	u8 major_ver;
	u8 errata;
	u8 uintn_size;
	u32 algo_count;
} __packed;

struct spec_id_algo_node {
	u16 type;
	u16 size;
};

struct spec_id_event {
	struct cc_event_head cc_head;
	u8 digest[20];
	struct spec_id_head sid_head;
} __packed;

static struct spec_id_algo_node *algo_list;
static void *next_event;
static void __iomem *ccel_addr;
static u64 ccel_len;
static u16 algo_count;

static u64 parse_spec_id_event(void *data)
{
	struct spec_id_event *event = data;
	u8 *vendor_size;
	u64 index = 0;

	index += sizeof(*event);

	algo_list = data + index;
	algo_count = event->sid_head.algo_count;
	index += sizeof(struct spec_id_algo_node) * algo_count;

	vendor_size = data + index;
	index += (sizeof(*vendor_size) + *vendor_size);

	return index;
}

static u64 parse_cc_event(void *data)
{
	struct cc_event_head *evhead = data;
	struct cc_event_data *evdata;
	u16 *algo_id, algo_size;
	u64 index = 0;
	int i, j;

	if (!algo_list)
		return 0;

	index += sizeof(*evhead);

	for (i = 0; i < evhead->count; i++) {
		algo_size = 0;
		algo_id = data + index;
		for (j = 0; j < algo_count; j++) {
			if (algo_list[j].type == *algo_id) {
				algo_size = algo_list[j].size;
				break;
			}
		}
		index += sizeof(*algo_id) + algo_size;
	}
	evdata = data + index;
	index += sizeof(*evdata) + evdata->size;

	return index;
}

static void* acpi_ccel_next_event(void)
{
	struct cc_event_head *evhead;
	struct acpi_table_ccel *ccel;
	u64 index = 0, start = 0, size = 0;
	acpi_status status;
	void *data;

	status = acpi_get_table(ACPI_SIG_CCEL, 0, (struct acpi_table_header **)&ccel);
	if (ACPI_FAILURE(status))
		return NULL;

	data = acpi_os_map_iomem(ccel->log_area_start_address, ccel->log_area_minimum_length);

	ccel_addr = data;
	ccel_len = ccel->log_area_minimum_length;

	while (index < ccel->log_area_minimum_length) {
		evhead = data + index;
		start = index;

		if (evhead->mr_idx == CC_INVALID_RTMR_IDX)
	                break;

		if (evhead->event_type == EV_NO_ACTION)
			index += parse_spec_id_event(evhead);
		else
			index += parse_cc_event(evhead);

		size = index - start;
	}

	return evhead;
}

static void acpi_ccel_release(void)
{
	if (!ccel_addr)
		return;

	acpi_os_unmap_iomem(ccel_addr, ccel_len);
}

static void ccel_record_eventlog(void *data, u8 index)
{
	struct cc_sha384_event *event = next_event;
	char event_data[] = "Runtime RTMR event log extend success";

	if (!event)
		return;

	/* Setup Evenlog header */
	event->head.mr_idx = index + 1;
	event->head.event_type = EV_EVENT_TAG;
	event->head.count = 1;
	event->algo_id = TPM_ALG_SHA384;
	memcpy(event->digest, data, SHA384_DIGEST_SIZE);

	event->data.size = strlen(event_data);
	memcpy(event->data.data, event_data, event->data.size);

	next_event += (sizeof(*event) + event->data.size);
}

static long tdx_get_report0(struct tdx_report_req __user *req)
{
	u8 *reportdata, *tdreport;
	long ret;

	reportdata = kmalloc(TDX_REPORTDATA_LEN, GFP_KERNEL);
	if (!reportdata)
		return -ENOMEM;

	tdreport = kzalloc(TDX_REPORT_LEN, GFP_KERNEL);
	if (!tdreport) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(reportdata, req->reportdata, TDX_REPORTDATA_LEN)) {
		ret = -EFAULT;
		goto out;
	}

	/* Generate TDREPORT0 using "TDG.MR.REPORT" TDCALL */
	ret = tdx_mcall_get_report0(reportdata, tdreport);
	if (ret)
		goto out;

	if (copy_to_user(req->tdreport, tdreport, TDX_REPORT_LEN))
		ret = -EFAULT;

out:
	kfree(reportdata);
	kfree(tdreport);

	return ret;
}

static long tdx_verify_report(struct tdx_verify_report_req __user *req)
{
	u8 *reportmac;
	long ret = 0;
	u64 err;

	reportmac = kmalloc(sizeof(req->reportmac), GFP_KERNEL);
	if (!reportmac)
		return -ENOMEM;

	if (copy_from_user(reportmac, req->reportmac, sizeof(req->reportmac))) {
		ret = -EFAULT;
		goto out;
	}

	/* Verify REPORTMACSTRUCT using "TDG.MR.VERIFYREPORT" TDCALL */
	err = tdx_mcall_verify_report(reportmac);
	if (err)
		ret = -EIO;

	if (copy_to_user(&req->err_code, &err, sizeof(u64)))
		ret = -EFAULT;
out:
	kfree(reportmac);

	return ret;
}

static long tdx_extend_rtmr(struct tdx_extend_rtmr_req __user *req)
{
	u8 *data, index;
	int ret;

	if (copy_from_user(&index, &req->index, sizeof(u8)))
		return -EFAULT;

	/*
	 * RTMR index 0 and 1 is used by BIOS and kernel and are not
	 * allowed for userspace update.
	 */
	if (index < 2)
		return -EPERM;

	/* TDG.MR.RTMR.EXTEND TDCALL expects buffer to be 64B aligned */
	data = kmalloc(ALIGN(sizeof(req->data), 64), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	if (copy_from_user(data, req->data, sizeof(req->data))) {
		ret = -EFAULT;
		goto out;
	}

	/* Extend RTMR registers using "TDG.MR.RTMR.EXTEND" TDCALL */
	ret = tdx_mcall_extend_rtmr(data, index);

	if (!ret)
		ccel_record_eventlog(data, index);
out:
	kfree(data);

	return ret;
}

static long tdx_guest_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	switch (cmd) {
	case TDX_CMD_GET_REPORT0:
		return tdx_get_report0((struct tdx_report_req __user *)arg);
	case TDX_CMD_VERIFY_REPORT:
		return tdx_verify_report((struct tdx_verify_report_req __user *)arg);
	case TDX_CMD_EXTEND_RTMR:
		return tdx_extend_rtmr((struct tdx_extend_rtmr_req __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations tdx_guest_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tdx_guest_ioctl,
	.llseek = no_llseek,
};

static struct miscdevice tdx_misc_dev = {
	.name = KBUILD_MODNAME,
	.minor = MISC_DYNAMIC_MINOR,
	.fops = &tdx_guest_fops,
};

static const struct x86_cpu_id tdx_guest_ids[] = {
	X86_MATCH_FEATURE(X86_FEATURE_TDX_GUEST, NULL),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, tdx_guest_ids);

static int __init tdx_guest_init(void)
{
	if (!x86_match_cpu(tdx_guest_ids))
		return -ENODEV;

	next_event = acpi_ccel_next_event();
	return misc_register(&tdx_misc_dev);
}
module_init(tdx_guest_init);

static void __exit tdx_guest_exit(void)
{
	acpi_ccel_release();
	misc_deregister(&tdx_misc_dev);
}
module_exit(tdx_guest_exit);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("TDX Guest Driver");
MODULE_LICENSE("GPL");

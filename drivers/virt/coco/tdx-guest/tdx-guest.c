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
#include <linux/set_memory.h>

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

/*
 * Intel's SGX QE implementation generally uses Quote size less
 * than 8K; Use 16K as MAX size to handle future updates and other
 * 3rd party implementations.
 */
#define GET_QUOTE_MAX_SIZE		(4 * PAGE_SIZE)

/**
 * struct quote_entry - Quote request struct
 * @valid: Flag to check validity of the GetQuote request.
 * @buf: Kernel buffer to share data with VMM (size is page aligned).
 * @buf_len: Size of the buf in bytes.
 * @compl: Completion object to track completion of GetQuote request.
 */
struct quote_entry {
	bool valid;
	void *buf;
	size_t buf_len;
	struct completion compl;
};

/* Quote data entry */
static struct quote_entry *qentry;

/* Lock to streamline quote requests */
static DEFINE_MUTEX(quote_lock);

static int quote_cb_handler(void *dev_id)
{
	struct quote_entry *entry = dev_id;
	struct tdx_quote_buf *quote_buf = entry->buf;

	if (entry->valid && quote_buf->status != GET_QUOTE_IN_FLIGHT)
		complete(&entry->compl);

	return 0;
}

static void free_shared_pages(void *buf, size_t len)
{
	unsigned int count = PAGE_ALIGN(len) >> PAGE_SHIFT;

	set_memory_encrypted((unsigned long)buf, count);

	free_pages_exact(buf, PAGE_ALIGN(len));
}

static void *alloc_shared_pages(size_t len)
{
	unsigned int count = PAGE_ALIGN(len) >> PAGE_SHIFT;
	void *addr;
	int ret;

	addr = alloc_pages_exact(len, GFP_KERNEL);
	if (!addr)
		return NULL;

	ret = set_memory_decrypted((unsigned long)addr, count);
	if (ret) {
		free_pages_exact(addr, PAGE_ALIGN(len));
		return NULL;
	}

	return addr;
}

static struct quote_entry *alloc_quote_entry(size_t len)
{
	struct quote_entry *entry = NULL;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->buf = alloc_shared_pages(len);
	if (!entry->buf) {
		kfree(entry);
		return NULL;
	}

	entry->buf_len = PAGE_ALIGN(len);
	init_completion(&entry->compl);
	entry->valid = false;

	return entry;
}

static void free_quote_entry(struct quote_entry *entry)
{
	free_shared_pages(entry->buf, entry->buf_len);
	kfree(entry);
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

static long tdx_get_quote(struct tdx_quote_req __user *ureq)
{
	struct tdx_quote_req req;
	long ret;

	if (copy_from_user(&req, ureq, sizeof(req)))
		return -EFAULT;

	mutex_lock(&quote_lock);

	if (!req.len || req.len > qentry->buf_len) {
		ret = -EINVAL;
		goto quote_failed;
	}

	memset(qentry->buf, 0, qentry->buf_len);
	reinit_completion(&qentry->compl);
	qentry->valid = true;

	if (copy_from_user(qentry->buf, (void __user *)req.buf, req.len)) {
		ret = -EFAULT;
		goto quote_failed;
	}

	/* Submit GetQuote Request using GetQuote hypercall */
	ret = tdx_hcall_get_quote(qentry->buf, qentry->buf_len);
	if (ret) {
		pr_err("GetQuote hypercall failed, status:%lx\n", ret);
		ret = -EIO;
		goto quote_failed;
	}

	/*
	 * Although the GHCI specification does not state explicitly that
	 * the VMM must not wait indefinitely for the Quote request to be
	 * completed, a sane VMM should always notify the guest after a
	 * certain time, regardless of whether the Quote generation is
	 * successful or not.  For now just assume the VMM will do so.
	 */
	wait_for_completion(&qentry->compl);

	if (copy_to_user((void __user *)req.buf, qentry->buf, req.len))
		ret = -EFAULT;

quote_failed:
	qentry->valid = false;
	mutex_unlock(&quote_lock);

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
	case TDX_CMD_GET_QUOTE:
		return tdx_get_quote((struct tdx_quote_req *)arg);
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
	int ret;

	if (!x86_match_cpu(tdx_guest_ids))
		return -ENODEV;

	next_event = acpi_ccel_next_event();
	ret = misc_register(&tdx_misc_dev);
	if (ret)
		return ret;

	qentry = alloc_quote_entry(GET_QUOTE_MAX_SIZE);
	if (!qentry) {
		pr_err("Failed to allocate Quote buffer\n");
		ret = -ENOMEM;
		goto free_misc;
	}

	ret = tdx_register_event_irq_cb(quote_cb_handler, qentry);
	if (ret)
		goto free_quote;

	return 0;

free_quote:
	free_quote_entry(qentry);
free_misc:
	misc_deregister(&tdx_misc_dev);

	return ret;
}
module_init(tdx_guest_init);

static void __exit tdx_guest_exit(void)
{
	acpi_ccel_release();
	tdx_unregister_event_irq_cb(quote_cb_handler, qentry);
	free_quote_entry(qentry);
	misc_deregister(&tdx_misc_dev);
}
module_exit(tdx_guest_exit);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("TDX Guest Driver");
MODULE_LICENSE("GPL");

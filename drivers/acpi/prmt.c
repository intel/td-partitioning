// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Erik Kaneda <erik.kaneda@intel.com>
 * Copyright 2020 Intel Corporation
 *
 * prmt.c
 *
 * Each PRM service is an executable that is run in a restricted environment
 * that is invoked by writing to the PlatformRtMechanism OperationRegion from
 * AML bytecode.
 *
 * init_prmt initializes the Platform Runtime Mechanism (PRM) services by
 * processing data in the PRMT as well as registering an ACPI OperationRegion
 * handler for the PlatformRtMechanism subtype.
 *
 */
#include <linux/kernel.h>
#include <linux/efi.h>
#include <linux/acpi.h>
#include <linux/err.h>
#include <linux/firmware.h>
#include <linux/platform_device.h>
#include <linux/prmt.h>
#include <asm/efi.h>

#pragma pack(1)
struct prm_mmio_addr_range {
	u64 phys_addr;
	u64 virt_addr;
	u32 length;
};

struct prm_mmio_info {
	u64 mmio_count;
	struct prm_mmio_addr_range addr_ranges[];
};

struct prm_buffer {
	u8 prm_status;
	u64 efi_status;
	u8 prm_cmd;
	guid_t handler_guid;
};

struct prm_context_buffer {
	char signature[ACPI_NAMESEG_SIZE];
	u16 revision;
	u16 reserved;
	guid_t identifier;
	u64 static_data_buffer;
	struct prm_mmio_info *mmio_ranges;
};

struct prm_handler_export_descriptor {
	guid_t handler_guid;
	char handler_name[128];
};

struct prm_module_export_descriptor {
	char signature[8];
	u16 revision;
	u16 handler_count;
	guid_t platform_guid;
	guid_t identifier;
	struct prm_handler_export_descriptor handlers[];
};
#pragma pack()

static LIST_HEAD(prm_module_list);

struct prm_handler_info {
	guid_t guid;
	u16 rev;
	efi_status_t (__efiapi *handler_addr)(u64, void *);
	u64 static_data_buffer_addr;
	u64 acpi_param_buffer_addr;

	struct list_head handler_list;
};

struct prm_module_info {
	guid_t guid;
	u16 major_rev;
	u16 minor_rev;
	u16 handler_count;
	struct prm_mmio_info *mmio_info;
	bool updatable;

	struct list_head module_list;
	struct prm_handler_info handlers[];
};

/* fake device for request_firmware */
static struct platform_device *prm_pdev;

enum prm_state {
	PRM_STS_OK		= 0,
	PRM_STS_NFOUND,
	PRM_STS_ERR,
	PRM_STS_MAX
};

static u64 efi_pa_va_lookup(u64 pa)
{
	efi_memory_desc_t *md;
	u64 pa_offset = pa & ~PAGE_MASK;
	u64 page = pa & PAGE_MASK;

	for_each_efi_memory_desc(md) {
		if (md->phys_addr < pa && pa < md->phys_addr + PAGE_SIZE * md->num_pages)
			return pa_offset + md->virt_addr + page - md->phys_addr;
	}

	return 0;
}

#define get_first_handler(a) ((struct acpi_prmt_handler_info *) ((char *) (a) + a->handler_info_offset))
#define get_next_handler(a) ((struct acpi_prmt_handler_info *) (sizeof(struct acpi_prmt_handler_info) + (char *) a))

static int __init
acpi_parse_prmt(union acpi_subtable_headers *header, const unsigned long end)
{
	struct acpi_prmt_module_info *module_info;
	struct acpi_prmt_handler_info *handler_info;
	struct prm_handler_info *th;
	struct prm_module_info *tm;
	u64 *mmio_count;
	u64 cur_handler = 0;
	u32 module_info_size = 0;
	u64 mmio_range_size = 0;
	void *temp_mmio;

	module_info = (struct acpi_prmt_module_info *) header;
	module_info_size = struct_size(tm, handlers, module_info->handler_info_count);
	tm = kmalloc(module_info_size, GFP_KERNEL);
	if (!tm)
		goto parse_prmt_out1;

	guid_copy(&tm->guid, (guid_t *) module_info->module_guid);
	tm->major_rev = module_info->major_rev;
	tm->minor_rev = module_info->minor_rev;
	tm->handler_count = module_info->handler_info_count;
	tm->updatable = true;

	if (module_info->mmio_list_pointer) {
		/*
		 * Each module is associated with a list of addr
		 * ranges that it can use during the service
		 */
		mmio_count = (u64 *) memremap(module_info->mmio_list_pointer, 8, MEMREMAP_WB);
		if (!mmio_count)
			goto parse_prmt_out2;

		mmio_range_size = struct_size(tm->mmio_info, addr_ranges, *mmio_count);
		tm->mmio_info = kmalloc(mmio_range_size, GFP_KERNEL);
		if (!tm->mmio_info)
			goto parse_prmt_out3;

		temp_mmio = memremap(module_info->mmio_list_pointer, mmio_range_size, MEMREMAP_WB);
		if (!temp_mmio)
			goto parse_prmt_out4;
		memmove(tm->mmio_info, temp_mmio, mmio_range_size);
	} else {
		tm->mmio_info = kmalloc(sizeof(*tm->mmio_info), GFP_KERNEL);
		if (!tm->mmio_info)
			goto parse_prmt_out2;

		tm->mmio_info->mmio_count = 0;
	}

	INIT_LIST_HEAD(&tm->module_list);
	list_add(&tm->module_list, &prm_module_list);

	handler_info = get_first_handler(module_info);
	do {
		th = &tm->handlers[cur_handler];

		guid_copy(&th->guid, (guid_t *)handler_info->handler_guid);
		th->handler_addr = (void *)efi_pa_va_lookup(handler_info->handler_address);
		th->static_data_buffer_addr = efi_pa_va_lookup(handler_info->static_data_buffer_address);
		th->acpi_param_buffer_addr = efi_pa_va_lookup(handler_info->acpi_param_buffer_address);
	} while (++cur_handler < tm->handler_count && (handler_info = get_next_handler(handler_info)));

	return 0;

parse_prmt_out4:
	kfree(tm->mmio_info);
parse_prmt_out3:
	memunmap(mmio_count);
parse_prmt_out2:
	kfree(tm);
parse_prmt_out1:
	return -ENOMEM;
}

#define GET_MODULE	0
#define GET_HANDLER	1

static void *find_guid_info(const guid_t *guid, u8 mode)
{
	struct prm_handler_info *cur_handler;
	struct prm_module_info *cur_module;
	int i = 0;

	list_for_each_entry(cur_module, &prm_module_list, module_list) {
		/*
		 * Module GUID match
		 */
		if (mode == GET_MODULE && guid_equal(guid, &cur_module->guid))
			return (void *)cur_module;
		/*
		 * Handler GUID match
		 */
		for (i = 0; i < cur_module->handler_count; ++i) {
			cur_handler = &cur_module->handlers[i];
			if (guid_equal(guid, &cur_handler->guid)) {
				if (mode == GET_MODULE)
					return (void *)cur_module;
				else
					return (void *)cur_handler;
			}
		}
	}

	return NULL;
}

static struct prm_module_info *find_prm_module(const guid_t *guid)
{
	return (struct prm_module_info *)find_guid_info(guid, GET_MODULE);
}

static struct prm_handler_info *find_prm_handler(const guid_t *guid)
{
	return (struct prm_handler_info *) find_guid_info(guid, GET_HANDLER);
}

/* In-coming PRM commands */

#define PRM_CMD_RUN_SERVICE		0
#define PRM_CMD_START_TRANSACTION	1
#define PRM_CMD_END_TRANSACTION		2

/* statuses that can be passed back to ASL */

#define PRM_HANDLER_SUCCESS 		0
#define PRM_HANDLER_ERROR 		1
#define INVALID_PRM_COMMAND 		2
#define PRM_HANDLER_GUID_NOT_FOUND 	3
#define UPDATE_LOCK_ALREADY_HELD 	4
#define UPDATE_UNLOCK_WITHOUT_LOCK 	5

/*
 * This is the PlatformRtMechanism opregion space handler.
 * @function: indicates the read/write. In fact as the PlatformRtMechanism
 * message is driven by command, only write is meaningful.
 *
 * @addr   : not used
 * @bits   : not used.
 * @value  : it is an in/out parameter. It points to the PRM message buffer.
 * @handler_context: not used
 */
static acpi_status acpi_platformrt_space_handler(u32 function,
						 acpi_physical_address addr,
						 u32 bits, acpi_integer *value,
						 void *handler_context,
						 void *region_context)
{
	struct prm_buffer *buffer = ACPI_CAST_PTR(struct prm_buffer, value);
	struct prm_handler_info *handler;
	struct prm_module_info *module;
	efi_status_t status;
	struct prm_context_buffer context;

	if (!efi_enabled(EFI_RUNTIME_SERVICES)) {
		pr_err_ratelimited("PRM: EFI runtime services no longer available\n");
		return AE_NO_HANDLER;
	}

	/*
	 * The returned acpi_status will always be AE_OK. Error values will be
	 * saved in the first byte of the PRM message buffer to be used by ASL.
	 */
	switch (buffer->prm_cmd) {
	case PRM_CMD_RUN_SERVICE:

		handler = find_prm_handler(&buffer->handler_guid);
		module = find_prm_module(&buffer->handler_guid);
		if (!handler || !module)
			goto invalid_guid;

		ACPI_COPY_NAMESEG(context.signature, "PRMC");
		context.revision = 0x0;
		context.reserved = 0x0;
		context.identifier = handler->guid;
		context.static_data_buffer = handler->static_data_buffer_addr;
		context.mmio_ranges = module->mmio_info;

		status = efi_call_acpi_prm_handler(handler->handler_addr,
						   handler->acpi_param_buffer_addr,
						   &context);
		if (status == EFI_SUCCESS) {
			buffer->prm_status = PRM_HANDLER_SUCCESS;
		} else {
			buffer->prm_status = PRM_HANDLER_ERROR;
			buffer->efi_status = status;
		}
		break;

	case PRM_CMD_START_TRANSACTION:

		module = find_prm_module(&buffer->handler_guid);
		if (!module)
			goto invalid_guid;

		if (module->updatable)
			module->updatable = false;
		else
			buffer->prm_status = UPDATE_LOCK_ALREADY_HELD;
		break;

	case PRM_CMD_END_TRANSACTION:

		module = find_prm_module(&buffer->handler_guid);
		if (!module)
			goto invalid_guid;

		if (module->updatable)
			buffer->prm_status = UPDATE_UNLOCK_WITHOUT_LOCK;
		else
			module->updatable = true;
		break;

	default:

		buffer->prm_status = INVALID_PRM_COMMAND;
		break;
	}

	return AE_OK;

invalid_guid:
	buffer->prm_status = PRM_HANDLER_GUID_NOT_FOUND;
	return AE_OK;
}

static int prm_dump_image_info(const u8 *data, int size)
{
	struct prm_module_export_descriptor *med;
	struct prm_handler_export_descriptor *hed;
	unsigned char *signature = "PRM_MEDT";
	int i, med_offset, sig_size = 8;

	/*
	 * Scan "PRM_MEDT" string for module export descriptor structure.
	 */
	for (i = 0; i <= size - sig_size; i++) {
		if (memcmp(data + i, signature, sig_size) == 0) {
			med_offset = i;
			pr_info("PRM: module export descriptor offset = 0x%x\n",
				i);
			break;
		}
	}

	if (i > size - sig_size) {
		pr_err("PRM: no module export descriptor structure found\n");
		return PRM_STS_NFOUND;
	}

	med = (struct prm_module_export_descriptor *)(data + med_offset);
	pr_info("Platform guid    : %pUl\n", &med->platform_guid);
	pr_info("Module signature : %s\n", med->signature);
	pr_info("Module revision  : %d\n", med->revision);
	pr_info("Module identifier: %pUl\n", &med->identifier);
	pr_info("Handler count    : %d\n", med->handler_count);

	hed = med->handlers;
	for (i = 0; i < med->handler_count; i++) {
		pr_info(" handler guid    : %pUl\n", &hed->handler_guid);
		pr_info(" handler name    : %s\n", hed->handler_name);
		hed++;
	}

	return PRM_STS_OK;
}

static int prm_load_image(struct device *dev)
{
	const struct firmware *firmware;
	char name[16];
	int ret;

	sprintf(name, "prm.efi");

	if (request_firmware_direct(&firmware, name, dev)) {
		pr_err("PRM: image %s load failed\n", name);
		return PRM_STS_NFOUND;
	}

	ret = prm_dump_image_info(firmware->data, firmware->size);
	if (ret != PRM_STS_OK) {
		pr_err("PRM: dump raw image error\n");
		goto load_out;
	}

load_out:
	release_firmware(firmware);
	return ret;
}

static ssize_t prm_update_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct prm_handler_info *cur_handler;
	struct prm_module_info *cur_module;
	char *s = buf;
	int i = 0;

	list_for_each_entry(cur_module, &prm_module_list, module_list) {
		s += sprintf(s, "Module GUID  : %pUl\n", &cur_module->guid);
		s += sprintf(s, "Major Rev    : %d\n", cur_module->major_rev);
		s += sprintf(s, "Minor Rev    : %d\n", cur_module->minor_rev);
		s += sprintf(s, "Handler Count: %d\n", cur_module->handler_count);
		for (i = 0; i < cur_module->handler_count; ++i) {
			cur_handler = &cur_module->handlers[i];
			s += sprintf(s, " Handler GUID: %pUl\n", &cur_handler->guid);
			s += sprintf(s, "          Rev: %d\n", cur_handler->rev);
		}
		s += sprintf(s, "\n");
	}

	return (s - buf);
}

static ssize_t prm_update_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t size)
{
	unsigned long val;
	ssize_t ret;

	ret = kstrtoul(buf, 0, &val);
	if (ret)
		return ret;
	if (val != 1)
		return size;

	pr_info("PRM: runtime update\n");
	ret = prm_load_image(&prm_pdev->dev);
	if (ret == PRM_STS_OK)
		ret = size;

	return ret;
}

static const struct kobj_attribute prm_update_attr =
__ATTR(prm_update, 0644, prm_update_show, prm_update_store);

void __init init_prmt(void)
{
	struct acpi_table_header *tbl;
	acpi_status status;
	int mc;

	status = acpi_get_table(ACPI_SIG_PRMT, 0, &tbl);
	if (ACPI_FAILURE(status))
		return;

	mc = acpi_table_parse_entries(ACPI_SIG_PRMT, sizeof(struct acpi_table_prmt) +
					  sizeof (struct acpi_table_prmt_header),
					  0, acpi_parse_prmt, 0);
	acpi_put_table(tbl);
	/*
	 * Return immediately if PRMT table is not present or no PRM module found.
	 */
	if (mc <= 0)
		return;

	pr_info("PRM: found %u modules\n", mc);

	if (!efi_enabled(EFI_RUNTIME_SERVICES)) {
		pr_err("PRM: EFI runtime services unavailable\n");
		return;
	}

	prm_pdev = platform_device_register_simple("prm", -1, NULL, 0);
	if (IS_ERR(prm_pdev))
		return;

	status = acpi_install_address_space_handler(ACPI_ROOT_OBJECT,
						    ACPI_ADR_SPACE_PLATFORM_RT,
						    &acpi_platformrt_space_handler,
						    NULL, NULL);
	if (ACPI_FAILURE(status))
		pr_alert("PRM: OperationRegion handler could not be installed\n");

	if (sysfs_create_file(acpi_kobj, &prm_update_attr.attr)) {
		pr_err("PRM: failed to create prm sysfs entry\n");
		platform_device_unregister(prm_pdev);
	}
}

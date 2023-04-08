// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2023 Intel Corporation.
 *
 * PCIe TDISP Driver
 */

#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/kvm_host.h>

static int pci_tdi_bind_kvm(struct pci_tdi *tdi, struct kvm *kvm)
{
	int (*fn)(struct kvm *kvm, struct pci_tdi *tdi);
	int ret;

	fn = symbol_get(kvm_bind_tdi);
	if (!fn)
		return -ENOENT;

	ret = fn(kvm, tdi);

	symbol_put(kvm_bind_tdi);

	if (!ret)
		tdi->kvm = kvm;

	return ret;
}

#if 0
static void pci_tdi_unbind_kvm(struct pci_tdi *tdi)
{
	void (*fn)(struct kvm *kvm, struct pci_tdi *tdi);

	if (!tdi->kvm)
		return;

	fn = symbol_get(kvm_unbind_tdi);
	if (!fn)
		return;

	fn(tdi->kvm, tdi);

	symbol_put(kvm_bind_tdi);
}
#endif

#define PCI_DOE_PROTOCOL_SPDM		1
#define PCI_DOE_PROTOCOL_SECURED_SPDM	2

static int pci_tdisp_create_doe_mb(struct pci_tdisp_dev *tdev)
{
	struct pci_dev *pdev = tdev->pdev;
	struct device *dev = &pdev->dev;

	tdev->doe_mb = pci_find_doe_mailbox(pdev, PCI_VENDOR_ID_PCI_SIG,
					    PCI_DOE_PROTOCOL_SPDM);
	if (!tdev->doe_mb) {
		dev_err(dev, "doe doesn't support SPDM\n");
		return -ENODEV;
	}

	tdev->sec_doe_mb = pci_find_doe_mailbox(pdev, PCI_VENDOR_ID_PCI_SIG,
						PCI_DOE_PROTOCOL_SECURED_SPDM);
	if (!tdev->sec_doe_mb) {
		dev_err(dev, "doe doesn't support SECURE SPDM\n");
		return -ENODEV;
	}

	/* For now, the 2 doe mb should be the same */
	dev_info(dev, "%s: doe_mb=0x%p, sec_doe_mb=0x%p\n", __func__,
		 tdev->doe_mb, tdev->sec_doe_mb);

	return 0;
}

static int pci_tdisp_create_spdm(struct pci_tdisp_dev *tdev)
{
	struct device *dev = &tdev->pdev->dev;
	struct spdm_session *session;
	struct spdm *spdm;

	spdm = spdm_create(dev, dev_name(dev), SPDM_FLAGS_TEE,
			   tdev->parm.spdm_parm, tdev->doe_mb);
	if (!spdm)
		return -ENOMEM;

	session = spdm_session_create(spdm, tdev->parm.session_parm);
	if (!session) {
		spdm_remove(spdm);
		return -ENOMEM;
	}

	tdev->spdm = spdm;
	tdev->session = session;
	return 0;
}

static void pci_tdisp_remove_spdm(struct pci_tdisp_dev *tdev)
{
	struct spdm_session *session = tdev->session;
	struct spdm *spdm = tdev->spdm;

	tdev->spdm = NULL;
	tdev->session = NULL;
	spdm_session_remove(session);
	spdm_remove(spdm);
}

static u32 pdev_to_func_id(struct pci_dev *pdev)
{
	u32 func_id;

	func_id = pci_domain_nr(pdev->bus) << 16 |
		  PCI_DEVID(pdev->bus->number, pdev->devfn);

	if (pci_domain_nr(pdev->bus))
		func_id |= TDISP_INTF_ID_SEGMENT_VALID;

	return func_id;
}

void pci_tdi_uinit_and_free(struct pci_tdi *tdi)
{
	struct pci_tdisp_dev *tdev = tdi->parent;
	struct pci_dev *pdev = tdi->pdev;

	if (pdev)
		pdev->tdi = NULL;

	if (tdev)
		tdev->tdi_num--;

	kfree(tdi->identities);
	kfree(tdi->report);
	kfree(tdi);
}
EXPORT_SYMBOL_GPL(pci_tdi_uinit_and_free);

struct pci_tdi *pci_tdi_alloc_and_init(struct pci_dev *pdev,
				       struct pci_tdi_parm parm)
{
	struct pci_tdisp_dev *tdev = pdev->tdisp_dev;
	struct pci_tdi *tdi;

	/*
	 * FIXME: check tdi_parm for type, but assume PFVF case now
	 */
	if (pdev->tdi)
		return ERR_PTR(-EEXIST);

	tdi = kzalloc(sizeof(*tdi), GFP_KERNEL);
	if (!tdi)
		return ERR_PTR(-ENOMEM);

	tdi->state = TDI_STATE_CONFIG_UNLOCKED;
	tdi->parent = tdev;
	tdi->pdev = pdev;
	tdi->parm = parm;
	if (tdev) {
		/*
		 * in TVM, no tdev (DSM), get below info using hypercall.
		 */
		tdi->stream_id = tdev->stm->stream_id;
		tdi->cap = tdev->cap;
		tdi->version = tdev->version;
		tdi->intf_id.func_id = pdev_to_func_id(pdev);
		tdev->tdi_num++;
	}
	pdev->tdi = tdi;
	return tdi;
}
EXPORT_SYMBOL_GPL(pci_tdi_alloc_and_init);

static int pci_tdisp_dev_init(struct pci_dev *pdev,
			      struct pci_tdisp_dev_parm parm)
{
	struct pci_tdisp_dev *tdev;
	struct pci_ide_stream *stm;
	int ret;

	/*
	 * Steps to initialize a TDI for attachment to a TEE
	 *
	 * 1. Generic initialization for TEE-IO device which hosts TDIs
	 *
	 *  1.1 Check if target device support TDISP or not.
	 *  1.2 Allocate and initialize per TDISP device data structure.
	 *  1.3 Initialize SPDM device identities, e.g. certificates.
	 *  1.4 Initialize SPDM session.
	 *  1.5 Initialize TDISP protocol, e.g. version and capabilities.
	 *  1.6 Setup selective IDE stream.
	 */

	/*
	 * 1.1 Check if target device support TDISP or not.
	 */
	if (!pci_tdisp_supported(pdev))
		return -ENODEV;

	/*
	 * 1.2 Allocate and initialize per TDISP device data structure.
	 */
	tdev = kzalloc(sizeof(*tdev), GFP_KERNEL);
	if (!tdev)
		return -ENOMEM;

	tdev->pdev = pdev;
	tdev->parm = parm;

	/*
	 * 1.3 Initialize DOE mailbox per TDISP requirement
	 */
	ret = pci_tdisp_create_doe_mb(tdev);
	if (ret)
		goto exit_free_tdev;

	/*
	 * 1.4 Initialize SPDM device identities, e.g. certificates
	 * 1.5 Initialize SPDM session.
	 * 1.6 Initialize TDISP protocol, e.g. version and capabilities.
	 *
	 * Call arch-specific initialization function, if anything is not
	 * initialized in arch-specific function, then goes to common ones.
	 */
	ret = pci_tdisp_create_spdm(tdev);
	if (ret)
		goto exit_free_tdev;

	ret = pci_arch_tdisp_dev_init(tdev);
	if (ret)
		goto exit_remove_spdm;

	/*
	 * 1.7 Setup selective IDE stream.
	 *
	 * Per TDISP spec, it requires to use the same SPDM session for
	 * TDISP protocol and IDE_KM, and also must use default stream
	 * for TDISP.
	 *
	 * FIXME: how to handle multiple VF cases
	 */
	stm = pci_ide_stream_setup(pdev, tdev->session, PCI_IDE_FLAG_TEE);
	if (IS_ERR(stm)) {
		ret = PTR_ERR(stm);
		goto exit_arch_uinit;
	}

	tdev->stm = stm;

	pdev->tdisp_dev = tdev;
	return 0;

exit_arch_uinit:
	pci_arch_tdisp_dev_uinit(tdev);
exit_remove_spdm:
	pci_tdisp_remove_spdm(tdev);
exit_free_tdev:
	kfree(tdev);
	return ret;
}

static void pci_tdisp_dev_uinit(struct pci_dev *pdev)
{
	struct pci_tdisp_dev *tdev = pdev->tdisp_dev;

	/*
	 * 2. Generic un-initialization for TDISP device which hosts TDIs
	 *
	 *  2.1 Remove IDE stream.
	 *  2.2 End SPDM session.
	 *  2.3 Cleanup per TDISP device data structure.
	 */

	if (!tdev || tdev->tdi_num)
		return;

	pdev->tdisp_dev = NULL;
	pci_ide_stream_remove(tdev->stm);
	pci_arch_tdisp_dev_uinit(tdev);
	pci_tdisp_remove_spdm(tdev);
	kfree(tdev);
}

/*
 * pci_tdi_init - initialize a TDI per given parameters
 *
 * @pdev: pci device to be managed as TDI
 * @parm: parameters used to describe a TDI
 *
 * This function creates and initializes a TDI to be assigned to a given TVM.
 */
struct pci_tdi *pci_tdi_init(struct pci_dev *pdev, struct pci_tdi_parm parm)
{
	struct pci_tdi *tdi;
	int ret;

	/*
	 * 1. Generic initialization for TEE-IO device which hosts TDIs
	 */
	ret = pci_tdisp_dev_init(pdev, parm.dparm);
	if (ret)
		return ERR_PTR(ret);

	/*
	 * 2. Per TDI initialization
	 *
	 * 2.1 pci_tdi_alloc_and_init()
	 *      Initialize per TDI data structure.
	 * 2.2 pci_tdi_bind_kvm()
	 *      Bind TDI with TVM.
	 *      Lock TDI via TDISP protocol.
	 */
	tdi = pci_tdi_alloc_and_init(pdev, parm);
	if (IS_ERR(tdi)) {
		ret = PTR_ERR(tdi);
		goto exit_tdisp_uinit;
	}

	ret = pci_tdi_bind_kvm(tdi, parm.kvm);
	if (ret)
		goto exit_uinit_free;

	return tdi;

exit_uinit_free:
	pci_tdi_uinit_and_free(tdi);
exit_tdisp_uinit:
	pci_tdisp_dev_uinit(pdev);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(pci_tdi_init);

/*
 * pci_tdi_uinit - uninitialize a TDI
 *
 * @tdi: TDI to be uninitialized
 * This function uninitializes a TDI which has already been assigned to a TVM.
 */
void pci_tdi_uinit(struct pci_tdi *tdi)
{
	struct pci_dev *pdev = NULL;

	if (tdi->parent)
		pdev = tdi->parent->pdev;

	/*
	 * 1. per TDI un-initialization
	 *
	 *  1.1 Stop TDI.
	 *  1.2 Unbind TDI from TVM.
	 *  1.3 Un-initialize fro TDI data structure.
	 */
	/* FIXME: skip tdi unbind function for now */
#if 0
	pci_tdi_unbind_kvm(tdi);
#endif
	pci_tdi_uinit_and_free(tdi);

	/*
	 * 2. Generic un-initialization for TDISP device which hosts TDIs
	 */
	pci_tdisp_dev_uinit(pdev);
}
EXPORT_SYMBOL_GPL(pci_tdi_uinit);

int pci_tdi_msg_exchange_prepare(struct pci_tdi *tdi)
{
	struct pci_tdisp_dev *tdev = tdi->parent;
	struct spdm_session *session = tdev->session;

	return spdm_session_msg_exchange_prepare(session);
}
EXPORT_SYMBOL_GPL(pci_tdi_msg_exchange_prepare);

int pci_tdi_msg_exchange(struct pci_tdi *tdi, struct spdm_message *msg)
{
	struct pci_tdisp_dev *tdev = tdi->parent;
	struct spdm_session *session = tdev->session;

	return spdm_session_msg_exchange(session, msg);
}
EXPORT_SYMBOL_GPL(pci_tdi_msg_exchange);

void pci_tdi_msg_exchange_complete(struct pci_tdi *tdi)
{
	struct pci_tdisp_dev *tdev = tdi->parent;
	struct spdm_session *session = tdev->session;

	spdm_session_msg_exchange_complete(session);
}
EXPORT_SYMBOL_GPL(pci_tdi_msg_exchange_complete);

/* Allow request generation for TDI, no matter it's VMM or TVM */
int pci_tdi_gen_req(struct pci_tdi *tdi, unsigned long req_va, size_t req_sz,
		    struct tdisp_request_parm *parm, unsigned int *actual_sz)
{
	struct tdisp_request *req = (struct tdisp_request *)req_va;
	struct device *dev = &tdi->pdev->dev;

	memset((void *)req_va, 0, req_sz);

	/* Initialize the common TDISP header */
	req->header.version = tdi->version;
	req->header.message = parm->message;
	req->header.func_id = tdi->intf_id.func_id;

	dev_dbg(dev, "%s request message code = 0x%x\n", __func__, parm->message);

	switch (parm->message) {
	case TDISP_LOCK_INTF_REQ:
		req->lock_intf.flags = 0;
		req->lock_intf.stream_id = tdi->stream_id;
		req->lock_intf.mmio_offset = tdi->mmio_offset;
		*actual_sz = TDISP_HEADER_SIZE + 20;
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, (void *)req_va, *actual_sz);
		return 0;
	case TDISP_GET_DEVIF_REPORT:
		req->get_devif_report.offset = parm->get_devif_report.offset;
		req->get_devif_report.length = parm->get_devif_report.length;
		*actual_sz = TDISP_HEADER_SIZE + 4;
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, (void *)req_va, *actual_sz);
		return 0;
	case TDISP_GET_DEVIF_STATE:
		*actual_sz = TDISP_HEADER_SIZE;
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, (void *)req_va, *actual_sz);
		return 0;
	case TDISP_START_INTF_REQ:
		req->start_intf.nonce[0] = tdi->nonce[0];
		req->start_intf.nonce[1] = tdi->nonce[1];
		req->start_intf.nonce[2] = tdi->nonce[2];
		req->start_intf.nonce[3] = tdi->nonce[3];
		*actual_sz = TDISP_HEADER_SIZE + 32;
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, (void *)req_va, *actual_sz);
		return 0;
	case TDISP_STOP_INTF_REQ:
		*actual_sz = TDISP_HEADER_SIZE;
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, (void *)req_va, *actual_sz);
		return 0;
	}

	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(pci_tdi_gen_req);

int pci_tdi_process_rsp(struct pci_tdi *tdi, unsigned long rsp_va, size_t rsp_sz,
			struct tdisp_response_parm *parm)
{
	struct tdisp_response *rsp = (struct tdisp_response *)rsp_va;
	struct device *dev = &tdi->pdev->dev;

	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, (void *)rsp_va, min_t(size_t, rsp_sz, 4096));

	/* Check the response TDISP header */
	if (rsp->header.version != tdi->version ||
	    rsp->header.message != parm->message ||
	    rsp->header.func_id != tdi->intf_id.func_id ||
	    rsp->header.rsvd0 != 0 || rsp->header.rsvd1 != 0) {
		dev_err(dev, "fail to process rsp hdr, version %x message %x func_id %x\n",
			tdi->version, parm->message, tdi->intf_id.func_id);
		return -EINVAL;
	}

	dev_dbg(dev, "%s response message code = 0x%x\n", __func__, parm->message);

	switch (rsp->header.message) {
	case TDISP_LOCK_INTF_RESP:
		tdi->nonce[0] = rsp->lock_intf.nonce[0];
		tdi->nonce[1] = rsp->lock_intf.nonce[1];
		tdi->nonce[2] = rsp->lock_intf.nonce[2];
		tdi->nonce[3] = rsp->lock_intf.nonce[3];
		return 0;
	case TDISP_DEVIF_REPORT:
		/*
		 * First GET_DEVIF_REPORT must set offset as 0, so calculate
		 * total size and allocate buffer for the first response.
		 */
		if (!tdi->report) {
			tdi->report_len = rsp->devif_report.portion_len +
					  rsp->devif_report.remainder_len;
			tdi->report_offset = 0;
			tdi->report = kzalloc(tdi->report_len, GFP_KERNEL);
			if (!tdi->report)
				return -ENOMEM;
		}

		memcpy(tdi->report + tdi->report_offset,
		       &rsp->devif_report.payload,
		       rsp->devif_report.portion_len);

		tdi->report_offset += rsp->devif_report.portion_len;
		return 0;
	case TDISP_DEVIF_STATE:
		tdi->state = rsp->devif_state.state;
		return 0;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(pci_tdi_process_rsp);

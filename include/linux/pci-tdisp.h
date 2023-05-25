/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2023 Intel Corporation.
 *
 * PCIe TDISP Driver
 */

#ifndef LINUX_PCI_TDISP_H
#define LINUX_PCI_TDISP_H

#include <linux/pci.h>
#include <linux/spdm_mgr.h>
#include <uapi/linux/pci_tdisp.h>

/* MAX TDISP Payload, see FAS 1.2.4 */
#define TDX_MAX_TDISP_PAYLOAD				(PAGE_SIZE - 43)
#define TDX_MAX_TDISP_DEVIF_REPORT_LENGTH		(TDX_MAX_TDISP_PAYLOAD - 21)

struct kvm;

struct pci_tdisp_dev_parm {
	struct spdm_parm spdm_parm;
	struct spdm_session_parm session_parm;
};

struct pci_tdisp_dev_cap {
	u32 dsm_caps;
	u64 req_msgs_supported_l;
	u64 req_msgs_supported_h;
	u16 lock_flags_supported;
	u8  dev_addr_width;
	u8  num_req_this;
	u8  num_req_all;
};

struct pci_tdi_intf_id {
	u32 func_id;
#define TDISP_INTF_ID_SEGMENT_VALID	(0x1 << 24)
	u64 rsvd;
};

struct pci_tdisp_dev {
	struct pci_dev *pdev;
	struct pci_tdisp_dev_parm parm;

	unsigned int flags;
	struct pci_doe_mb *doe_mb;
	struct pci_doe_mb *sec_doe_mb;
	struct pci_ide_stream *stm;

	struct spdm *spdm;
	struct spdm_session *session;

	void *priv;
	unsigned int tdi_num;

	u8  version;
	struct pci_tdisp_dev_cap cap;
};

struct pci_tdi_parm {
	struct kvm *kvm;
	struct pci_tdisp_dev_parm dparm;
};

#define MAX_TDI_MMIO_RANGE	32

struct pci_tdi_mmio {
	u64 haddr;
	u32 pages;
	u16 attr;
	u16 id;
	u64 gpa;
	bool is_tee;
};

struct pci_tdi {
	struct pci_tdisp_dev *parent;
	struct pci_tdi_parm parm;
	unsigned int state;

	struct kvm *kvm;

	unsigned int flags;
	struct pci_dev *pdev;
	void *priv;

	u8  version;
	struct pci_tdisp_dev_cap cap;
	struct pci_tdi_intf_id intf_id;
	u8  stream_id;
	u64 mmio_offset;
	u64 nonce[4];

	size_t report_len;
	size_t report_offset;
	void *report;
	u16 interface_info;
	u16 msix_ctrl;
	u16 lnr_ctrl;
	u32 tph_ctrl;
	u32 mmio_range_num;
	struct pci_tdi_mmio mmio[MAX_TDI_MMIO_RANGE];

	size_t identities_len;
	void *identities;
};

static inline const char *tdisp_message_to_string(u8 message)
{
	switch (message) {
	case TDISP_LOCK_INTF_REQ:
		return "TDISP_LOCK_INTF_REQ";
	case TDISP_STOP_INTF_REQ:
		return "TDISP_STOP_INTF_REQ";
	case TDISP_GET_DEVIF_REPORT:
		return "TDISP_GET_DEVIF_REPORT";
	case TDISP_START_INTF_REQ:
		return "TDISP_START_INTF_REQ";
	default:
		return "unknown";
	}
}

static inline bool pci_tdisp_supported(struct pci_dev *pdev)
{
#if 0
	u32 cap;

	pcie_capability_read_dword(pdev, PCI_EXP_DEVCAP, &cap);

	return !!(cap & PCI_EXP_DEVCAP_TEE_IO);
#endif
	return true;
}

static inline bool is_pci_tdi_mmio_tee(struct pci_tdi_mmio *mmio)
{
	return !(mmio->attr & DEVIF_RP_MMIO_ATTR_NON_TEE);
}

#pragma pack(1)
struct tdisp_header {
	u8  version;
	u8  message;
	u16 rsvd0;
	u32 func_id;
	u64 rsvd1;
};

#define TDISP_HEADER_SIZE	16

struct tdisp_request {
	struct tdisp_header header;
	union {
		struct {
			u16 flags;
			u8  stream_id;
			u8  rsvd;
			u64 mmio_offset;
			u64 bind_p2p_addr_mask;
		} lock_intf;
		struct {
			u16 offset;
			u16 length;
		} get_devif_report;
		struct {
			u64 nonce[4];
		} start_intf;
	};
};

struct tdisp_response {
	struct tdisp_header header;
	union {
		struct {
			u64 nonce[4];
		} lock_intf;
		struct {
			u16 portion_len;
			u16 remainder_len;
			u8  payload[0];
		} devif_report;
		struct {
			u8  state;
		} devif_state;
	};
};

#pragma pack()

struct tdisp_request_parm {
	u8 message;
	union {
		struct {
			u16 lock_flags;
		} lock_intf;
		struct {
			u16 offset;
			u16 length;
		} get_devif_report;
	};
};

struct tdisp_response_parm {
	u8 message;
};

static inline u8 tdisp_req_to_rsp_message(u8 message)
{
	return message & 0x7f;
}

//FIXME: Add arch tdisp dev init implementation
#ifdef CONFIG_PCI_TDISP
struct pci_tdi *pci_tdi_init(struct pci_dev *pdev, struct pci_tdi_parm parm);
void pci_tdi_uinit(struct pci_tdi *tdi);
int pci_tdi_msg_exchange_prepare(struct pci_tdi *tdi);
int pci_tdi_msg_exchange(struct pci_tdi *tdi, struct spdm_message *msg);
void pci_tdi_msg_exchange_complete(struct pci_tdi *tdi);
int pci_tdi_gen_req(struct pci_tdi *tdi, unsigned long req_va, size_t req_sz,
		    struct tdisp_request_parm *parm, unsigned int *actual_sz);
int pci_tdi_process_rsp(struct pci_tdi *tdi, unsigned long rsp_va, size_t rsp_sz,
			struct tdisp_response_parm *parm);
struct pci_tdi *pci_tdi_alloc_and_init(struct pci_dev *pdev,
				       struct pci_tdi_parm parm);
void pci_tdi_uinit_and_free(struct pci_tdi *tdi);
int pci_arch_tdisp_dev_init(struct pci_tdisp_dev *tdev);
void pci_arch_tdisp_dev_uinit(struct pci_tdisp_dev *tdev);
int pci_tdi_mmap_resource_range(struct pci_dev *pdev, int bar,
				struct vm_area_struct *vma);
#else
static inline struct pci_tdi *pci_tdi_init(struct pci_dev *pdev,
					   struct pci_tdi_parm parm)
					   { return NULL; }
static inline void pci_tdi_uinit(struct pci_tdi *tdi) {}
static inline int pci_tdi_msg_exchange_prepare(struct pci_tdi *tdi)
					       { return -ENOTTY; }
static inline int pci_tdi_msg_exchange(struct pci_tdi *tdi,
				       struct spdm_message *msg)
				       { return -ENOTTY; }
static inline void pci_tdi_msg_exchange_complete(struct pci_tdi *tdi) {}
static inline int pci_tdi_gen_req(struct pci_tdi *tdi, unsigned long req_va,
	size_t req_sz, struct tdisp_request_parm *parm, unsigned int *actual_sz)
	{ return -ENOTSUPP; }
static inline int pci_tdi_process_rsp(struct pci_tdi *tdi, unsigned long rsp_va,
	size_t rsp_sz, struct tdisp_response_parm *parm) { return -ENOTSUPP; }
static inline struct pci_tdi *pci_tdi_alloc_and_init(struct pci_dev *pdev, struct pci_tdi_parm parm)
				       { return NULL; }
static inline void pci_tdi_uinit_and_free(struct pci_tdi *tdi) {};
static inline int pci_arch_tdisp_dev_init(struct pci_tdisp_dev *tdev) { return -ENOTTY; }
static inline void pci_arch_tdisp_dev_uinit(struct pci_tdisp_dev *tdev) { return; }
static inline int pci_tdi_mmap_resource_range(struct pci_dev *pdev, int bar,
					      struct vm_area_struct *vma)
					      {return -ENOTSUPP;}
#endif
#endif /* LINUX_PCI_TDISP_H */

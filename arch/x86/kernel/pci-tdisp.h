/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2023 Intel Corporation. */
#ifndef _ARCH_X86_KERNEL_PCI_TDISP_H
#define _ARCH_X86_KERNEL_PCI_TDISP_H

#include <linux/miscdevice.h>
#include <uapi/linux/tdisp_mgr.h>
#include <asm/tdx.h>
#include <asm/tdxio.h>

#define TDISP_MGR_MAXNAMELEN 32

struct tdisp_mgr {
	struct pci_tdisp_dev *tdev;
	unsigned char name[TDISP_MGR_MAXNAMELEN];
	int id;

	struct miscdevice miscdev;
	struct eventfd_ctx *efd_ctx;

	spinlock_t lock;
	struct list_head pending_reqs;
	int req_timeout;
#define TDISP_MGR_REQ_DEFAULT_TIMEOUT	60000 /* 60s */

	struct tmgr_dev_info dev_info;
	unsigned long session_page_pa;
	unsigned int spdm_owner;
#define TMGR_SPDM_OWNER_USER	1
#define TMGR_SPDM_OWNER_KERNEL	2

	struct delayed_work sess_hbeat_dwork;

	/*
	 * iommu_id
	 * u8 hiop_id:4;
	 * u8 socket_id:4;
	 * u8 rsvd;
	 */
	u16 iommu_id;
	u16 session_idx;
#define SESSION_PER_IOMMU		256

	struct tpa_dev_info_data data;
};

struct tdisp_mgr_request {
	struct tmgr_request treq;
	int state;
#define TDISP_MGR_REQ_STATE_INIT	0x0 /* Init, but not queued */
#define TDISP_MGR_REQ_STATE_PENDING	0x1 /* Waiting agent to pick */
#define TDISP_MGR_REQ_STATE_HANDLING	0x2 /* Agent is working on the request */
#define TDISP_MGR_REQ_STATE_COMPLETED	0x3 /* Agent completed the request */
#define TDISP_MGR_REQ_STATE_FINISHED	0x4 /* TDISP manager handled the request */
	unsigned int session_id;

	struct kref kref;
	struct list_head node;
	struct completion complete;
	struct tdisp_mgr *tmgr;
};

#endif /* _ARCH_X86_KERNEL_PCI_TDISP_H */

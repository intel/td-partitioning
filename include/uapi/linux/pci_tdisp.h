/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright(c) 2023 Intel Corporation.
 *
 * PCIe TDISP Spec Definitions
 */
#ifndef _UAPILINUX_PCI_TDISP_H
#define _UAPILINUX_PCI_TDISP_H

/* PCIe TEE Device Interface Security Protocol (TDISP) Message Code */
#define TDISP_GET_VERSION		0x81
#define TDISP_VERSION			0x01
#define TDISP_GET_CAPABILITY		0x82
#define TDISP_CAPABILITY		0x02
#define TDISP_LOCK_INTF_REQ		0x83
#define TDISP_LOCK_INTF_RESP		0x03
#define TDISP_GET_DEVIF_REPORT		0x84
#define TDISP_DEVIF_REPORT		0x04
#define TDISP_GET_DEVIF_STATE		0x85
#define TDISP_DEVIF_STATE		0x05
#define TDISP_START_INTF_REQ		0x86
#define TDISP_START_INTF_RESP		0x06
#define TDISP_STOP_INTF_REQ		0x87
#define TDISP_STOP_INTF_RESP		0x07
#define TDISP_BIND_P2P_STREAM_REQ	0x88
#define TDISP_BIND_P2P_STREAM_RESP	0x08
#define TDISP_UNBIND_P2P_STREAM_REQ	0x89
#define TDISP_UNBIND_P2P_STREAM_RESP	0x09
#define TDISP_SET_MMIO_ATTR_REQ		0x8a
#define TDISP_SET_MMIO_ATTR_RESP	0x0a
#define TDISP_VDM_REQ			0x8b
#define TDISP_VDM_RESP			0x0b
#define TDISP_ERROR			0x7f

/* TEE Device Interface (TDI) state */
#define TDI_STATE_CONFIG_UNLOCKED	0x0
#define TDI_STATE_CONFIG_LOCKED		0x1
#define TDI_STATE_RUN			0x2
#define TDI_STATE_ERROR			0x3

/* TEE Device Interface Lock Flags */
#define TDI_LOCK_FLAGS_NO_FW_UPDATE	0x1

/*
 * Device Interface Report - content
 * The Device Interface Report header is taken into account, but the TDISP
 * header is not.
 */
#define DEVIF_RP_INTF_INFO		0
#define   TDI_INTF_INFO_NO_FW_UPDATE	0x1
#define   TDI_INTF_INFO_DMA_NO_PASID	0x2
#define   TDI_INTF_INFO_DMA_PASID	0x4
#define   TDI_INTF_INFO_ATS		0x8
#define   TDI_INTF_INFO_PRS		0x10
#define DEVIF_RP_MSIX_CTRL		4
#define DEVIF_RP_LNR_CTRL		6
#define DEVIF_RP_TPH_CTRL		8
#define DEVIF_RP_MMIO_NUM		12
#define DEVIF_RP_MMIO_ADDR_LO(n)	(16 + (n) * 16)
#define DEVIF_RP_MMIO_ADDR_HI(n)	(20 + (n) * 16)
#define DEVIF_RP_MMIO_PAGES(n)		(24 + (n) * 16)
#define DEVIF_RP_MMIO_ATTR(n)		(28 + (n) * 16)
#define DEVIF_RP_MMIO_ATTR_MSIX		0x1
#define DEVIF_RP_MMIO_ATTR_PBA		0x2
#define DEVIF_RP_MMIO_ATTR_NON_TEE	0x4
#define DEVIF_RP_MMIO_ATTR_UPDATABLE	0x8

#endif

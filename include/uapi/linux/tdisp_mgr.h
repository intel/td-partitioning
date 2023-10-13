/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright(c) 2023 Intel Corporation. */
#ifndef _UAPI_LINUX_TDISP_MGR_H
#define _UAPI_LINUX_TDISP_MGR_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define TDISP_MGR_MAGIC 0xB8

/**
 * TDISP_MGR_GET_API_VERSION
 *
 * Report the version of the driver API.
 * Return: Driver API version.
 */
#define TDISP_MGR_GET_API_VERSION	_IO(TDISP_MGR_MAGIC, 0)

#define TDISP_MGR_API_VERSION		0

/**
 * TDISP_MGR_GET_INFO
 *
 * Get info for given TDISP MGR
 */
#define TDISP_MGR_GET_INFO		_IO(TDISP_MGR_MAGIC, 1)

struct tmgr_info {
	__u32 flags;
	__u32 devid;
	__u32 iommu_id;
	__u32 session_idx;
};

/**
 * TDISP_MGR_MSG_EXCHANGE
 *
 * Message exchange with target TDISP device.
 * Return: 0 on success, -errno on failure.
 */
#define TDISP_MGR_MSG_EXCHANGE		_IO(TDISP_MGR_MAGIC, 2)

struct tmgr_message {
	__u32 flags;
#define TMGR_MSG_FLAGS_DOE			0x1
#define TMGR_MSG_FLAGS_SECURE			0x2
	__u32 status;
#define TMGR_MSG_STATUS_SUCCESS			0
#define TMGR_MSG_STATUS_DEVICE_ERROR		1
#define TMGR_MSG_STATUS_TIMEOUT			2
#define TMGR_MSG_STATUS_RESP_BUF_SMALL		3
#define TMGR_MSG_STATUS_BAD_COM_BUF_SIZE	4
#define TMGR_MSG_STATUS_BAD_RESP_BUF_SIZE	5
#define TMGR_MSG_STATUS_SERVICE_BUSY		6
#define TMGR_MSG_STATUS_INVALID_PARAM		7
#define TMGR_MSG_STATUS_OUT_OF_RESOURCE		8
	__u32 req_size;
	__u32 resp_size;

	__u64 req_addr;
	__u64 resp_addr;
};

/**
 * TDISP_MGR_SET_EVENTFD
 *
 * Userspace agents provide eventfd to tdisp manager.
 * Return: 0 on success, -errno on failure.
 */
#define TDISP_MGR_SET_EVENTFD		_IO(TDISP_MGR_MAGIC, 3)

struct tmgr_eventfd {
	/*
	 * fd < 0: tdisp manager will put current eventfd_ctx.
	 * fd >= 0: tdisp manager will get the eventfd_ctx of fd.
	 */
	__s32 fd;
};

/**
 * TDISP_MGR_GET_REQUEST
 *
 * Get requests to userspace agent.
 * Return: 0 on success, -ENOENT if no pending request.
 */
#define TDISP_MGR_GET_REQUEST		_IO(TDISP_MGR_MAGIC, 4)

struct tmgr_request {
	__u8 request;
#define TMGR_REQ_NOOP			0x0
#define TMGR_REQ_START			TMGR_REQ_NOOP
#define TMGR_SESS_REQ_START_SESSION	0x1
#define TMGR_SESS_REQ_START		TMGR_SESS_REQ_START_SESSION
#define TMGR_SESS_REQ_END_SESSION	0x2
#define TMGR_SESS_REQ_KEYUPDATE		0x3
#define TMGR_SESS_REQ_HEARTBEAT		0x4
#define TMGR_SESS_REQ_END		TMGR_SESS_REQ_HEARTBEAT
#define TMGR_REQ_RECOLLECT		0x5
#define TMGR_REQ_TYPE_MAX		TMGR_REQ_RECOLLECT
	__u8 result;
#define TMGR_REQ_RET_SUCCESS		0x0
#define TMGR_REQ_RET_INVALID		0x1
#define TMGR_REQ_RET_UNSUPPORTED	0x2
#define TMGR_REQ_RET_OOR		0x3
#define TMGR_REQ_RET_MOD_ERR		0x4
#define TMGR_REQ_RET_DEV_ERR		0x5
#define TMGR_REQ_RET_MESSAGE_ERR	0x6
#define TMGR_REQ_RET_AGENT_ERR		0x7
#define TMGR_REQ_RET_SW_INIT_ERR	0xa0
#define TMGR_REQ_RET_SW_COMP_ERR	0xa1
#define TMGR_REQ_RET_SW_NO_MATCH	0xa2

	union {
		struct {
			__u8 meas_req_attr;
			__u8 session_policy;
		} start_sess;
	};
};

/**
 *
 * TDISP_MGR_COMPLETE_REQUEST
 *
 * Notify that userspace agent has completed a request.
 * Return: 0 on success, -errno on failure.
 */
#define TDISP_MGR_COMPLETE_REQUEST	_IO(TDISP_MGR_MAGIC, 5)

/**
 *
 * TDISP_MGR_SET_DEVICE_INFO
 *
 * Userspace agent sets agent relavant Device Information
 * to TDISP manager.
 */
#define TDISP_MGR_SET_DEVICE_INFO	_IO(TDISP_MGR_MAGIC, 6)

struct tmgr_dev_info {
	__u32 size;
	__u8 *data;
};

/**
 * TDISP_MGR_SEC_MSG_EXCHANGE
 *
 * Message exchange with device
 */
#define TDISP_MGR_SEC_MSG_EXCHANGE	_IO(TDISP_MGR_MAGIC, 7)

/**
 * TDISP_MGR_GET_DEVICE_INFO_SIZE
 *
 * Get Device Information data size
 */
#define TDISP_MGR_GET_DEVICE_INFO_SIZE	_IO(TDISP_MGR_MAGIC, 8)

/**
 * TDISP_MGR_GET_DEVICE_INFO
 *
 * Get Device Information data
 */
#define TDISP_MGR_GET_DEVICE_INFO	_IO(TDISP_MGR_MAGIC, 9)

#endif /* _UAPI_LINUX_TDISP_MGR_H */

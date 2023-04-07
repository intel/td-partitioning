/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2023 Intel Corporation */
#ifndef _ASM_X86_TDXIO_H
#define _ASM_X86_TDXIO_H

#include <linux/spdm_mgr.h>

struct tpa_dev_info {
	u32 struct_version;

	u64 tpa_request_id;
	u32 device_id;
	u32 interface_id_l;
	u64 interface_id_h;
	u32 iommu_id;
	u32 session_idx;
	u64 tpa_req_nonce[4];
};

struct tpa_spdm_policy {
	u32 struct_version;

	u8  version_entry_num;
	/* u16 version_entry; */
	u8  meas_req_attr;
	u8  session_policy;
};

struct tpa_tdisp_policy {
	u32 struct_version;

	u8  version_entry_num;
	/* u16 version_entry; */
	u32 capabilities;
};

struct dev_spdm_info {
	u32 struct_version;

	u8  spdm_version;
	u8  ctexponent;
	u32 capability_flags;
	u32 data_trans_size;
	u32 max_spdm_msg_size;
	u8  meas_spec;
	u8  other_parm_support;
	u32 meas_hash_algo;
	u32 base_hash_algo;
	u32 base_asym_algo;
	u16 dhe_algo;
	u16 aead_algo;
	u16 key_schedule_algo;

	u8  spdm_secure_version;
	u32 session_id;
	u8  heartbeat_period;
};

struct dev_spdm_cert {
	u32 struct_version;

	struct {
		u16 size;
		u8  *data;
	} certs[SPDM_CERT_NUM];
};

struct dev_spdm_meas {
	u32 struct_version;

	u32 meas_cap;
	u8  meas_req_attr;
	u8  meas_resp_attr;

	u16 meas_size_l;
	u16 meas_size_h;
	u32 all_meas_block_size;
	u8  *all_meas_block;
};

struct dev_tdisp_info {
	u32 struct_version;

	u8  tdisp_version;
	u32 dsm_caps;
	u64 req_msgs_supported_l;
	u64 req_msgs_supported_h;
	u16 lock_flags_supported;
	u8  rsvd[3];
	u8  dev_addr_width;
	u8  num_req_this;
	u8  num_req_all;
};

struct tpa_dev_info_data {
	u32 struct_version;

	struct tpa_dev_info     dev_info;
	struct tpa_spdm_policy  spdm_policy;
	struct tpa_tdisp_policy tdisp_policy;

	struct dev_spdm_info	spdm_info;
	struct dev_spdm_cert	spdm_cert;
	struct dev_spdm_meas	spdm_meas;

	struct dev_tdisp_info   tdisp_info;
};

#define DEVINFO_FETCH_DATA(x, member, type, data) \
	{ (x)->member = *(type *)(data);\
	(data) += sizeof(type);\
	pr_debug("%s:" #member " 0x%llx\n", __func__, (u64)(x)->member); }

static inline void *parse_tpa_dev_info(struct tpa_dev_info *info, void *data)
{
	data += 24;

	DEVINFO_FETCH_DATA(info, struct_version,   u32, data);
	DEVINFO_FETCH_DATA(info, tpa_request_id,   u64, data);
	DEVINFO_FETCH_DATA(info, device_id,        u32, data);
	DEVINFO_FETCH_DATA(info, interface_id_l,   u32, data);
	DEVINFO_FETCH_DATA(info, interface_id_h,   u64, data);
	DEVINFO_FETCH_DATA(info, iommu_id,         u32, data);
	DEVINFO_FETCH_DATA(info, session_idx,      u32, data);
	DEVINFO_FETCH_DATA(info, tpa_req_nonce[0], u64, data);
	DEVINFO_FETCH_DATA(info, tpa_req_nonce[1], u64, data);
	DEVINFO_FETCH_DATA(info, tpa_req_nonce[2], u64, data);
	DEVINFO_FETCH_DATA(info, tpa_req_nonce[3], u64, data);
	return data;
}

static inline void *parse_tpa_spdm_policy(struct tpa_spdm_policy *policy, void *data)
{
	data += 24;

	DEVINFO_FETCH_DATA(policy, struct_version,    u32, data);
	DEVINFO_FETCH_DATA(policy, version_entry_num, u8,  data);
	DEVINFO_FETCH_DATA(policy, meas_req_attr,     u8,  data);
	DEVINFO_FETCH_DATA(policy, session_policy,    u8,  data);
	return data;
}

static inline void *parse_tpa_tdisp_policy(struct tpa_tdisp_policy *policy, void *data)
{
	data += 24;

	DEVINFO_FETCH_DATA(policy, struct_version,    u32, data);
	DEVINFO_FETCH_DATA(policy, version_entry_num, u8,  data);
	DEVINFO_FETCH_DATA(policy, capabilities,      u32, data);
	return data;
}

static inline void *parse_dev_spdm_info(struct dev_spdm_info *info, void *data)
{
	data += 24;

	DEVINFO_FETCH_DATA(info, struct_version,      u32, data);

	/* Connection Info */
	DEVINFO_FETCH_DATA(info, spdm_version,        u8,  data);
	DEVINFO_FETCH_DATA(info, ctexponent,          u8,  data);
	DEVINFO_FETCH_DATA(info, capability_flags,    u32, data);
	DEVINFO_FETCH_DATA(info, data_trans_size,     u32, data);
	DEVINFO_FETCH_DATA(info, max_spdm_msg_size,   u32, data);
	DEVINFO_FETCH_DATA(info, meas_spec,           u8,  data);
	DEVINFO_FETCH_DATA(info, other_parm_support,  u8,  data);
	DEVINFO_FETCH_DATA(info, meas_hash_algo,      u32, data);
	DEVINFO_FETCH_DATA(info, base_hash_algo,      u32, data);
	DEVINFO_FETCH_DATA(info, base_asym_algo,      u32, data);
	DEVINFO_FETCH_DATA(info, dhe_algo,            u16, data);
	DEVINFO_FETCH_DATA(info, aead_algo,           u16, data);
	DEVINFO_FETCH_DATA(info, key_schedule_algo,   u16, data);

	/* Session Info */
	DEVINFO_FETCH_DATA(info, spdm_secure_version, u8,  data);
	DEVINFO_FETCH_DATA(info, session_id,          u32, data);
	DEVINFO_FETCH_DATA(info, heartbeat_period,    u8,  data);

	return data;
}

static inline void *parse_dev_spdm_cert(struct dev_spdm_cert *cert, void *data)
{
	data += 24;

	DEVINFO_FETCH_DATA(cert, struct_version,      u32, data);

	for (int i = 0; i < SPDM_CERT_NUM; ++i) {
		DEVINFO_FETCH_DATA(cert, certs[i].size, u16, data);

		if (cert->certs[i].size) {
			cert->certs[i].data = data;
			data += cert->certs[i].size;
			pr_debug("%s: cert%d %p\n", __func__, i, cert->certs[i].data);
		}
	}

	return data;
}

static inline void *parse_dev_spdm_meas(struct dev_spdm_meas *meas, void *data)
{
	data += 24;

	DEVINFO_FETCH_DATA(meas, struct_version, u32, data);
	DEVINFO_FETCH_DATA(meas, meas_cap,       u32, data);
	DEVINFO_FETCH_DATA(meas, meas_req_attr,  u8,  data);
	DEVINFO_FETCH_DATA(meas, meas_resp_attr, u8,  data);
	DEVINFO_FETCH_DATA(meas, meas_size_l,    u16, data);
	DEVINFO_FETCH_DATA(meas, meas_size_h,    u8,  data);

	meas->all_meas_block_size = meas->meas_size_l + (meas->meas_size_h << 16);

	if (meas->all_meas_block_size) {
		meas->all_meas_block = data;
		data += meas->all_meas_block_size;
	}

	return data;
}

static inline void *parse_dev_tdisp_info(struct dev_tdisp_info *info, void *data)
{
	data += 24;

	DEVINFO_FETCH_DATA(info, struct_version,       u32, data);
	DEVINFO_FETCH_DATA(info, tdisp_version,        u32, data);
	DEVINFO_FETCH_DATA(info, dsm_caps,             u32, data);
	DEVINFO_FETCH_DATA(info, req_msgs_supported_l, u64, data);
	DEVINFO_FETCH_DATA(info, req_msgs_supported_h, u64, data);
	DEVINFO_FETCH_DATA(info, lock_flags_supported, u16, data);

	/* skip reserved filed */
	data += 3;

	DEVINFO_FETCH_DATA(info, dev_addr_width,       u8, data);
	DEVINFO_FETCH_DATA(info, num_req_this,         u8, data);
	DEVINFO_FETCH_DATA(info, num_req_all,          u8, data);
	return data;
}

static inline void parse_tpa_dev_info_data(struct tpa_dev_info_data *info, void *data)
{
	u16 hob_len;

	DEVINFO_FETCH_DATA(info, struct_version, u32, data);

	pr_debug("%s: struct_version 0x%x\n", __func__, info->struct_version);

	hob_len = ((u16 *)data)[1];
	parse_tpa_dev_info(&info->dev_info, data);
	hob_len = round_up(hob_len, 8);
	data += hob_len;

	hob_len = ((u16 *)data)[1];
	parse_tpa_spdm_policy(&info->spdm_policy, data);
	hob_len = round_up(hob_len, 8);
	data += hob_len;

	hob_len = ((u16 *)data)[1];
	parse_tpa_tdisp_policy(&info->tdisp_policy, data);
	hob_len = round_up(hob_len, 8);
	data += hob_len;

	hob_len = ((u16 *)data)[1];
	parse_dev_spdm_info(&info->spdm_info, data);
	hob_len = round_up(hob_len, 8);
	data += hob_len;

	hob_len = ((u16 *)data)[1];
	parse_dev_spdm_cert(&info->spdm_cert, data);
	hob_len = round_up(hob_len, 8);
	data += hob_len;

	hob_len = ((u16 *)data)[1];
	parse_dev_spdm_meas(&info->spdm_meas, data);
	hob_len = round_up(hob_len, 8);
	data += hob_len;

	hob_len = ((u16 *)data)[1];
	parse_dev_tdisp_info(&info->tdisp_info, data);
	hob_len = round_up(hob_len, 8);
	data += hob_len;

	pr_debug("%s: complete\n", __func__);
}

#endif /* _ASM_X86_TDXIO_H */

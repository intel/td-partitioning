/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2023 Intel Corporation. */
#ifndef _TDX_DEVICE_ATTEST_H
#define _TDX_DEVICE_ATTEST_H

#include <linux/types.h>
#include <asm/tdxio.h>

/* SPDM v1.2, sec 10.11.1.2, "Device mode field of measurement block" */
#define DEV_OP_CAP_RP_MASK			GENMASK(5, 0)
#define DEV_OP_CAP_RP_MANUFACTURE		BIT_MASK(0)
#define DEV_OP_CAP_RP_VALIDATION		BIT_MASK(1)
#define DEV_OP_CAP_RP_NORMAL			BIT_MASK(2)
#define DEV_OP_CAP_RP_RECOVERY			BIT_MASK(3)
#define DEV_OP_CAP_RP_RMA			BIT_MASK(4)
#define DEV_OP_CAP_RP_DECOMMISION		BIT_MASK(5)

#define DEV_OP_STS_MANUFACTURE			BIT_MASK(0)
#define DEV_OP_STS_VALIDATION			BIT_MASK(1)
#define DEV_OP_STS_NORMAL			BIT_MASK(2)
#define DEV_OP_STS_RECOVERY			BIT_MASK(3)
#define DEV_OP_STS_RMA				BIT_MASK(4)
#define DEV_OP_STS_DECOMMISION			BIT_MASK(5)

#define DEV_MD_CAP_RP_MASK			GENMASK(4, 0)
#define DEV_MD_CAP_RP_NON_INVASIVE		BIT_MASK(0)
#define DEV_MD_CAP_RP_INVASIVE			BIT_MASK(1)
#define DEV_MD_CAP_RP_NON_INVASIVE_ACTIVE	BIT_MASK(2)
#define DEV_MD_CAP_RP_INVASIVE_ACTIVE		BIT_MASK(3)
#define DEV_MD_CAP_RP_INVASIVE_ALREADY		BIT_MASK(4)

#define DEV_MD_STS_NON_INVASIVE			BIT_MASK(0)
#define DEV_MD_STS_INVASIVE			BIT_MASK(1)
#define DEV_MD_STS_NON_INVASIVE_ACTIVE		BIT_MASK(2)
#define DEV_MD_STS_INVASIVE_ACTIVE		BIT_MASK(3)
#define DEV_MD_STS_INVASIVE_ALREADY		BIT_MASK(4)

struct device_mode_measurement {
	u32 operational_mode_capabilties;
	u32 operational_mode_state;
	u32 device_mode_capabilties;
	u32 device_mode_state;
} __packed;

/* SPDM v1.2, sec 10.11.1.1, Table 45 "DMTF measurement specification format" */
#define DMTF_VALUE_TYPE_RAW		BIT_MASK(7)
#define DMTF_VALUE_TYPE_ROM		0
#define DMTF_VALUE_TYPE_FW		1
#define DMTF_VALUE_TYPE_HW_CFG		2
#define DMTF_VALUE_TYPE_FW_CFG		3
#define DMTF_VALUE_TYPE_MANIFEST	4
#define DMTF_VALUE_TYPE_DEV_MODE	5
#define DMTF_VALUE_TYPE_FW_VER		6
#define DMTF_VALUE_TYPE_FW_SECURITY_VER	7

#define DMTF_VALUE_TYPE_MASK		GENMASK(6, 0)
#define DMTF_VALUE_TYPE(v)		((v) & DMTF_VALUE_TYPE_MASK)

/* SPDM v1.2, sec 10.11.1, Table 44 "Measurement block format" */
struct dmtf_measurement {
	u8  value_type;
	u16 value_size;
	union {
		struct device_mode_measurement device_mode_measurement;
		u8 hash[64];
		u8 value[0];
	};
} __packed;

#define DMTF_MEASU_SPEC	1

struct measurement_block {
	u8  index;
	u8  specification;
	u16 size;
	struct dmtf_measurement dmtf;
} __packed;

/* SPDM v1.2, sec 10.6.1, Table 28 "Certificate chain format" */
struct certificate_chain_fmt {
	u16 length;
	u16 reserved;
	u8  root_hash[0]; /* H bytes */
	/* u8  chain[0]; */
} __packed;

/* GHCI v2.0.0.6.4, sec 3.13.3.2.1 "TDX-IO TPA Device Information" */
struct tpa_device_information {
	u32 struct_version;
	u64 tpa_request_id;
	u32 device_id;
	u32 iommu_id;
	u32 spdm_session_index;
	u8  tpa_request_nonce[32];
} __packed;

/* GHCI v2.0.0.6.4, sec 3.13.3.2.2 "TDX-IO TPA SPDM Policy" */
struct dev_spdm_policy {
	u32 struct_version;
	u8  measurement_request_attributes;
	u8  session_policy;
} __packed;

/* GHCI v2.0.0.6.4, sec 3.13.3.2.3 "TDX-IO TPA SPDM TDISP Policy" */
struct dev_tdisp_policy {
	u32 structversion;
	u8  tdispcapabilities[20 - 16];
} __packed;

/* GHCI v2.0.0.6.4, sec 3.13.3.3.1 "TDX-IO Device SPDM Information" */
struct device_spdm_information {
	u32 struct_version;
	u8  spdm_version;
	u8  ct_exponent;
	u32 capability_flags;
	u32 data_transfer_size;
	u32 max_spdm_msgsize;
	u8  measurement_spec;
	u8  other_params_support;
	u32 measurement_hash_algo;
	u32 base_hash_algo;
	u32 base_asym_algo;
	u16 dhe_algo;
	u16 aead_algo;
	u16 key_schedule_algo;
	u8  secure_spdm_version;
	u32 session_id;
	u8  heart_beat_period;
} __packed;

/* GHCI v2.0.0.6.4, sec 3.13.3.3.4 "TDX-IO Device TDISP Information" */
struct device_tdisp_information {
	u32 struct_version;
	u8  tdisp_version;
	u8  tdisp_capabilities[44 - 16];
} __packed;

/*
 * GHCI v2.0.0.6.4, sec 3.13.3.3.2 "TDX-IO Device SPDM Certificate"
 *
 * cert0, cert1, ... cert7 are in format of struct certificate_chain_fmt.
 */
struct device_spdm_certificate {
	u32 struct_version;
	u16 cert0_size;
	u8  cert0[0];
	/* u16 cert1_size; */
	/* u8 cert1[cert1_size]; */
	/* ... */
	/* u16 cert7_size; */
	/* u8 cert7[cert7_size]; */
} __packed;

/* GHCI v2.0.0.6.4, sec 3.13.3.3.3 "TDX-IO Device SPDM Measurement" */
struct device_spdm_measurement {
	u32 struct_version;
	u32 measurement_cap;
	u8  measurement_request_attributes;
	u8  measurement_response_attributes;
	u8  all_measurement_block_size[3];
	u8  all_measurement_block[0];
	/* struct measurement_block measurement_block */
} __packed;

/* GHCI v2.0.0.6.4, sec 3.13.3.3.1 "TDX-IO Device Information Data" */
struct device_info_data {
	u32 struct_version;
	struct tpa_device_information   tpa_device_information;
	struct dev_spdm_policy          dev_spdm_policy;
	struct dev_tdisp_policy         dev_tdisp_policy;
	struct device_spdm_information  device_spdm_information;
	struct device_spdm_certificate  device_spdm_certificate;
	/* struct device_spdm_measurement  device_spdm_measurement; */
	/* struct device_tdisp_information device_tdisp_information; */
} __packed;

struct certs {
	unsigned int vendor;
	unsigned int device;
	size_t size;
	/* A cert or a cert chain in DER format */
	const u8 *data;
};

bool tdx_attest_device(struct pci_tdi *tdi);
#endif

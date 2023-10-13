// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2023 Intel Corporation. */
#define DEBUG
#define pr_fmt(fmt) "Device Attestation: " fmt

#include <linux/types.h>
#include <linux/string.h>
#include <linux/minmax.h>
#include <linux/asn1.h>
#include <linux/stddef.h>
#include <linux/printk.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/random.h>
#include "device-attest.h"
#include "device-pre-certs.h"

/* 2-byte tag and 2-byte size */
#define DER_CERT_HDR_SIZE	4
#define DER_CERT_SIZE(hdr)	(((u16)hdr[2] << 8 | (u16)hdr[3]) + DER_CERT_HDR_SIZE)

#define MAX_CHAIN_DEPTH		8
/* Size of device_spdm_certificate->struct_version */
#define SPDM_CERT_VER_SIZE	4
/* Size of device_spdm_certificate->cert0_size */
#define SPDM_CHAIN_HDR_SIZE	2
/* Size of device_spdm_measurement->all_measurement_block_size */
#define SPDM_MEASU_HDR_SIZE	3

#define MAX_MEASUREMENTS	32

#define for_each_measu(i, size, tmp, m, ms)		\
	for (i = 0, tmp = ms;				\
		m = tmp,				\
		size = m->size, i < MAX_MEASUREMENTS;	\
		tmp = (struct measurement_block *)	\
		((u8 *)&m->dmtf + m->size), i++)	\

#define for_each_pre_chain(pre_cert, tmp, pre_certs)			\
	for (tmp = pre_certs; pre_cert = *tmp, pre_cert; tmp++)		\

static void show_device_mode_measu(struct device_mode_measurement *d)
{
	pr_info("    Device mode measurement:");
	pr_info("      Operational mode cap : 0x%x\n", d->operational_mode_capabilties);
	pr_info("      Operational mode sts : 0x%x\n", d->operational_mode_state);
	pr_info("      Device mode cap      : 0x%x\n", d->device_mode_capabilties);
	pr_info("      Device mode sts      : 0x%x\n", d->device_mode_state);
}

static void show_measus(struct dev_spdm_meas *spdm_meas)
{
	size_t size, total_size = 0, used_size = 0;
	struct measurement_block *tmp, *m, *ms;
	struct dmtf_measurement *dmtf;
	int i;

	ms = (struct measurement_block *)spdm_meas->all_meas_block;

	total_size = spdm_meas->all_meas_block_size;

	for_each_measu(i, size, tmp, m, ms) {
		size += offsetof(struct measurement_block, dmtf);
		used_size += size;

		if (m->specification != DMTF_MEASU_SPEC) {
			pr_info("Skip non-dmtf measure(index %u)\n", m->index);
			goto end;
		}

		pr_info("--------------------------------");
		pr_info("Measurement#%d:", i);

		dmtf = &m->dmtf;
		pr_info("Measure index: %u", m->index);
		pr_info("DMTFSpecMeasurementValueType: 0x%02x", dmtf->value_type);

		if (DMTF_VALUE_TYPE(dmtf->value_type) == DMTF_VALUE_TYPE_DEV_MODE) {
			show_device_mode_measu(&dmtf->device_mode_measurement);
			goto end;
		}

		pr_info("DMTFSpecMeasurementValue:");
		size = m->dmtf.value_size;
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, dmtf->value, size);

end:
		if (used_size >= total_size)
			break;
	}
	pr_info("=================================");
}

enum hash_algo {
	TPM_ALG_SHA_256 = 1 << 0,
	TPM_ALG_SHA_384 = 1 << 1,
	TPM_ALG_SHA_512 = 1 << 2,
	TPM_ALG_SHA3_256 = 1 << 3,
	TPM_ALG_SHA3_384 = 1 << 4,
	TPM_ALG_SHA3_512 = 1 << 5,
};

static int get_root_hash_length(uint32_t hash_algo)
{
	if (hash_algo & TPM_ALG_SHA_256) {
		pr_info("Root certificate hash: TPM_ALG_SHA_256\n");
		return 32;
	} else if (hash_algo & TPM_ALG_SHA_384) {
		pr_info("Root certificate hash: TPM_ALG_SHA_384\n");
		return 48;
	} else if (hash_algo & TPM_ALG_SHA_512) {
		pr_info("Root certificate hash: TPM_ALG_SHA_512\n");
		return 64;
	} else if (hash_algo & TPM_ALG_SHA3_256) {
		pr_info("Root certificate hash: TPM_ALG_SHA3_256\n");
		return 32;
	} else if (hash_algo & TPM_ALG_SHA3_384) {
		pr_info("Root certificate hash: TPM_ALG_SHA3_384\n");
		return 48;
	} else if (hash_algo & TPM_ALG_SHA3_512) {
		pr_info("Root certificate hash: TPM_ALG_SHA3_512\n");
		return 64;
	}

	pr_err("Unknown root cert hash algo 0x%x\n", hash_algo);
	return -EINVAL;
}

static u8 *get_der_encoded_chain(struct certificate_chain_fmt *chain_fmt,
				 uint32_t hash_algo)
{
	int root_hash_length;
	u8 *root_hash;

	if (!chain_fmt->length)
		return NULL;

	root_hash_length = get_root_hash_length(hash_algo);
	if (root_hash_length < 0)
		return NULL;

	root_hash = &chain_fmt->root_hash[0];

	return root_hash + root_hash_length;
};

static bool match_chain(u8 *chain_data, size_t chain_size,
			struct certs *pre_cert_chain,
			uint32_t hash_algo)
{
	struct certificate_chain_fmt *fmt = (struct certificate_chain_fmt *)chain_data;
	u8 *chain_der_encoded;
	unsigned long offset;

	chain_der_encoded = get_der_encoded_chain(fmt, hash_algo);

	if (!chain_der_encoded) {
		pr_err("Failed to get the DER encoded chain from device_info_data\n");
		return false;
	}

	offset = (unsigned long)chain_der_encoded - (unsigned long)chain_data;
	chain_size  -= offset;

	if (chain_size != pre_cert_chain->size) {
		pr_info("Failed to match chains size, device cert:0x%lx vs pre-install cert:0x%lx",
			chain_size, pre_cert_chain->size);
		return false;
	}

	if (memcmp(chain_der_encoded, pre_cert_chain->data, pre_cert_chain->size)) {
		pr_info("Failed to match chains, the contents of two chains are not same.");
		return false;
	}

	pr_info("Certificate is matched with pre-install certificates.");
	return true;
}

static bool match_cert_chain(struct pci_dev *pdev,
			     struct dev_spdm_cert *cert,
			     struct dev_spdm_info *info)
{
	struct certs *pre_cert, **tmp_cert;
	struct device *dev = &pdev->dev;

	for_each_pre_chain(pre_cert, tmp_cert, pre_cert_chains) {
		if (pre_cert->vendor != pdev->vendor || pre_cert->device != pdev->device)
			continue;

		for (int i = 0; i < SPDM_CERT_NUM; ++i) {
			if (cert->certs[i].size == 0)
				continue;

			dev_info(dev, "------------------------\n");
			dev_info(dev, "Compare chain%d and pre-installed cert%ld:",
				 i, tmp_cert - pre_cert_chains);

			if (match_chain(cert->certs[i].data, cert->certs[i].size,
					pre_cert, info->base_hash_algo))
				return true;
		}
	}

	return false;
}

static bool attest_certs(struct pci_dev *pdev,
			 struct dev_spdm_cert *cert,
			 struct dev_spdm_info *info)
{
	bool ret;

	pr_info("Start certificate comparation");
	ret = match_cert_chain(pdev, cert, info);
	pr_info("Certificate comparation done.");
	pr_info("=================================");

	return ret;
}

static bool attest_measurements(struct pci_dev *pdev, struct dev_spdm_meas *meas)
{
	/* TODO: Add what measurement to be attested. */
	pr_info("Start measurement comparation");
	pr_info("Skip measurement comparation now.");
	pr_info("Measurement comparation done.");
	pr_info("=================================");
	return true;
}

static bool attest_device(struct pci_dev *pdev,
			  struct dev_spdm_cert *cert,
			  struct dev_spdm_meas *meas,
			  struct dev_spdm_info *info)
{
	show_measus(meas);

	dev_info(&pdev->dev, "Device attestation for %04x:%04x(%s) start:",
		 pdev->vendor, pdev->device, dev_name(&pdev->dev));

	return attest_certs(pdev, cert, info) && attest_measurements(pdev, meas);
}

bool tdx_attest_device(struct pci_tdi *tdi)
{
	struct tpa_dev_info_data *tpa_info;
	struct dev_spdm_cert *cert;
	struct dev_spdm_meas *meas;
	struct dev_spdm_info *info;

	tpa_info = tdi->priv;
	info = &tpa_info->spdm_info;
	cert = &tpa_info->spdm_cert;
	meas = &tpa_info->spdm_meas;

	pr_info("=================================");
	pr_info("SPDM device info:");
	pr_info("  StructVersion: 0x%08x", info->struct_version);
	pr_info("  SpdmVersion: 0x%02x", info->spdm_version);
	pr_info("  CTExponent: 0x%02x", info->ctexponent);
	pr_info("  CapabilityFlags: 0x%08x", info->capability_flags);
	pr_info("  DataTransferSize: 0x%08x", info->data_trans_size);
	pr_info("  MaxSPDMmsgSize: 0x%08x", info->max_spdm_msg_size);
	pr_info("  MeasurementSpec: 0x%02x", info->meas_spec);
	pr_info("  OtherParamsSupport: 0x%02x", info->other_parm_support);
	pr_info("  MeasurementHashAlgo: 0x%08x", info->meas_hash_algo);
	pr_info("  BaseHashAlgo: 0x%08x", info->base_hash_algo);
	pr_info("  BaseAsymAlgo: 0x%08x", info->base_asym_algo);
	pr_info("  DheAlgo: 0x%04x", info->dhe_algo);
	pr_info("  AeadAlgo: 0x%04x", info->aead_algo);
	pr_info("  KeyScheduleAlgo: 0x%04x", info->key_schedule_algo);
	pr_info("  SecureSpdmVersion: 0x%02x", info->spdm_secure_version);
	pr_info("  SessionId: 0x%08x", info->session_id);
	pr_info("  HeartbeatPeriod: 0x%02x", info->heartbeat_period);
	pr_info("=================================");

	pr_info("Data Info. Certificate:");
	for (int i = 0; i < SPDM_CERT_NUM; ++i) {
		pr_info("---------------------------------");
		pr_info("Size%d: 0x%04x", i, cert->certs[i].size);
		pr_info("Cert%d:", i);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, cert->certs[i].data,
				     cert->certs[i].size);
	}
	pr_info("=================================");

	pr_info("Measurement:");
	pr_info("Size: 0x%x", meas->all_meas_block_size);
	pr_info("Content:");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, meas->all_meas_block,
			     meas->all_meas_block_size);

	return attest_device(tdi->pdev, cert, meas, info);
}

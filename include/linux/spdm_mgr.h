/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2023 Intel Corporation.
 *
 * SPDM Manager Driver
 */
#ifndef LINUX_SPDM_MGR_H
#define LINUX_SPDM_MGR_H

#include <linux/mutex.h>
#include <linux/types.h>

struct spdm;
struct spdm_message;

struct spdm_parm {
	u8 meas_req_attr;
#define SIGNATURE_REQUESTED		0x1
#define RAW_BIT_STREAM_REQUESTED	0x2
};

struct spdm_session_parm {
	u8 session_policy;
#define TERMINATION_POLICY	0x1
};

struct spdm_session {
	struct spdm *spdm;
	struct spdm_session_parm parm;
	unsigned long flags;

	struct mutex state_lock;
	int state;
#define SPDM_SESS_STATE_NONE	0x0
#define SPDM_SESS_STATE_SETUP	0x1
#define SPDM_SESS_STATE_READY	0x2
#define SPDM_SESS_STATE_CLEANUP	0x3
#define SPDM_SESS_STATE_ERROR	0x4

	struct mutex transfer_lock;
	atomic64_t seq_num;
	int (*msg_exchange)(struct spdm_session *session,
			    struct spdm_message *msg);
	int (*keyupdate)(struct spdm_session *session);

	u64 keyupdate_threshold;
#define SPDM_KEYUPD_THR_DEFAULT	0xffff

	u8 version;
	u32 session_id;

	u8 policy;
	u8 secure_spdm_version;
	u8 heartbeat_period;

	void *priv;
};

struct spdm {
	struct spdm_parm parm;
	unsigned long flags;
#define SPDM_FLAGS_TEE		0x1
#define SPDM_FLAGS_PCI		0x2
	const char *name;
	unsigned int state;
#define SPDM_STATE_NONE		0x1
#define SPDM_STATE_CONNECT	0x2

	const struct spdm_ops	*ops; /* Transport Ops */
	struct spdm_session session;

	struct mutex transfer_lock;
	int (*msg_exchange)(struct spdm *spdm, struct spdm_message *msg);

	void *priv;

	/* Connection Info */
	u8  version;
	u8  ctexponent;
	u32 capability_flags;
#define SPDM_CACHE_CAP		(1 << 1)
#define SPDM_CACL_CAP		(1 << 2)
#define SPDM_MEAS_CAP		(3 << 3)
#define SPDM_MEAS_FRESH_CAP	(1 << 5)
#define SPDM_ENCRYPT_CAP	(1 << 6)
#define SPDM_MAC_CAP		(1 << 7)
#define SPDM_MUT_AUTH_CAP	(1 << 8)
#define SPDM_KEY_EX_CAP		(1 << 9)
#define SPDM_PSK_CAP		(3 << 10)
#define SPDM_ENCAP_CAP		(1 << 12)
#define SPDM_HBEAT_CAP		(1 << 13)
#define SPDM_KEY_UPD_CAP	(1 << 14)
#define SPDM_HS_IN_THE_CLR_CAP  (1 << 15)
#define SPDM_PUB_KEY_ID_CAP     (1 << 16)
#define SPDM_CHUNK_CAP		(1 << 17)
#define SPDM_ALIAS_CERT_CAP	(1 << 18)
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

	/* Certificaties */
#define SPDM_CERT_NUM 8
	struct {
		u16 size;
		u8  *data;
	} certs[SPDM_CERT_NUM];

	/* Mesurements */
	u32 meas_cap;
	u8  meas_req_attr;
	u8  meas_resp_attr;

	u32 all_meas_block_size;
	u8  *all_meas_block;
};

struct spdm_message {
	u32 flags;
#define SPDM_MSG_FLAGS_DOE	0x1
#define SPDM_MSG_FLAGS_SECURE	0x2
	u32 status;
	u32 req_size;
	u32 resp_size;
	u64 req_addr;
	u64 resp_addr;
};

struct spdm *spdm_create(struct device *dev, const char *name,
			 unsigned long flags, struct spdm_parm parm,
			 void *priv);
void spdm_remove(struct spdm *spdm);

static inline int spdm_msg_exchange_prepare(struct spdm *spdm)
{
	return mutex_lock_interruptible(&spdm->transfer_lock);
}

static inline void spdm_msg_exchange_complete(struct spdm *spdm)
{
	mutex_unlock(&spdm->transfer_lock);
}

int spdm_msg_exchange(struct spdm *spdm, struct spdm_message *msg);

struct spdm_session *spdm_session_create(struct spdm *spdm,
					 struct spdm_session_parm parm);
void spdm_session_remove(struct spdm_session *session);

static inline bool is_spdm_session_keyupdate_required(struct spdm_session *session, int budget)
{
	u64 seq_num = atomic64_read(&session->seq_num);
	struct spdm *spdm = session->spdm;

	return (spdm->capability_flags & SPDM_KEY_UPD_CAP) &&
	       (seq_num + budget >= session->keyupdate_threshold);
}

static inline void spdm_session_set_state(struct spdm_session *session, int state)
{
	session->state = state;
}

static inline int spdm_session_get_state(struct spdm_session *session)
{
	return session->state;
}

static inline bool is_spdm_session_alive(struct spdm_session *session)
{
	return !(session->state == SPDM_SESS_STATE_ERROR);
}

static inline int spdm_session_msg_exchange_prepare(struct spdm_session *session, int budget)
{
	int ret;

	ret = mutex_lock_interruptible(&session->transfer_lock);
	if (ret)
		return ret;

	if (!is_spdm_session_alive(session)) {
		mutex_unlock(&session->transfer_lock);
		return -EIO;
	}

	if (is_spdm_session_keyupdate_required(session, budget)) {
		ret = session->keyupdate(session);
		if (ret)
			mutex_unlock(&session->transfer_lock);
		else
			atomic64_set(&session->seq_num, 0);
	}

	return ret;
}

static inline void spdm_session_msg_exchange_complete(struct spdm_session *session)
{
	mutex_unlock(&session->transfer_lock);
}

int spdm_session_msg_exchange(struct spdm_session *session, struct spdm_message *msg);

static inline bool is_spdm_hbeat_required(struct spdm_session *session)
{
	struct spdm *spdm = session->spdm;

	return (spdm->capability_flags & SPDM_HBEAT_CAP) && session->heartbeat_period;
}

#endif /* LINUX_SPDM_MGR_H */

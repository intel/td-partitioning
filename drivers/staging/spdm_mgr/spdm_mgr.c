// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2023 Intel Corporation.
 *
 * SPDM Manager Driver
 */
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/spdm_mgr.h>

/*
 * test_keyupdate: shorten threshold of keyupdate for testing purpose.
 */
static int test_keyupdate = 15;
module_param(test_keyupdate, int, 0644);

struct spdm *spdm_create(struct device *dev, const char *name,
			 unsigned long flags, struct spdm_parm parm, void *priv)
{
	struct spdm *spdm;

	spdm = kzalloc(sizeof(*spdm), GFP_KERNEL);
	if (!spdm)
		return NULL;

	mutex_init(&spdm->transfer_lock);
	spdm->name = name;
	spdm->flags = flags;
	spdm->parm = parm;
	spdm->priv = priv;
	return spdm;
}
EXPORT_SYMBOL_GPL(spdm_create);

void spdm_remove(struct spdm *spdm)
{
	mutex_destroy(&spdm->transfer_lock);
	kfree(spdm);
}
EXPORT_SYMBOL_GPL(spdm_remove);

int spdm_msg_exchange(struct spdm *spdm, struct spdm_message *msg)
{
	if (msg->flags & SPDM_MSG_FLAGS_SECURE)
		return -EINVAL;

	if (!spdm->msg_exchange)
		return -ENOTTY;

	return spdm->msg_exchange(spdm, msg);
}
EXPORT_SYMBOL_GPL(spdm_msg_exchange);

int spdm_session_msg_exchange(struct spdm_session *session, struct spdm_message *msg)
{
	int ret;

	if (!(msg->flags & SPDM_MSG_FLAGS_SECURE))
		return -EINVAL;

	if (!session->msg_exchange)
		return -ENOTTY;

	ret = session->msg_exchange(session, msg);
	if (ret)
		return ret;

	atomic64_inc(&session->seq_num);
	return ret;
}
EXPORT_SYMBOL_GPL(spdm_session_msg_exchange);

struct spdm_session *spdm_session_create(struct spdm *spdm,
					 struct spdm_session_parm parm)
{
	struct spdm_session *session;

	/* FIXME: just use spdm->session */
	session = &spdm->session;
	session->spdm = spdm;
	session->parm = parm;
	session->state = SPDM_SESS_STATE_NONE;
	session->keyupdate_threshold = test_keyupdate ?
			test_keyupdate : SPDM_KEYUPD_THR_DEFAULT;

	mutex_init(&session->state_lock);
	atomic64_set(&session->seq_num, 0);
	mutex_init(&session->transfer_lock);

	return session;
}
EXPORT_SYMBOL_GPL(spdm_session_create);

void spdm_session_remove(struct spdm_session *session)
{
	mutex_destroy(&session->state_lock);
	mutex_destroy(&session->transfer_lock);
}
EXPORT_SYMBOL_GPL(spdm_session_remove);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SPDM manager");

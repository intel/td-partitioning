// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2023 Intel Corporation. */
#include <linux/cpu.h>
#include <linux/eventfd.h>
#include <linux/iommu.h>
#include <linux/miscdevice.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>

#include <asm/vmx.h>
#include <asm/tdx.h>
#include <asm/tdxio.h>

#include "pci-tdisp.h"

/* by default request_timeout is 20s */
static unsigned int request_timeout = 20000;
module_param(request_timeout, uint, 0644);

static int pci_arch_tdisp_dev_tee_enter(struct pci_tdisp_dev *tdev)
{
	struct pci_dev *rp;

	if (!tdev || !tdev->pdev)
		return -EINVAL;

	/* Configure Root Port to enter TEE mode */
	rp = pcie_find_root_port(tdev->pdev);
	if (!rp)
		return -ENODEV;

	return pci_ide_dev_tee_enter(rp);
}

static void pci_arch_tdisp_dev_tee_exit(struct pci_tdisp_dev *tdev)
{
	struct pci_dev *rp;

	if (!tdev || !tdev->pdev)
		return;

	rp = pcie_find_root_port(tdev->pdev);
	if (rp)
		pci_ide_dev_tee_exit(rp);
}

static inline char *treq_to_str(struct tmgr_request *treq)
{
	switch (treq->request) {
	case TMGR_REQ_NOOP:
		return "TMGR_REQ_NOOP";
	case TMGR_SESS_REQ_START_SESSION:
		return "TMGR_SESS_REQ_START_SESSION";
	case TMGR_SESS_REQ_END_SESSION:
		return "TMGR_SESS_REQ_END_SESSION";
	case TMGR_SESS_REQ_KEYUPDATE:
		return "TMGR_SESS_REQ_KEYUPDATE";
	case TMGR_SESS_REQ_HEARTBEAT:
		return "TMGR_SESS_REQ_HEARTBEAT";
	case TMGR_REQ_RECOLLECT:
		return "TMGR_MGR_REQ_RECOLLECT";
	default:
		return "UNKNOWN";
	}
}

#define tmreq_to_str(x)	((x) ? treq_to_str(&(x)->treq) : "NULL")

static inline struct device *tmgr_to_dev(struct tdisp_mgr *tmgr)
{
	return &tmgr->tdev->pdev->dev;
}

static inline struct spdm_session *tmgr_to_sess(struct tdisp_mgr *tmgr)
{
	return tmgr->tdev->session;
}

static struct tdisp_mgr *file_to_tmgr(struct file *file)
{
	return container_of(file->private_data, struct tdisp_mgr, miscdev);
}

static long tmgr_ioctl_get_info(struct tdisp_mgr *tmgr, void __user *arg)
{
	struct pci_tdisp_dev *tdev = tmgr->tdev;
	struct tmgr_info info;

	info.flags = 0;
	info.devid = pci_dev_id(tdev->pdev);
	info.iommu_id = tmgr->iommu_id;
	info.session_idx = tmgr->session_idx;

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static long tmgr_ioctl_msg_exchange(struct tdisp_mgr *tmgr, void __user *arg)
{
	struct pci_tdisp_dev *tdev = tmgr->tdev;
	struct spdm_session *session = tdev->session;
	gfp_t gfp_mask = GFP_KERNEL | __GFP_ZERO;
	struct device *dev = &tdev->pdev->dev;
	struct spdm_message spdm_msg = { 0 };
	struct tmgr_message user_msg = { 0 };
	u64 addr;
	int ret;

	if (tmgr->spdm_owner != TMGR_SPDM_OWNER_USER)
		return -EBUSY;

	if (copy_from_user(&user_msg, arg, sizeof(user_msg)))
		return -EFAULT;

	if (!user_msg.req_size || !user_msg.resp_size ||
	    !(user_msg.flags & SPDM_MSG_FLAGS_DOE))
		return -EINVAL;

	spdm_msg.flags = user_msg.flags;
	spdm_msg.req_size = user_msg.req_size;
	spdm_msg.resp_size = user_msg.resp_size;

	addr = (u64)__get_free_pages(gfp_mask, get_order(user_msg.req_size));
	if (!addr)
		return -ENOMEM;
	spdm_msg.req_addr = addr;

	addr = (u64)__get_free_pages(gfp_mask, get_order(user_msg.resp_size));
	if (!addr) {
		ret = -ENOMEM;
		goto exit_free;
	}
	spdm_msg.resp_addr = addr;

	if (copy_from_user((void *)(unsigned long)spdm_msg.req_addr,
			   (void *)(unsigned long)user_msg.req_addr, user_msg.req_size)) {
		ret = -EFAULT;
		goto exit_free_all;
	}

	dev_dbg(dev, "TMGR: msg_exchange: flags %x req_size=%u, resp_size=%u\n",
		user_msg.flags, user_msg.req_size, user_msg.resp_size);

	/* as owner is USER now so it's OK to send spdm message directly */
	if (spdm_msg.flags & SPDM_MSG_FLAGS_SECURE)
		ret = spdm_session_msg_exchange(session, &spdm_msg);
	else
		ret = spdm_msg_exchange(session->spdm, &spdm_msg);

	if (ret) {
		dev_err(dev, "TMGR: msg_exchage: failed %d\n", ret);

		/* return -EFBIG if response buffer is not enough */
		ret = -EIO;
		goto exit_free_all;
	}

	if (copy_to_user((void *)(unsigned long)user_msg.resp_addr,
			 (void *)(unsigned long)spdm_msg.resp_addr, spdm_msg.resp_size)) {
		ret = -EINVAL;
		goto exit_free_all;
	}

exit_free_all:
	free_pages(spdm_msg.resp_addr, get_order(spdm_msg.resp_size));
exit_free:
	free_pages(spdm_msg.req_addr, get_order(spdm_msg.req_size));

	dev_dbg(dev, "TMGR: msg_exchange: ret=%d\n", ret);
	return ret;
}

static long tmgr_ioctl_set_eventfd(struct tdisp_mgr *tmgr, void __user *arg)
{
	struct tmgr_eventfd efd = { 0 };
	struct eventfd_ctx *ctx = NULL;

	if (copy_from_user(&efd, arg, sizeof(efd)))
		return -EFAULT;

	spin_lock(&tmgr->lock);
	ctx = tmgr->efd_ctx;
	tmgr->efd_ctx = NULL;
	spin_unlock(&tmgr->lock);
	if (ctx)
		eventfd_ctx_put(ctx);

	if (efd.fd >= 0) {
		ctx = eventfd_ctx_fdget(efd.fd);
		if (IS_ERR(ctx))
			return PTR_ERR(ctx);

		tmgr->efd_ctx = ctx;
		/*
		 * Re-send a eventfd signal for
		 * preventing missing any request
		 */
		if (!list_empty(&tmgr->pending_reqs))
			eventfd_signal(tmgr->efd_ctx, 1);
	}

	return 0;
}

static void tdisp_mgr_request_del(struct tdisp_mgr *tmgr,
				  struct tdisp_mgr_request *tmreq)
{
	spin_lock(&tmgr->lock);
	list_del(&tmreq->node);
	if (tmgr->efd_ctx && !list_empty(&tmgr->pending_reqs))
		eventfd_signal(tmgr->efd_ctx, 1);
	spin_unlock(&tmgr->lock);
}

static void tdisp_mgr_request_done(struct tdisp_mgr *tmgr,
				   struct tdisp_mgr_request *tmreq)
{
	struct device *dev = tmgr_to_dev(tmgr);

	tmreq->state = TDISP_MGR_REQ_STATE_COMPLETED;
	complete_all(&tmreq->complete);

	dev_dbg(dev, "%s: tmgr req %s done\n", __func__, tmreq_to_str(tmreq));
}

static void tdisp_mgr_request_fill(struct tdisp_mgr_request *tmreq)
{
	struct tdisp_mgr *tmgr = tmreq->tmgr;
	struct pci_tdisp_dev *tdev = tmgr->tdev;
	struct tmgr_request *treq = &tmreq->treq;
	struct pci_tdisp_dev_parm *parm = &tdev->parm;

	if (treq->request != TMGR_SESS_REQ_START_SESSION)
		return;

	treq->start_sess.meas_req_attr = parm->spdm_parm.meas_req_attr;
	treq->start_sess.session_policy = parm->session_parm.session_policy;
}

static struct tdisp_mgr_request *
tdisp_mgr_request_create(struct tdisp_mgr *tmgr, u8 request)
{
	struct spdm_session *session = tmgr_to_sess(tmgr);
	struct tdisp_mgr_request *tmreq;

	tmreq = kzalloc(sizeof(*tmreq), GFP_KERNEL);
	if (!tmreq)
		return NULL;

	tmreq->tmgr = tmgr;
	tmreq->treq.request = request;
	tmreq->treq.result = TMGR_REQ_RET_INVALID;
	tmreq->state = TDISP_MGR_REQ_STATE_INIT;
	tmreq->session_id = session->session_id;

	INIT_LIST_HEAD(&tmreq->node);
	init_completion(&tmreq->complete);

	tdisp_mgr_request_fill(tmreq);
	return tmreq;
}

static void tdisp_mgr_request_remove(struct tdisp_mgr_request *tmreq)
{
	kfree(tmreq);
}

static int tdisp_mgr_request_finish(struct tdisp_mgr *tmgr,
				    struct tdisp_mgr_request *tmreq)
{
	struct device *dev = tmgr_to_dev(tmgr);
	struct tmgr_request *treq = &tmreq->treq;
	int ret = 0;

	if (treq->result) {
		ret = -EIO;
		goto done;
	}

	switch (treq->request) {
	case TMGR_SESS_REQ_START_SESSION:
		if (!tmgr->dev_info.data) {
			dev_err(dev, "%s: finish %s without dev info\n",
				__func__, treq_to_str(treq));
			return -EFAULT;
		}
		break;
	}

done:
	dev_dbg(dev, "%s: finish %s result 0x%x\n", __func__,
		treq_to_str(treq), treq->result);
	return ret;
}

static void tdisp_mgr_request_queue(struct tdisp_mgr *tmgr,
				    struct tdisp_mgr_request *tmreq)
{
	struct device *dev = tmgr_to_dev(tmgr);
	bool notify = false;

	dev_dbg(dev, "%s: session %u tmgr req %s queued\n", __func__,
		tmreq->session_id, tmreq_to_str(tmreq));

	spin_lock(&tmgr->lock);
	if (list_empty(&tmgr->pending_reqs))
		notify = true;
	list_add_tail(&tmreq->node, &tmgr->pending_reqs);
	if (tmgr->efd_ctx && notify)
		eventfd_signal(tmgr->efd_ctx, 1);
	tmreq->state = TDISP_MGR_REQ_STATE_PENDING;
	spin_unlock(&tmgr->lock);
}

static int tdisp_mgr_request_wait_done(struct tdisp_mgr *tmgr,
				       struct tdisp_mgr_request *tmreq)
{
	struct device *dev = tmgr_to_dev(tmgr);
	long timeout = tmgr->req_timeout;
	int ret = 0;

	dev_dbg(dev, "%s: session %u tmgr req %s wait\n", __func__,
		tmreq->session_id, tmreq_to_str(tmreq));

	timeout = wait_for_completion_timeout(&tmreq->complete,
			msecs_to_jiffies(timeout));

	tdisp_mgr_request_del(tmgr, tmreq);

	/*
	 * Check request state firstly for handling timeout and
	 * request completed happened at the same time
	 */
	if (tmreq->state == TDISP_MGR_REQ_STATE_COMPLETED)
		ret = 0;
	else if (timeout == 0)
		ret = -ETIMEDOUT;
	else if (timeout < 0)
		ret = -EINTR;

	dev_dbg(dev, "%s: request done, ret %d\n", __func__, ret);
	return ret;
}

static long tmgr_ioctl_get_request(struct tdisp_mgr *tmgr, void __user *arg)
{
	struct device *dev = tmgr_to_dev(tmgr);
	struct tdisp_mgr_request *tmreq;
	struct tmgr_request treq;

	spin_lock(&tmgr->lock);
	tmreq = list_first_entry_or_null(&tmgr->pending_reqs,
					 struct tdisp_mgr_request,
					 node);
	if (!tmreq) {
		spin_unlock(&tmgr->lock);
		return -ENOENT;
	}
	if (tmreq->state == TDISP_MGR_REQ_STATE_HANDLING)
		dev_warn(dev, "%s: Request(%s) picked already picked\n",
			 __func__, tmreq_to_str(tmreq));

	tmreq->state = TDISP_MGR_REQ_STATE_HANDLING;
	/*
	 * tmreq is possible to be freed during calling copy_to_user(),
	 * using a local treq for copy_to_user().
	 */
	treq = tmreq->treq;
	spin_unlock(&tmgr->lock);

	if (copy_to_user(arg, &treq, sizeof(treq)))
		return -EFAULT;

	dev_dbg(dev, "%s: Request(%s) is picked by agent\n", __func__,
		tmreq_to_str(tmreq));
	return 0;
}

static long tmgr_ioctl_complete_request(struct tdisp_mgr *tmgr, void __user *arg)
{
	struct device *dev = tmgr_to_dev(tmgr);
	struct tmgr_request treq = { 0 };
	struct tdisp_mgr_request *tmreq;
	int ret = 0;

	if (copy_from_user(&treq, arg, sizeof(treq)))
		return -EFAULT;

	spin_lock(&tmgr->lock);
	tmreq = list_first_entry_or_null(&tmgr->pending_reqs,
					 struct tdisp_mgr_request,
					 node);
	if (!tmreq || tmreq->treq.request != treq.request) {
		dev_err(dev, "Received request(%s) vs Queued request(%s)\n",
			treq_to_str(&treq), tmreq_to_str(tmreq));
		ret = -EINVAL;
		goto exit;
	}

	tmreq->treq = treq;

	dev_dbg(dev, "%s: session %u tmgr req %s\n", __func__,
		tmreq->session_id, tmreq_to_str(tmreq));

	tdisp_mgr_request_done(tmgr, tmreq);

exit:
	spin_unlock(&tmgr->lock);

	return ret;
}

static long tmgr_ioctl_set_device_info(struct tdisp_mgr *tmgr, void __user *arg)
{
	struct device *dev = tmgr_to_dev(tmgr);
	struct tmgr_dev_info dev_info = { 0 };
	void *buf;

	if (copy_from_user(&dev_info, arg, sizeof(dev_info)))
		return -EFAULT;

	if (!dev_info.size)
		return -EINVAL;

	buf = vzalloc(dev_info.size);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, dev_info.data, dev_info.size)) {
		vfree(buf);
		return -EFAULT;
	}

	if (tmgr->dev_info.data) {
		dev_warn(dev, "%s: Device Info already set\n", __func__);
		vfree(tmgr->dev_info.data);
	}

	dev_dbg(dev, "%s: Agent sets Device Info done\n", __func__);
	tmgr->dev_info.data = buf;
	tmgr->dev_info.size = dev_info.size;
	return 0;
}

static long tmgr_ioctl_get_device_info_size(struct tdisp_mgr *tmgr,
					    void __user *addr)
{
	return put_user(tmgr->dev_info.size, (__u32 __user *)addr);
}

static long tmgr_ioctl_get_device_info(struct tdisp_mgr *tmgr,
				       void __user *addr)
{
	if (!tmgr->dev_info.data)
		return -ENODEV;

	return copy_to_user(addr, tmgr->dev_info.data, tmgr->dev_info.size);
}

static long tmgr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct tdisp_mgr *tmgr = file_to_tmgr(file);

	switch (cmd) {
	case TDISP_MGR_GET_API_VERSION:
		return TDISP_MGR_API_VERSION;
	case TDISP_MGR_GET_INFO:
		return tmgr_ioctl_get_info(tmgr, (void __user *)arg);
	case TDISP_MGR_MSG_EXCHANGE:
		return tmgr_ioctl_msg_exchange(tmgr, (void __user *)arg);
	case TDISP_MGR_SET_EVENTFD:
		return tmgr_ioctl_set_eventfd(tmgr, (void __user *)arg);
	case TDISP_MGR_GET_REQUEST:
		return tmgr_ioctl_get_request(tmgr, (void __user *)arg);
	case TDISP_MGR_COMPLETE_REQUEST:
		return tmgr_ioctl_complete_request(tmgr, (void __user *)arg);
	case TDISP_MGR_SET_DEVICE_INFO:
		return tmgr_ioctl_set_device_info(tmgr, (void __user *)arg);
	case TDISP_MGR_GET_DEVICE_INFO_SIZE:
		return tmgr_ioctl_get_device_info_size(tmgr, (void __user *)arg);
	case TDISP_MGR_GET_DEVICE_INFO:
		return tmgr_ioctl_get_device_info(tmgr, (void __user *)arg);
	}

	return -EINVAL;
}

static const struct file_operations tdisp_mgr_ops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= tmgr_ioctl,
};

static int tdisp_mgr_get_spdm(struct tdisp_mgr *tmgr, int budget)
{
	struct spdm_session *session = tmgr_to_sess(tmgr);
	int ret;

	spdm_msg_exchange_prepare(session->spdm);
	ret = spdm_session_msg_exchange_prepare(session, budget);
	if (ret)
		spdm_msg_exchange_complete(session->spdm);

	return ret;
}

static void tdisp_mgr_put_spdm(struct tdisp_mgr *tmgr)
{
	struct spdm_session *session = tmgr_to_sess(tmgr);

	spdm_session_msg_exchange_complete(session);
	spdm_msg_exchange_complete(session->spdm);
}

static void tdisp_mgr_set_spdm_owner(struct tdisp_mgr *tmgr, unsigned int owner)
{
	tmgr->spdm_owner = owner;
	dev_dbg(tmgr_to_dev(tmgr), "%s: owner to %d\n", __func__, tmgr->spdm_owner);
}

/*
 * Life cycle of tdisp_mgr_request.
 *
 * tdisp_mgr_request_create (INIT)
 * tdisp_mgr_request_queue (PENDING, in queue)
 *   tmgr_ioctl_get_request (HANDLING, in queue) -> picked by agent
 * tdisp_mgr_request_wait_done
 *   tmgr_ioctl_complete_request (COMPLETE) <- completed by agent, fill result
 *   tdisp_mgr_request_finish (FINISHED) <- finish result handling
 * tdisp_mgr_request_remove
 */
static int tdisp_mgr_request_process_sync(struct tdisp_mgr *tmgr, u8 request)
{
	struct device *dev = tmgr_to_dev(tmgr);
	struct tdisp_mgr_request *tmreq;
	int ret;

	dev_dbg(dev, "%s req = %u\n", __func__, request);

	tmreq = tdisp_mgr_request_create(tmgr, request);
	if (!tmreq)
		return -ENOMEM;

	dev_dbg(dev, "%s request create\n", __func__);
	tdisp_mgr_request_queue(tmgr, tmreq);
	dev_dbg(dev, "%s request queued\n", __func__);

	/*
	 * return error if request is not processed in time
	 *
	 * 1 timeout - request is not picked by agent
	 * 2 timeout - request is picked by agent
	 *
	 * anyway remove request from queue, and remove request directly
	 */
	ret = tdisp_mgr_request_wait_done(tmgr, tmreq);
	if (ret)
		goto done;

	dev_dbg(dev, "%s request wait done\n", __func__);
	/*
	 * if requeset completed in time, then handle it and move it
	 * to finished state.
	 */
	ret = tdisp_mgr_request_finish(tmgr, tmreq);
	dev_dbg(dev, "%s request finish %d\n", __func__, ret);
done:
	tdisp_mgr_request_remove(tmreq);
	return ret;
}

static void tdisp_mgr_set_session_state(struct tdisp_mgr *tmgr, int state)
{
	struct pci_tdisp_dev *tdev = tmgr->tdev;
	struct spdm_session *session = tdev->session;
	struct device *dev = tmgr_to_dev(tmgr);

	spdm_session_set_state(session, state);

	dev_dbg(dev, "spdm session state: %d\n", state);
}

#define dwork_to_tmgr(x) container_of((x), struct tdisp_mgr, sess_hbeat_dwork)
static void tdisp_mgr_sess_hbeat_timeout(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct tdisp_mgr *tmgr = dwork_to_tmgr(dwork);
	struct pci_tdisp_dev *tdev = tmgr->tdev;
	unsigned long delay = tdev->session->heartbeat_period * HZ;
	struct device *dev = tmgr_to_dev(tmgr);
	int ret;

	dev_dbg(dev, "%s\n", __func__);

	/* heartbeat requires only 1 session budget */
	ret = tdisp_mgr_get_spdm(tmgr, 1);
	if (ret) {
		dev_err(dev, "fail to get budget for heartbeat %d\n", ret);
		return;
	}

	tdisp_mgr_set_spdm_owner(tmgr, TMGR_SPDM_OWNER_USER);

	ret = tdisp_mgr_request_process_sync(tmgr, TMGR_SESS_REQ_HEARTBEAT);
	if (ret)
		tdisp_mgr_set_session_state(tmgr, SPDM_SESS_STATE_ERROR);
	else
		schedule_delayed_work(&tmgr->sess_hbeat_dwork, delay);

	tdisp_mgr_set_spdm_owner(tmgr, TMGR_SPDM_OWNER_KERNEL);
	tdisp_mgr_put_spdm(tmgr);

	dev_dbg(dev, "%s ------>\n", __func__);
}

static DEFINE_IDA(tdisp_mgr_ida);

static struct tdisp_mgr *tdisp_mgr_create(struct pci_tdisp_dev *tdev)
{
	struct spdm *spdm = tdev->spdm;
	struct tdisp_mgr *tmgr;
	int id;

	/* do necessary checking before create tdisp-mgr */
	if (!(spdm->flags & SPDM_FLAGS_TEE))
		return ERR_PTR(-EINVAL);

	tmgr = kzalloc(sizeof(*tmgr), GFP_KERNEL);
	if (!tmgr)
		return ERR_PTR(-ENOMEM);

	id = ida_simple_get(&tdisp_mgr_ida, 0, 0, GFP_KERNEL);
	if (id < 0) {
		kfree(tmgr);
		return ERR_PTR(id);
	}

	tmgr->id = id;
	snprintf(tmgr->name, sizeof(tmgr->name), "tdisp_mgr%d", tmgr->id);
	INIT_DELAYED_WORK(&tmgr->sess_hbeat_dwork, tdisp_mgr_sess_hbeat_timeout);
	INIT_LIST_HEAD(&tmgr->pending_reqs);
	tmgr->tdev = tdev;
	spin_lock_init(&tmgr->lock);
	tmgr->req_timeout = request_timeout;
	tdev->priv = tmgr;
	return tmgr;
};

static void tdisp_mgr_remove(struct tdisp_mgr *tmgr)
{
	if (tmgr->dev_info.data)
		vfree(tmgr->dev_info.data);
	ida_simple_remove(&tdisp_mgr_ida, tmgr->id);
	kfree(tmgr);
}

static DEFINE_IDA(session_idx_ida);

#define idx_start(iommu_id)	((iommu_id) * SESSION_PER_IOMMU)
#define idx_end(iommu_id)	(idx_start(iommu_id) + SESSION_PER_IOMMU - 1)

static int tdisp_mgr_session_idx_alloc(u16 iommu_id, u16 *session_idx)
{
	int idx;

	idx = ida_alloc_range(&session_idx_ida, idx_start(iommu_id),
			      idx_end(iommu_id), GFP_KERNEL);
	if (idx < 0)
		return idx;

	*session_idx = idx - idx_start(iommu_id);
	return 0;
}

static void tdisp_mgr_session_idx_free(u16 iommu_id, u16 session_idx)
{
	ida_free(&session_idx_ida, idx_start(iommu_id) + session_idx);
}

static int get_iommu_id(struct device *dev, u16 *iommu_id)
{
	struct iommu_hw_info_vtd info;
	int ret;

	ret = iommu_get_hw_info(dev, IOMMU_HW_INFO_TYPE_INTEL_VTD,
				(void *)&info, sizeof(struct iommu_hw_info_vtd));
	if (ret)
		return ret;

	*iommu_id = (u16)info.id;
	return 0;
}

static int tdisp_mgr_spdm_msg_exchange(struct spdm *spdm, struct spdm_message *msg)
{
	struct pci_doe_mb *doe_mb = spdm->priv;

	return pci_doe_msg_exchange_sync(doe_mb, (void *)(unsigned long)msg->req_addr,
					 (void *)(unsigned long)msg->resp_addr, msg->resp_size);
}

static int tdisp_mgr_session_msg_exchange(struct spdm_session *session,
					  struct spdm_message *msg)
{
	struct tdisp_mgr *tmgr = session->priv;
	struct device *dev = tmgr_to_dev(tmgr);
	struct pci_tdisp_dev *tdev = tmgr->tdev;
	int ret;

	ret = pci_doe_msg_exchange_sync(tdev->sec_doe_mb, (void *)(unsigned long)msg->req_addr,
					(void *)(unsigned long)msg->resp_addr, msg->resp_size);
	if (ret)
		return ret;

	dev_dbg(dev, "session seq_num %llx\n", atomic64_read(&session->seq_num));

	return ret;
}

static int tdisp_mgr_session_keyupdate(struct spdm_session *session)
{
	struct tdisp_mgr *tmgr = session->priv;
	struct device *dev = tmgr_to_dev(tmgr);
	int ret;

	dev_dbg(dev, "%s\n", __func__);

	tdisp_mgr_set_spdm_owner(tmgr, TMGR_SPDM_OWNER_USER);

	ret = tdisp_mgr_request_process_sync(tmgr, TMGR_SESS_REQ_KEYUPDATE);
	if (ret)
		tdisp_mgr_set_session_state(tmgr, SPDM_SESS_STATE_ERROR);

	tdisp_mgr_set_spdm_owner(tmgr, TMGR_SPDM_OWNER_KERNEL);

	dev_dbg(dev, "%s ------>\n", __func__);
	return ret;
}

static int tdisp_mgr_spdm_setup(struct tdisp_mgr *tmgr)
{
	struct pci_tdisp_dev *tdev = tmgr->tdev;
	struct device *dev = &tdev->pdev->dev;
	struct spdm_session *session = tdev->session;
	struct spdm *spdm = tdev->spdm;
	u16 iommu_id, session_idx;
	unsigned long va;
	u64 retval;
	int ret;

	ret = get_iommu_id(dev, &iommu_id);
	if (ret) {
		dev_err(dev, "%s: Get iommu id failed %d\n", __func__, ret);
		return ret;
	}

	ret = tdisp_mgr_session_idx_alloc(iommu_id, &session_idx);
	if (ret) {
		dev_err(dev, "%s: Alloc session idx failed %d\n", __func__, ret);
		return ret;
	}

	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va) {
		ret = -ENOMEM;
		dev_err(dev, "%s: Alloc td page failed %d\n", __func__, ret);
		goto exit_idx_free;
	}

	retval = tdh_spdm_create(iommu_id, session_idx, __pa(va));
	if (retval) {
		ret = -EFAULT;
		goto exit_reclaim_page;
	}

	tmgr->iommu_id = iommu_id;
	tmgr->session_idx = session_idx;
	tmgr->session_page_pa = __pa(va);

	spdm->msg_exchange = tdisp_mgr_spdm_msg_exchange;
	session->msg_exchange = tdisp_mgr_session_msg_exchange;
	session->keyupdate = tdisp_mgr_session_keyupdate;
	session->priv = tmgr;
	return 0;

exit_reclaim_page:
	free_page(va);
exit_idx_free:
	tdisp_mgr_session_idx_free(iommu_id, session_idx);
	return ret;
}

static int tdisp_mgr_spdm_session_complete(struct tdisp_mgr *tmgr)
{
	struct pci_tdisp_dev *tdev = tmgr->tdev;
	struct spdm_session *session = tdev->session;
	struct device *dev = &tdev->pdev->dev;
	u64 spdm_info_pa, retval;

	session->priv = NULL;

	retval = tdh_spdm_delete(tmgr->iommu_id, tmgr->session_idx, &spdm_info_pa);

	dev_dbg(dev, "%s: iommu_id=%d, session_idx=%d, pa=0x%llx (original:0x%lx), ret=0x%llx\n",
		__func__, tmgr->iommu_id, tmgr->session_idx, spdm_info_pa,
		tmgr->session_page_pa, retval);

	if (retval)
		return -EFAULT;

	/* TODO: WIP on discuss whether reclaim is needed */
//	tdx_reclaim_td_page(tmgr->session_page_pa);
	free_page((unsigned long)__va(tmgr->session_page_pa));
	tdisp_mgr_session_idx_free(tmgr->iommu_id, tmgr->session_idx);
	return 0;
}

static void tdisp_mgr_update(struct tdisp_mgr *tmgr)
{
	struct dev_tdisp_info *info = &tmgr->data.tdisp_info;
	struct pci_tdisp_dev *tdev = tmgr->tdev;

	tdev->version		       = info->tdisp_version;
	tdev->cap.dsm_caps	       = info->dsm_caps;
	tdev->cap.req_msgs_supported_l = info->req_msgs_supported_l;
	tdev->cap.req_msgs_supported_h = info->req_msgs_supported_h;
	tdev->cap.lock_flags_supported = info->lock_flags_supported;
	tdev->cap.dev_addr_width       = info->dev_addr_width;
	tdev->cap.num_req_this         = info->num_req_this;
	tdev->cap.num_req_all          = info->num_req_all;
}

static void tdisp_mgr_update_spdm(struct tdisp_mgr *tmgr)
{
	struct spdm *spdm = tmgr->tdev->spdm;
	struct dev_spdm_info *info = &tmgr->data.spdm_info;
	struct dev_spdm_cert *cert = &tmgr->data.spdm_cert;
	struct dev_spdm_meas *meas = &tmgr->data.spdm_meas;

	/* Connect Info */
	spdm->version             = info->spdm_version;
	spdm->ctexponent          = info->ctexponent;
	spdm->capability_flags    = info->capability_flags;
	spdm->data_trans_size     = info->data_trans_size;
	spdm->max_spdm_msg_size   = info->max_spdm_msg_size;
	spdm->meas_spec           = info->meas_spec;
	spdm->other_parm_support  = info->other_parm_support;
	spdm->meas_hash_algo      = info->meas_hash_algo;
	spdm->base_hash_algo      = info->base_hash_algo;
	spdm->base_asym_algo      = info->base_asym_algo;
	spdm->dhe_algo            = info->dhe_algo;
	spdm->aead_algo           = info->aead_algo;
	spdm->key_schedule_algo   = info->key_schedule_algo;

	/* SPDM Certificates */
	for (int i = 0; i < SPDM_CERT_NUM; ++i) {
		spdm->certs[i].size = cert->certs[i].size;
		spdm->certs[i].data = cert->certs[i].data;
	}

	/* SPDM Measurement */
	spdm->meas_cap            = meas->meas_cap;
	spdm->meas_req_attr       = meas->meas_req_attr;
	spdm->meas_resp_attr      = meas->meas_resp_attr;
	spdm->all_meas_block_size = meas->all_meas_block_size;
	spdm->all_meas_block      = meas->all_meas_block;

	/* Move state to CONNECT */
	spdm->state = SPDM_STATE_CONNECT;
}

static void tdisp_mgr_update_session_info(struct tdisp_mgr *tmgr)
{
	struct pci_tdisp_dev *tdev = tmgr->tdev;
	struct dev_spdm_info *info = &tmgr->data.spdm_info;
	struct spdm_session *session = tdev->session;
	unsigned long delay;

	session->version          = info->spdm_secure_version;
	session->session_id       = info->session_id;
	session->heartbeat_period = info->heartbeat_period;

	/*
	 * start housekeeping work for heartbeat
	 */
	if (is_spdm_hbeat_required(session)) {
		/* real heartbeat timeout is 2 * heartbeat_period */
		delay = session->heartbeat_period * HZ;
		schedule_delayed_work(&tmgr->sess_hbeat_dwork, delay);
	}
}

static int tdisp_mgr_start(struct tdisp_mgr *tmgr)
{
	struct device *dev = tmgr_to_dev(tmgr);
	int ret;

	dev_dbg(dev, "%s --------> %p\n", __func__, tmgr);

	/* always assume enough budget for start session operation */
	ret = tdisp_mgr_get_spdm(tmgr, 0);
	if (ret) {
		dev_err(dev, "fail to get spdm for start session %d\n", ret);
		return ret;
	}

	tdisp_mgr_set_spdm_owner(tmgr, TMGR_SPDM_OWNER_USER);

	tdisp_mgr_set_session_state(tmgr, SPDM_SESS_STATE_SETUP);

	/*
	 * START_SESSION to TPA
	 *
	 * 1 Connect SPDM
	 * 2 Establish SPDM session
	 * 3 TDISP version/capability negotiation
	 */
	ret = tdisp_mgr_request_process_sync(tmgr, TMGR_SESS_REQ_START_SESSION);
	if (ret) {
		tdisp_mgr_set_session_state(tmgr, SPDM_SESS_STATE_ERROR);
		goto done;
	}

	dev_dbg(dev, "%s: request process done\n", __func__);

	parse_tpa_dev_info_data(&tmgr->data, tmgr->dev_info.data);

	/*
	 * START_SESSION complete, DEV_INFO returned from TPA.
	 *
	 * 1 Update SPDM Connection Information
	 * 2 Update SPDM Session Information
	 * 3 Update TDISP Information
	 */
	tdisp_mgr_update_spdm(tmgr);
	tdisp_mgr_update_session_info(tmgr);
	tdisp_mgr_set_session_state(tmgr, SPDM_SESS_STATE_READY);
	tdisp_mgr_update(tmgr);

done:
	/* Switch owner back to Kernel (TDX module) */
	tdisp_mgr_set_spdm_owner(tmgr, TMGR_SPDM_OWNER_KERNEL);
	tdisp_mgr_put_spdm(tmgr);
	dev_dbg(dev, "%s <---------- done %d\n", __func__, ret);
	return ret;
}

static void tdisp_mgr_stop(struct tdisp_mgr *tmgr)
{
	struct device *dev = tmgr_to_dev(tmgr);
	int ret;

	dev_dbg(dev, "%s\n", __func__);

	/* stop heartbeat for end session */
	if (delayed_work_pending(&tmgr->sess_hbeat_dwork))
		cancel_delayed_work(&tmgr->sess_hbeat_dwork);

	ret = tdisp_mgr_get_spdm(tmgr, 1);
	if (ret) {
		dev_err(dev, "fail to get budget for end session %d\n", ret);
		return;
	}

	tdisp_mgr_set_spdm_owner(tmgr, TMGR_SPDM_OWNER_USER);

	ret = tdisp_mgr_request_process_sync(tmgr, TMGR_SESS_REQ_END_SESSION);
	if (ret) {
		dev_err(dev, "Fail to end session\n");
		tdisp_mgr_set_session_state(tmgr, SPDM_SESS_STATE_ERROR);
	} else {
		tdisp_mgr_set_session_state(tmgr, SPDM_SESS_STATE_NONE);
	}

	tdisp_mgr_set_spdm_owner(tmgr, TMGR_SPDM_OWNER_KERNEL);
	tdisp_mgr_put_spdm(tmgr);

	dev_dbg(dev, "%s <---------- done\n", __func__);
}

int pci_arch_tdisp_dev_init(struct pci_tdisp_dev *tdev)
{
	struct tdisp_mgr *tmgr;
	int ret;

	cpus_read_lock();
	ret = cpu_vmxop_get_all();
	if (ret)
		goto exit_vmxoff;

	ret = pci_arch_tdisp_dev_tee_enter(tdev);
	if (ret)
		goto exit_vmxoff;

	tmgr = tdisp_mgr_create(tdev);
	if (!tmgr) {
		ret = -ENOMEM;
		goto exit_tee_exit;
	}

	ret = tdisp_mgr_spdm_setup(tmgr);
	if (ret)
		goto exit_tmgr_free;

	tmgr->miscdev.minor = MISC_DYNAMIC_MINOR;
	tmgr->miscdev.name = tmgr->name;
	tmgr->miscdev.fops = &tdisp_mgr_ops;
	tmgr->miscdev.parent = &tdev->pdev->dev;

	/*
	 * create device node for userspace agent before
	 * conversation with target device.
	 */
	ret = misc_register(&tmgr->miscdev);
	if (ret)
		goto exit_session_cleanup;

	/*
	 * do initialization for SPDM / SPDM session / TDISP protocol.
	 */
	ret = tdisp_mgr_start(tmgr);
	if (ret)
		goto exit_misc_deregister;

	return ret;

exit_misc_deregister:
	misc_deregister(&tmgr->miscdev);
exit_session_cleanup:
	tdisp_mgr_spdm_session_complete(tmgr);
exit_tmgr_free:
	tdisp_mgr_remove(tmgr);
exit_tee_exit:
	pci_arch_tdisp_dev_tee_exit(tdev);
exit_vmxoff:
	cpu_vmxop_put_all();
	cpus_read_unlock();
	return ret;
}

void pci_arch_tdisp_dev_uinit(struct pci_tdisp_dev *tdev)
{
	struct tdisp_mgr *tmgr = tdev->priv;

	tdev->priv = NULL;
	tdisp_mgr_stop(tmgr);
	misc_deregister(&tmgr->miscdev);
	tdisp_mgr_spdm_session_complete(tmgr);
	tdisp_mgr_remove(tmgr);
	pci_arch_tdisp_dev_tee_exit(tdev);

	cpus_read_lock();
	cpu_vmxop_put_all();
	cpus_read_unlock();
}

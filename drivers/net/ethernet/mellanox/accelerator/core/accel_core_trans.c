/*
 * Copyright (c) 2015-2016 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include "accel_core_trans.h"

static struct mlx_accel_transaction_private *
mlx_accel_find_tid(struct mlx_accel_core_device *accel_device, u8 tid)
{
	if (tid >= MLX_ACCEL_TID_COUNT) {
		pr_warn("Unexpected transaction ID %u\n", tid);
		return NULL;
	}
	return &accel_device->trans->transactions[tid];
}

static struct mlx_accel_transaction_private *
mlx_accel_alloc_tid(struct mlx_accel_core_device *accel_device)
{
	struct mlx_accel_transaction_private *ret;
	unsigned long flags;

	spin_lock_irqsave(&accel_device->trans->lock, flags);

	if (list_empty(&accel_device->trans->free_queue)) {
		pr_info("***** No free transaction ID available!");
		ret = NULL;
		goto out;
	}

	ret = container_of(accel_device->trans->free_queue.next,
			   struct mlx_accel_transaction_private, list_item);
	list_del(&ret->list_item);

	ret->state = TRANS_STATE_NONE;
out:
	spin_unlock_irqrestore(&accel_device->trans->lock, flags);
	return ret;
}

static void mlx_accel_free_tid(struct mlx_accel_core_device *accel_device,
			       struct mlx_accel_transaction_private *trans_priv)
{
	unsigned long flags;

	spin_lock_irqsave(&accel_device->trans->lock, flags);
	list_add_tail(&trans_priv->list_item,
		      &accel_device->trans->free_queue);
	spin_unlock_irqrestore(&accel_device->trans->lock, flags);
}

static void
mlx_accel_trans_complete(struct mlx_accel_transaction_private *trans_priv,
			 enum ib_wc_status status)
{
	unsigned long flags;
	struct mlx_accel_trans_device_state *trans;
	const struct mlx_accel_transaction *user_trans;

	pr_debug("Transaction %u is complete with status %u\n",
		 trans_priv->tid, status);
	trans = trans_priv->user_trans->conn->accel_device->trans;
	spin_lock_irqsave(&trans->lock, flags);
	trans_priv->state = TRANS_STATE_COMPLETE;
	trans_priv->status = status;
	spin_unlock_irqrestore(&trans->lock, flags);

	user_trans = trans_priv->user_trans;
	mlx_accel_free_tid(trans_priv->user_trans->conn->accel_device,
			   trans_priv);

	if (user_trans->complete)
		user_trans->complete(user_trans, status);
}

static void mlx_accel_trans_send_complete(struct mlx_accel_core_conn *conn,
					  struct mlx_accel_core_dma_buf *buf,
					  struct ib_wc *wc)
{
	unsigned long flags;
	struct mlx_accel_transaction_private *trans_priv;

	pr_debug("mlx_accel_trans_send_complete. Status: %u\n", wc->status);
	trans_priv = container_of(buf, struct mlx_accel_transaction_private,
				  buf);
	if (wc->status != IB_WC_SUCCESS) {
		mlx_accel_trans_complete(trans_priv, wc->status);
		return;
	}

	spin_lock_irqsave(&conn->accel_device->trans->lock, flags);
	if (trans_priv->state == TRANS_STATE_SEND)
		trans_priv->state = TRANS_STATE_WAIT;
	spin_unlock_irqrestore(&conn->accel_device->trans->lock, flags);
}

int mlx_accel_trans_validate(struct mlx_accel_core_device *accel_device,
			     u64 addr, size_t size)
{
	if (size > MLX_ACCEL_TRANSACTION_MAX_SIZE) {
		pr_info("Cannot access %lu bytes at once. Max is %u\n",
			size, MLX_ACCEL_TRANSACTION_MAX_SIZE);
		return -EINVAL;
	}
	if (size & MLX_ACCEL_TRANSACTION_SEND_ALIGN_BITS) {
		pr_info("Cannot access %lu bytes. Must be full dwords\n",
			size);
		return -EINVAL;
	}
	if (size < 1) {
		pr_info("Cannot access %lu bytes. Empty transaction not allowed\n",
			size);
		return -EINVAL;
	}
	if (addr & MLX_ACCEL_TRANSACTION_SEND_ALIGN_BITS) {
		pr_info("Cannot access %lu bytes at unaligned address %llx\n",
			size, addr);
		return -EINVAL;
	}
	if ((addr >> MLX_ACCEL_TRANSACTION_SEND_PAGE_BITS) !=
	    ((addr + size - 1) >> MLX_ACCEL_TRANSACTION_SEND_PAGE_BITS)) {
		pr_info("Cannot access %lu bytes at address %llx. Crosses page boundary\n",
			size, addr);
		return -EINVAL;
	}
	if (addr < mlx_accel_core_ddr_base_get(accel_device)) {
		if (size != sizeof(u32)) {
			pr_info("Cannot access %lu bytes at cr-space address %llx. Must access a single dword\n",
				size, addr);
			return -EINVAL;
		}
	}
	return 0;
}

int mlx_accel_trans_exec(const struct mlx_accel_transaction *transaction)
{
	int rc;
	struct mlx_accel_core_conn *conn = transaction->conn;
	struct mlx_accel_transaction_private *trans_priv = NULL;

	if (!transaction->complete) {
		pr_warn("Transaction must have a completion callback\n");
		rc = -EINVAL;
		goto out;
	}

	rc = mlx_accel_trans_validate(conn->accel_device,
				      transaction->addr, transaction->size);
	if (rc)
		goto out;

	trans_priv = mlx_accel_alloc_tid(conn->accel_device);
	if (!trans_priv) {
		rc = -EBUSY;
		goto out;
	}
	trans_priv->user_trans = transaction;

	memset(&trans_priv->header, 0, sizeof(trans_priv->header));
	memset(&trans_priv->buf, 0, sizeof(trans_priv->buf));
	MLX5_SET(fpga_shell_qp_packet, trans_priv->header, type,
		 (transaction->direction == MLX_ACCEL_WRITE) ?
		 MLX5_FPGA_MSG_WRITE : MLX5_FPGA_MSG_READ);
	MLX5_SET(fpga_shell_qp_packet, trans_priv->header, tid,
		 trans_priv->tid);
	MLX5_SET(fpga_shell_qp_packet, trans_priv->header, len,
		 transaction->size);
	MLX5_SET(fpga_shell_qp_packet, trans_priv->header, address_h,
		 transaction->addr >> 32);
	MLX5_SET(fpga_shell_qp_packet, trans_priv->header, address_l,
		 transaction->addr & 0xFFFFFFFF);

	trans_priv->buf.data = &trans_priv->header;
	trans_priv->buf.data_size = sizeof(trans_priv->header);
	if (transaction->direction == MLX_ACCEL_WRITE) {
		trans_priv->buf.more = transaction->data;
		trans_priv->buf.more_size = transaction->size;
	}

	trans_priv->buf.complete = mlx_accel_trans_send_complete;
	trans_priv->state = TRANS_STATE_SEND;

	rc = mlx_accel_core_rdma_post_send(conn, &trans_priv->buf);
	if (rc)
		goto out_buf_tid;
	goto out;

out_buf_tid:
	mlx_accel_free_tid(conn->accel_device, trans_priv);
out:
	return rc;
}

void mlx_accel_trans_recv(void *cb_arg, struct mlx_accel_core_dma_buf *buf)
{
	struct mlx_accel_core_device *accel_device = cb_arg;
	struct mlx_accel_transaction_private *trans_priv;
	size_t payload_len;
	enum ib_wc_status status = IB_WC_SUCCESS;

	pr_debug("Rx QP message on %s core conn; %ld bytes\n",
		 accel_device->name, buf->data_size);

	if (buf->data_size < MLX5_ST_SZ_BYTES(fpga_shell_qp_packet)) {
		pr_warn("Short message %lu bytes from device\n",
			buf->data_size);
		goto out;
	}
	payload_len = buf->data_size - MLX5_ST_SZ_BYTES(fpga_shell_qp_packet);

	trans_priv = mlx_accel_find_tid(accel_device,
					MLX5_GET(fpga_shell_qp_packet,
						 buf->data, tid));
	if (!trans_priv)
		goto out;

	/* Note: header addr and len are always 0 */
	switch (MLX5_GET(fpga_shell_qp_packet, buf->data, type)) {
	case MLX5_FPGA_MSG_READ_RESPONSE:
		if (trans_priv->user_trans->direction != MLX_ACCEL_READ) {
			pr_warn("Wrong answer type %u to a %u transaction\n",
				MLX5_GET(fpga_shell_qp_packet, buf->data, type),
				trans_priv->user_trans->direction);
			status = IB_WC_BAD_RESP_ERR;
			goto complete;
		}
		if (payload_len != trans_priv->user_trans->size) {
			pr_warn("Incorrect transaction payload length %lu expected %lu\n",
				payload_len, trans_priv->user_trans->size);
			goto complete;
		}
		memcpy(trans_priv->user_trans->data,
		       MLX5_ADDR_OF(fpga_shell_qp_packet, buf->data, data),
		       payload_len);
		break;
	case MLX5_FPGA_MSG_WRITE_RESPONSE:
		if (trans_priv->user_trans->direction != MLX_ACCEL_WRITE) {
			pr_warn("Wrong answer type %u to a %u transaction\n",
				MLX5_GET(fpga_shell_qp_packet, buf->data, type),
				trans_priv->user_trans->direction);
			status = IB_WC_BAD_RESP_ERR;
			goto complete;
		}
		break;
	default:
		pr_warn("Unexpected message type %u len %lu from device\n",
			MLX5_GET(fpga_shell_qp_packet, buf->data, type),
			buf->data_size);
		status = IB_WC_BAD_RESP_ERR;
		goto complete;
	}

complete:
	mlx_accel_trans_complete(trans_priv, status);
out:
	return;
}

int mlx_accel_trans_device_init(struct mlx_accel_core_device *accel_device)
{
	int ret = 0;
	int tid;

	accel_device->trans = kzalloc(sizeof(*accel_device->trans), GFP_KERNEL);
	if (!accel_device->trans) {
		ret = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&accel_device->trans->free_queue);
	for (tid = 0; tid < MLX_ACCEL_TID_COUNT; tid++) {
		accel_device->trans->transactions[tid].tid = tid;
		list_add_tail(&accel_device->trans->transactions[tid].list_item,
			      &accel_device->trans->free_queue);
	}

	spin_lock_init(&accel_device->trans->lock);

out:
	return ret;
}

void mlx_accel_trans_device_deinit(struct mlx_accel_core_device *accel_device)
{
	kfree(accel_device->trans);
}


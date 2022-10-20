/**
 * (C) Copyright 2016-2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#include "dfuse_common.h"
#include "dfuse.h"

static void
dfuse_cb_write_complete(struct dfuse_event *ev)
{
	if (ev->de_ev.ev_error == 0)
		DFUSE_REPLY_WRITE(ev->de_oh, ev->de_req, ev->de_len);
	else
		DFUSE_REPLY_ERR_RAW(ev->de_oh, ev->de_req, ev->de_ev.ev_error);
	D_FREE(ev->de_iov.iov_buf);
}

void
dfuse_cb_write(fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec *bufv,
	       off_t position, struct fuse_file_info *fi)
{
	struct dfuse_obj_hdl         *oh        = (struct dfuse_obj_hdl *)fi->fh;
	struct dfuse_projection_info *fs_handle = fuse_req_userdata(req);
	const struct fuse_ctx        *fc        = fuse_req_ctx(req);
	size_t                        len       = fuse_buf_size(bufv);
	struct fuse_bufvec            ibuf      = FUSE_BUFVEC_INIT(len);
	struct dfuse_eq              *eqt;
	int                           rc;
	struct dfuse_event           *ev;
	uint64_t                      eqt_idx;

	eqt_idx = atomic_fetch_add_relaxed(&fs_handle->dpi_eqt_idx, 1);

	eqt = &fs_handle->dpi_eqt[eqt_idx % fs_handle->dpi_eqt_count];

	DFUSE_TRA_DEBUG(oh, "%#zx-%#zx requested flags %#x pid=%d",
			position, position + len - 1,
			bufv->buf[0].flags, fc->pid);

	if (atomic_fetch_add_relaxed(&oh->doh_write_count, 1) == 0) {
		if (atomic_fetch_add_relaxed(&oh->doh_ie->ie_open_write_count, 1) == 0) {
			dfuse_cache_evict(oh->doh_ie);
		}
	}

	D_ALLOC_PTR(ev);
	if (ev == NULL)
		D_GOTO(err, rc = ENOMEM);

	/* Declare a bufvec on the stack and have fuse copy into it.
	 * For page size and above this will read directly into the
	 * buffer, avoiding any copying of the data.
	 */
	D_ALLOC(ibuf.buf[0].mem, len);
	if (ibuf.buf[0].mem == NULL)
		D_GOTO(err, rc = ENOMEM);

	rc = fuse_buf_copy(&ibuf, bufv, 0);
	if (rc != len)
		D_GOTO(err, rc = EIO);

	rc = daos_event_init(&ev->de_ev, eqt->de_eq, NULL);
	if (rc != -DER_SUCCESS)
		D_GOTO(err, rc = daos_der2errno(rc));

	ev->de_oh          = oh;
	ev->de_req         = req;
	ev->de_len         = len;
	ev->de_complete_cb = dfuse_cb_write_complete;

	ev->de_sgl.sg_nr = 1;
	d_iov_set(&ev->de_iov, ibuf.buf[0].mem, len);
	ev->de_sgl.sg_iovs = &ev->de_iov;

	/* Check for potentially using readahead on this file, ie_truncated
	 * will only be set if caching is enabled so only check for the one
	 * flag rather than two here
	 */
	if (oh->doh_ie->ie_truncated) {
		if (oh->doh_ie->ie_start_off == 0 &&
		    oh->doh_ie->ie_end_off == 0) {
			oh->doh_ie->ie_start_off = position;
			oh->doh_ie->ie_end_off = position + len;
		} else {
			if (oh->doh_ie->ie_start_off > position)
				oh->doh_ie->ie_start_off = position;
			if (oh->doh_ie->ie_end_off < position + len)
				oh->doh_ie->ie_end_off = position + len;
		}
	}

	if (len + position > oh->doh_ie->ie_stat.st_size)
		oh->doh_ie->ie_stat.st_size = len + position;

	rc = dfs_write(oh->doh_dfs, oh->doh_obj, &ev->de_sgl, position, &ev->de_ev);
	if (rc != 0)
		D_GOTO(err, rc);

	/* Send a message to the async thread to wake it up and poll for events */
	sem_post(&eqt->de_sem);
	return;

err:
	DFUSE_REPLY_ERR_RAW(oh, req, rc);
	D_FREE(ibuf.buf[0].mem);
	D_FREE(ev);
}

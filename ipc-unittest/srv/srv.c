/*
 * Copyright (C) 2014-2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <err.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_std.h>

/* Expected limits: should be in sync with kernel settings */
#define MAX_USER_HANDLES    64  /* max number of user handles */
#define MAX_PORT_PATH_LEN   64  /* max length of port path name   */

#define LOG_TAG "ipc-unittest-srv"

#define TLOGI(fmt, ...) \
    fprintf(stderr, "%s: " fmt, LOG_TAG, ## __VA_ARGS__)

typedef void (*event_handler_proc_t) (const uevent_t *ev);

#define MSEC 1000000UL
#define SRV_PATH_BASE  "com.android.ipc-unittest"

static void closer1_handle_port(const uevent_t *ev);
static void closer2_handle_port(const uevent_t *ev);
static void closer3_handle_port(const uevent_t *ev);
static void connect_handle_port(const uevent_t *ev);
static void datasink_handle_port(const uevent_t *ev);
static void echo_handle_port(const uevent_t *ev);

static bool stopped = false;
static handle_t closer1_port  = INVALID_IPC_HANDLE;
static handle_t closer2_port  = INVALID_IPC_HANDLE;
static handle_t closer3_port  = INVALID_IPC_HANDLE;
static handle_t connect_port  = INVALID_IPC_HANDLE;
static handle_t datasink_port = INVALID_IPC_HANDLE;
static handle_t echo_port     = INVALID_IPC_HANDLE;


static void echo_handle_chan(const uevent_t *ev);
static void datasink_handle_chan(const uevent_t *ev);

/************************************************************************/

/*
 * close specified port
 */
static void _close_port(handle_t port)
{
	if (port == INVALID_IPC_HANDLE)
		return;

	int rc = close(port);
	if (rc != NO_ERROR) {
		TLOGI("Failed (%d) to close port %d\n", rc, port);
	}
}

/*
 * Close specified channel
 */
static void _close_channel (handle_t chan)
{
	if (chan == INVALID_IPC_HANDLE)
		return;

	int rc = close(chan);
	if (rc != NO_ERROR) {
		TLOGI("Failed (%d) to close chan %d\n", rc, chan);
	}
}

/*
 *  Create port helper
 */
static int _create_port(const char *name, uint buf_num, uint buf_sz,
                        void *cookie)
{
	handle_t port;
	char path[MAX_PORT_PATH_LEN];

	sprintf(path, "%s.srv.%s", SRV_PATH_BASE, name);
	int rc = port_create(path, buf_num, buf_sz, 0);
	if (rc < 0) {
		TLOGI("Failed (%d) to create port\n", rc);
		return INVALID_IPC_HANDLE;
	}
	port = (handle_t) rc;

	rc = set_cookie (port, cookie);
	if (rc << 0) {
		TLOGI("Failed (%d) to set cookie on port %d\n", rc, port);
	}
	return port;
}

/*
 *  Free resources allocated by all services
 */
static void kill_services(void)
{
	TLOGI ("Terminating unittest services\n");

	/* close any opened ports */
	_close_port(closer1_port);
	_close_port(closer2_port);
	_close_port(closer3_port);
	_close_port(connect_port);
	_close_port(datasink_port);
	_close_port(echo_port);
}

/*
 *  Initialize all services
 */
static int init_services(void)
{
	int rc;
	TLOGI ("Init unittest services!!!\n");

	rc = _create_port("closer1", 2, 64, closer1_handle_port);
	if (rc < 0)
		return -1;
	closer1_port = (handle_t) rc;

	rc = _create_port("closer2", 2, 64, closer2_handle_port);
	if (rc < 0)
		return -1;
	closer2_port = (handle_t) rc;

	rc = _create_port("closer3", 2, 64, closer3_handle_port);
	if (rc < 0)
		return -1;
	closer3_port = (handle_t) rc;

	rc = _create_port("connect", 2, 64, connect_handle_port);
	if (rc < 0)
		return -1;
	connect_port = (handle_t) rc;

	rc = _create_port("datasink", 2, 64, datasink_handle_port);
	if (rc < 0)
		return -1;
	datasink_port = (handle_t) rc;

	rc = _create_port("echo", 8, 4096, echo_handle_port);
	if (rc < 0)
		return -1;
	echo_port = (handle_t) rc;

	return 0;
}

/****************************** connect test service *********************/

static void connect_handle_port(const uevent_t *ev)
{
	if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
	    (ev->event & IPC_HANDLE_POLL_HUP) ||
	    (ev->event & IPC_HANDLE_POLL_MSG)) {
		TLOGI("error event (0x%x) for port (%d)\n",
		       ev->event, ev->handle);

		/* close port */
		close (ev->handle);

		/* and recreate it */
		connect_port = _create_port("connect", 2, 64,
		                             connect_handle_port);
		return;
	}

	if (ev->event & IPC_HANDLE_POLL_READY) {
		char path[MAX_PORT_PATH_LEN];

		/* accept incomming connection and close it */
		int rc = accept(ev->handle);
		if (rc < 0) {
			TLOGI("accept failed (%d)\n", rc);
			return;
		}
		close (rc);

		/* but then issue a series of connect requests */
		for (uint i = 2; i < MAX_USER_HANDLES; i++) {
			sprintf(path, "%s.port.accept%d", SRV_PATH_BASE, i);
			rc = connect(path, 1000);
			close(rc);
		}
	}
}

/****************************** closer services **************************/

static void closer1_handle_port(const uevent_t *ev)
{
	static uint _conn_cnt = 0;

	if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
	    (ev->event & IPC_HANDLE_POLL_HUP) ||
	    (ev->event & IPC_HANDLE_POLL_MSG)) {
		TLOGI("error event (0x%x) for port (%d)\n",
		       ev->event, ev->handle);
		/* close port */
		close (ev->handle);
		/* and recreate it */
		closer1_port = _create_port("closer1", 2, 64,
		                             closer1_handle_port);
		return;
	}

	if (ev->event & IPC_HANDLE_POLL_READY) {
		/* new connection request, bump counter */
		_conn_cnt++;

		/* accept it */
		int rc = accept(ev->handle);
		if (rc < 0) {
			TLOGI("accept failed (%d)\n", rc);
			return;
		}
		if (_conn_cnt & 1) {
			/* sleep a bit */
			nanosleep (0, 0, 100 * MSEC);
		}
		/* and close it */
		_close_channel((handle_t) rc);
	}
}

static void closer2_handle_port(const uevent_t *ev)
{
	static uint _conn_cnt = 0;

	if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
	    (ev->event & IPC_HANDLE_POLL_HUP) ||
	    (ev->event & IPC_HANDLE_POLL_MSG)) {
		TLOGI("error event (0x%x) for port (%d)\n",
		       ev->event, ev->handle);
		/* close port */
		close (ev->handle);
		/* and recreate it */
		closer2_port = _create_port("closer2", 2, 64,
		                             closer2_handle_port);
		return;
	}

	if (ev->event & IPC_HANDLE_POLL_READY) {
		/* new connection request, bump counter */
		_conn_cnt++;

		if (_conn_cnt & 1) {
			/* sleep a bit */
			nanosleep (0, 0, 100 * MSEC);
		}
		/* then close the port without accepting any connections */
		_close_port(closer2_port);
		/* and recreate port again */
		closer2_port = _create_port ("closer2", 2, 64,
		                              closer2_handle_port);
		return;
	}
}

static void closer3_handle_port(const uevent_t *ev)
{
	static uint _chan_cnt = 0;
	static handle_t _chans[4];

	if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
	    (ev->event & IPC_HANDLE_POLL_HUP) ||
	    (ev->event & IPC_HANDLE_POLL_MSG)) {
		/* log error */
		TLOGI("error event (0x%x) for port (%d)\n",
		       ev->event, ev->handle);

		/* close all channels */
		for (uint i = 0; i < _chan_cnt; i++) {
			close(_chans[i]);
			_chans[i] = INVALID_IPC_HANDLE;
		}
		_chan_cnt = 0;

		/* close port */
		close (ev->handle);

		/* and recreate it */
		closer3_port = _create_port("closer3", 2, 64,
		                             closer3_handle_port);
		return;
	}

	if (ev->event & IPC_HANDLE_POLL_READY) {

		/* accept connection */
		int rc = accept(ev->handle);
		if (rc < 0) {
			TLOGI("accept failed (%d)\n", rc);
			return;
		}

		/* add it to connection pool */
		_chans[_chan_cnt++] = (handle_t) rc;

		set_cookie((handle_t) rc, datasink_handle_chan);

		/* when max number of connection reached */
		if (_chan_cnt == countof(_chans)) {
			/* wait a bit */
			nanosleep (0, 0, 100 * MSEC);

			/* close them all */
			for (uint i = 0; i < countof(_chans); i++ ) {
				_close_channel(_chans[i]);
				_chans[i] = INVALID_IPC_HANDLE;

			}
			_chan_cnt = 0;
		}
		return;
	}
}

/****************************** datasync service **************************/

static int datasink_handle_msg(const uevent_t *ev)
{
	int rc;
	ipc_msg_info_t inf;

	/* for all messages */
	for (;;) {
		/* get message */
		rc = get_msg(ev->handle, &inf);
		if (rc == ERR_NO_MSG)
			break; /* no new messages */

		if (rc != NO_ERROR) {
			TLOGI("failed (%d) to get_msg for chan (%d)\n",
			      rc, ev->handle);
			return rc;
		}

		/* and retire it without actually reading  */
		rc = put_msg(ev->handle, inf.id);
		if (rc != NO_ERROR) {
			TLOGI("failed (%d) to putt_msg for chan (%d)\n",
			      rc, ev->handle);
			return rc;
		}
	}

	return NO_ERROR;
}

/*
 *  Datasink service channel handler
 */
static void datasink_handle_chan(const uevent_t *ev)
{
	if (ev->event & IPC_HANDLE_POLL_ERROR) {
		/* close it as it is in an error state */
		TLOGI("error event (0x%x) for chan (%d)\n",
		       ev->event, ev->handle);
		close (ev->handle);
		return;
	}

	if (ev->event & IPC_HANDLE_POLL_MSG) {
		if (datasink_handle_msg(ev) != 0) {
			close (ev->handle);
			return;
		}
	}

	if (ev->event & IPC_HANDLE_POLL_HUP) {
		/* closed by peer */
		close (ev->handle);
		return;
	}
}

/*
 *  Datasink service port event handler
 */
static void datasink_handle_port(const uevent_t *ev)
{
	if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
	    (ev->event & IPC_HANDLE_POLL_HUP) ||
	    (ev->event & IPC_HANDLE_POLL_MSG)) {
		/* log error */
		TLOGI("error event (0x%x) for port (%d)\n",
		       ev->event, ev->handle);

		/* GMAR: need to kill channels */

		/* close port */
		close (ev->handle);

		/* and recreate it */
		datasink_port = _create_port("datasink", 2, 64,
		                              datasink_handle_port);
		return;
	}

	if (ev->event & IPC_HANDLE_POLL_READY) {
		handle_t chan;

		/* incomming connection: accept it */
		int rc = accept(ev->handle);
		if (rc < 0) {
			TLOGI("failed (%d) to accept on port %d\n",
			       rc, ev->handle);
			return;
		}
		chan = (handle_t) rc;

		rc = set_cookie(chan, datasink_handle_chan);
		if (rc) {
			TLOGI("failed (%d) to set_cookie on chan %d\n",
			       rc, chan);
		}
	}
}

/******************************   echo service    **************************/

static uint8_t echo_msg_buf[4096];

static int _echo_handle_message(const uevent_t *ev, int delay)
{
	int rc;
	ipc_msg_info_t inf;
	ipc_msg_t      msg;
	iovec_t        iov;

	/* for all messages */
	for (;;) {
		/* init message structure */
		iov.base = echo_msg_buf;
		iov.len  = sizeof(echo_msg_buf);
		msg.num_iov = 1;
		msg.iov     = &iov;
		msg.num_handles = 0;
		msg.handles  = NULL;

		/* get message */
		rc = get_msg(ev->handle, &inf);
		if (rc == ERR_NO_MSG)
			break; /* no new messages */

		if (rc != NO_ERROR) {
			TLOGI("failed (%d) to get_msg for chan (%d)\n",
			      rc, ev->handle);
			return rc;
		}

		/* read content */
		rc = read_msg(ev->handle, inf.id, 0, &msg);
		if (rc < 0) {
			TLOGI("failed (%d) to read_msg for chan (%d)\n",
			      rc, ev->handle);
			return rc;
		}

		/* update numvber of bytes recieved */
		iov.len = (size_t) rc;

		/* retire original message */
		rc = put_msg(ev->handle, inf.id);
		if (rc != NO_ERROR) {
			TLOGI("failed (%d) to put_msg for chan (%d)\n",
			      rc, ev->handle);
			return rc;
		}

		/* sleep a bit an send it back */
		if (delay) {
			nanosleep (0, 0, 1000);
		}

		/* and send it back */
		rc = send_msg(ev->handle, &msg);
		if (rc < 0) {
			TLOGI("failed (%d) to send_msg for chan (%d)\n",
			      rc, ev->handle);
			return rc;
		}
	}
	return NO_ERROR;
}

static int echo_handle_msg(const uevent_t *ev)
{
	return _echo_handle_message(ev, false);
}

/*
 *  echo service channel handler
 */
static void echo_handle_chan(const uevent_t *ev)
{
	if (ev->event & IPC_HANDLE_POLL_ERROR) {
		/* close it as it is in an error state */
		TLOGI("error event (0x%x) for chan (%d)\n",
		       ev->event, ev->handle);
		close (ev->handle);
		return;
	}

	if (ev->event & IPC_HANDLE_POLL_MSG) {
		if (echo_handle_msg(ev) != 0) {
			close (ev->handle);
			return;
		}
	}

	if (ev->event & IPC_HANDLE_POLL_HUP) {
		/* closed by peer */
		close (ev->handle);
		return;
	}
}

/*
 *  echo service port event handler
 */
static void echo_handle_port(const uevent_t *ev)
{
	if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
	    (ev->event & IPC_HANDLE_POLL_HUP) ||
	    (ev->event & IPC_HANDLE_POLL_MSG)) {
		/* log error */
		TLOGI("error event (0x%x) for port (%d)\n",
		       ev->event, ev->handle);
		/* GMAR: need to kill channels */

		/* close port */
		close (ev->handle);

		/* and recreate it */
		echo_port = _create_port("echo", 8, 4096,
		                          echo_handle_port);
		return;
	}

	if (ev->event & IPC_HANDLE_POLL_READY) {
		handle_t chan;

		/* incomming connection: accept it */
		int rc = accept(ev->handle);
		if (rc < 0) {
			TLOGI("failed (%d) to accept on port %d\n",
			       rc, ev->handle);
			return;
		}
		chan = (handle_t) rc;

		rc = set_cookie(chan, echo_handle_chan);
		if (rc) {
			TLOGI("failed (%d) to set_cookie on chan %d\n",
			       rc, chan);
		}
	}
}

/***************************************************************************/

/*
 *  Dispatch event
 */
static void dispatch_event(const uevent_t *ev)
{
	assert(ev);

	if (ev->event == IPC_HANDLE_POLL_NONE) {
		/* not really an event, do nothing */
		TLOGI("got an empty event\n");
		return;
	}

	if (ev->handle == INVALID_IPC_HANDLE) {
		/* not a valid handle  */
		TLOGI("got an event (0x%x) with invalid handle (%d)",
		      ev->event, ev->handle);
		return;
	}

	/* check if we have handler */
	event_handler_proc_t handler = (event_handler_proc_t)ev->cookie;
	if (handler) {
		/* invoke it */
		handler(ev);
		return;
	}

	/* no handler? close it */
	TLOGI("no handler for event (0x%x) with handle %d\n",
	       ev->event, ev->handle);
	close(ev->handle);

	return;
}

/*
 *  Main entry point of service task
 */
int main(void)
{
	int rc;
	uevent_t event;

	/* Initialize service */
	rc = init_services();
	if (rc != NO_ERROR ) {
		TLOGI("Failed (%d) to init service", rc);
		kill_services();
		return -1;
	}

	/* handle events */
	while (!stopped) {
		event.handle = INVALID_IPC_HANDLE;
		event.event  = 0;
		event.cookie = NULL;
		rc = wait_any(&event, -1);
		if (rc < 0) {
			TLOGI("wait_any failed (%d)", rc);
			continue;
		}
		if (rc > 0) { /* got an event */
			dispatch_event (&event);
		}
	}

	kill_services();
	return 0;
}


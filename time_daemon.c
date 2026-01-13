// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <linux/rtc.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

#include "qmi_cci.h"
#include "qmi_idl_lib_internal.h"
#include "time_service_v01.h"
#include "localdefs.h"

#include "time_genoff.h"

#ifdef SYSLOG_ENABLE
#include <stdarg.h>
#include <syslog.h>
#define SYSLOG_PREFIX "time_daemon:"
#define TIME_LOGD(x...) syslog(LOG_ERR, x)
#define TIME_LOGE(x...) syslog(LOG_ERR, x)
#else
#include <cutils/log.h>
#define LOG_TAG "QC-time-services"
#define TIME_LOGE(...) ALOGE(__VA_ARGS__)
#define TIME_LOGD(...) ALOGD(__VA_ARGS__)
#endif

static qmi_client_type modem_time_client;
static qmi_client_type notifier;
static qmi_cci_os_signal_type modem_os_signals;
static qmi_cci_os_signal_type os_params;
static qmi_idl_service_object_type modem_time_service_object;
static pthread_t qmi_clnt_thread;

static struct time_genoff_struct ats_bases[ATS_MAX];
static pthread_mutex_t genoff_mutex;
static uint8_t time_genoff_set_id;
static uint8_t modem_qmi_initialized;
static uint8_t qmi_serv_up;

static int disable_logging;
static int property_false;
static int property_true;

/* For reading full time */
static cb_indication_t  indication;
static pthread_cond_t   read_cond = PTHREAD_COND_INITIALIZER;

static pthread_mutex_t qmi_clnt_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qmi_clnt_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t qmi_serv_up_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t qmi_serv_hdl_thread_cond = PTHREAD_COND_INITIALIZER;
/* Sleep thread */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_t sleep_thread, read_time, connection_mgr, time_thread;

/* Forward declaration */
static void genoff_qmi_error_cb(qmi_client_type clnt, qmi_cci_error_type error, void *error_cb_data);

/* This array lists the bases which have to be sent to MODEM */
static int genoff_update_to_modem[] = {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/* This array lists the bases which can receive update from MODEM */
static int genoff_update_from_modem[] = {0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/* This array lists the bases on which updates are allowed */
static int genoff_valid_base[] = {0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

/* This array lists the bases, which can be updated from APPS */
static int genoff_update_from_apps[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

/* Signal handler to terminate time_daemon gracefully */
void time_service_exit(int signum)
{
	TIME_LOGE("Received signal terminating service\n");
	pthread_cond_signal(&cond);
}

static int time_persistent_memory_opr(const char *file_name,
		enum time_persistant_operation rd_wr, int64_t *data_ptr)
{
	char fname[120];
	int fd;

	/* location where offset is to be stored */
	snprintf(fname, 120, "%s/%s", OFFSET_LOCATION, file_name);
	TIME_LOGD("Opening File: %s\n", fname);

	switch (rd_wr) {
		case TIME_READ_MEMORY:
			TIME_LOGD("%s:Genoff Read operation\n",
					__func__);
			fd = open(fname,O_RDONLY);
			if (fd < 0) {
				TIME_LOGE("Unable to open filefor read\n");
				goto fail_operation;
			}
			if (read(fd, (int64_t *)data_ptr,
						sizeof(int64_t)) < 0) {
				TIME_LOGE("%s:Error reading fromfile\n",
					       __func__);
				close(fd);
				goto fail_operation;
			}
			break;

		case TIME_WRITE_MEMORY:
			TIME_LOGD("%s:Genoff write operation\n",
					__func__);
			fd = open(fname, O_RDWR | O_SYNC);
			if (fd < 0) {
				TIME_LOGE("Unable to open file,creating file\n");
				if ((fd = open(fname, O_CREAT | O_RDWR |
							O_SYNC,	0666)) < 0) {
					TIME_LOGE("Unable to createfile, exiting\n");
					goto fail_operation;
				}
			}
			if (write(fd, (int64_t *)data_ptr,
						sizeof(int64_t)) < 0) {
				TIME_LOGE("%s:Error reading fromfile\n",
						__func__);
				close(fd);
				goto fail_operation;
			}
			break;
		default:
			return -EINVAL;
	}
	close(fd);
	return 0;

fail_operation:
	return -EINVAL;
}

static void
genoff_pre_init(struct time_genoff_struct *time_genoff, time_bases_type base)
{
	time_genoff->initialized = 0;
	time_genoff->reqd_base_genoff = base;
	time_genoff->generic_offset = 0;
	time_genoff->bases_type =  base;
	time_genoff->init_func = NULL;
	time_genoff->per_storage_spec.initialized = 0;
	TIME_LOGD("%s::Base = %d\n", __func__, base);
}

static int genoff_post_init(struct time_genoff_struct *time_genoff)
{
	int rc;

	if (time_genoff->init_func != NULL) {
		rc = time_genoff->init_func();
		if (rc) {
			TIME_LOGE("%s:Init func failed\n", __func__);
			return -EINVAL;
		}
	}

	if (time_genoff->per_storage_spec.initialized == 1) {
		/* Read from the generic offset */
		rc = time_persistent_memory_opr(
				time_genoff->per_storage_spec.f_name,
				TIME_READ_MEMORY, &(time_genoff->generic_offset));
		if (rc) {
			TIME_LOGD("%s:Error in accessing storage\n",
					__func__);
			time_genoff->generic_offset = 0;
		}
	}

	time_genoff->initialized = 1;

	return 0;
}

static void genoff_set_generic_offset(struct time_genoff_struct *time_genoff,
		int64_t offset)
{
	int64_t delta_ms;

	delta_ms = offset - time_genoff->generic_offset;
	time_genoff->generic_offset = offset;
}

static struct time_genoff_struct *genoff_get_pointer(time_bases_type base)
{
	if (base >= ATS_MAX)
		return NULL;

	return &(ats_bases[base]);
}

static int genoff_check_offset(struct time_genoff_info *pargs)
{
	struct time_genoff_struct *ptime_genoff;

	ptime_genoff = genoff_get_pointer(pargs->base);
	if (ptime_genoff == NULL) {
		TIME_LOGE("Daemon:%s:Genoff memory not allocated\n", __func__);
		return -EINVAL;
	}
	*(uint64_t *)pargs->ts_val = ((ptime_genoff->generic_offset) != 0) ? 1 : 0;
	if (!disable_logging)
		TIME_LOGD("offset is: %d for base: %d", *(uint64_t *)pargs->ts_val, pargs->base);
	return 0;
}

static void
genoff_updates_per_storage(struct time_genoff_struct *time_genoff, char *name,
		int64_t thold)
{
	time_genoff->per_storage_spec.initialized = 1;
	time_genoff->per_storage_spec.threshold   = thold;
	strlcpy(time_genoff->per_storage_spec.f_name, name, FILE_NAME_MAX);
	TIME_LOGD(" Storage Name: %s\n",
			time_genoff->per_storage_spec.f_name);
} /* time_genoff_updates_per_storage */


void genoff_persistent_update(struct time_genoff_struct *ptime_genoff, int64_t delta_ms)
{
	int rc;

	if (ptime_genoff->per_storage_spec.initialized == 1) {
		TIME_LOGD("%s: Writing genoff = %llu to memory\n",
				__func__, ptime_genoff->generic_offset);

		rc = time_persistent_memory_opr(
				ptime_genoff->per_storage_spec.f_name,
				TIME_WRITE_MEMORY,
				&ptime_genoff->generic_offset);
		if (rc) {
			TIME_LOGD("%s:or in accessing storage\n",
					__func__);
		}
	}
}

static int rtc_get(int64_t *msecs)
{
	int rc, fd;
	time_t secs = 0;
	struct tm rtc_tm;

	errno = 0;
	fd = open("/dev/rtc0", O_RDONLY);
	if (fd < 0) {
		TIME_LOGE("%s: Unable to open RTC device errno: %d\n", __func__, errno);
		return -EINVAL;
	}

	rc = ioctl(fd, RTC_RD_TIME, &rtc_tm);
	if (rc < 0) {
		TIME_LOGE("%s: Unable to read from RTC device\n",
								__func__);
		goto fail_rtc;
	}

	TIME_LOGD("%s: Time read from RTC -- year = %d, month = %d,day = %d\n",
			__func__, rtc_tm.tm_year, rtc_tm.tm_mon,
			rtc_tm.tm_mday);

	/* Convert the time to UTC and then to milliseconds and store	it */
	secs = mktime(&rtc_tm);
	secs += rtc_tm.tm_gmtoff;
	if (secs < 0) {
		TIME_LOGE("Invalid RTC seconds = %ld\n", secs);

		goto fail_rtc;
	}

	*msecs = SEC_TO_MSEC(secs);
	TIME_LOGD("Value read from RTC mseconds = %lld\n", *msecs);

	close(fd);
	return 0;

fail_rtc:
	close(fd);
	return -EINVAL;
}

static int genoff_set(struct time_genoff_info *pargs)
{
	int64_t rtc_msecs;
	int64_t delta_ms;
	struct time_genoff_struct *ptime_genoff, *ptime_genoff_tod;

	ptime_genoff = genoff_get_pointer(pargs->base);
	if (ptime_genoff == NULL) {
		TIME_LOGE("%s:Genoff memory not allocated\n", __func__);
		return -EINVAL;
	}
	if (ptime_genoff->initialized == 0) {
		TIME_LOGE("%s:Genoff not initialized\n", __func__);
		return -EINVAL;
	}

	/* Get RTC time */
	if (rtc_get(&rtc_msecs))
		return -EINVAL;

	/* delta_ms = new time - rtc time */
	delta_ms = *(uint64_t *)pargs->ts_val - rtc_msecs;
	TIME_LOGD("new time %lld\n",
			*(uint64_t *)pargs->ts_val);
	ptime_genoff->generic_offset = delta_ms;

	TIME_LOGD("delta %lld genoff %lld\n", delta_ms,
			ptime_genoff->generic_offset);
	genoff_persistent_update(ptime_genoff, delta_ms);

	return 0;
}

static int genoff_get(struct time_genoff_info *pargs)
{
	struct time_genoff_struct *ptime_genoff;
	int64_t rtc_msecs = 0;

	TIME_LOGD("genoff get for %d\n", pargs->base);
	ptime_genoff = genoff_get_pointer(pargs->base);
	if (ptime_genoff == NULL) {
		TIME_LOGE("%s:Genoff memory not allocated\n",
								__func__);
		return -EINVAL;
	}

	if (ptime_genoff->initialized == 0) {
		TIME_LOGE("%s:Bases not initialized\n", __func__);
		goto fail_time_get;
	}

	if (rtc_get(&rtc_msecs))
		goto fail_time_get;

	TIME_LOGD("Value read from RTC mseconds = %lld\n", rtc_msecs);
	TIME_LOGD("Daemon:Value read from generic offset = %lld\n",
					ptime_genoff->generic_offset);

	/* Add RTC time to the offset */
	*(uint64_t *)pargs->ts_val = ptime_genoff->generic_offset + rtc_msecs;

	TIME_LOGD("Final Time = %llu\n", *(uint64_t *)pargs->ts_val);
	return 0;

fail_time_get:
	*(uint64_t *)pargs->ts_val = 0;
	return -EINVAL;
}

static int genoff_opr(struct time_genoff_info *pargs)
{
	struct time_genoff_info temp_genoff_args;
	uint64_t ts_val_secs;
	int rc = 0;

	TIME_LOGD("%s: Base = %d, val = %llu, operation = %d",
			__func__, pargs->base, *(uint64_t *)(pargs->ts_val),
			pargs->operation);

	if (pargs->operation == T_GET) {
		switch (pargs->unit) {
			case TIME_MSEC:
				rc = genoff_get(pargs);
				break;
			case TIME_SECS:
				rc = genoff_get(pargs);
				/* Convert the time to secs */
				*(uint64_t *)pargs->ts_val =
					(uint64_t)MSEC_TO_SEC(*(uint64_t *)pargs->ts_val);
				break;
			case TIME_JULIAN:
				temp_genoff_args.base        = pargs->base;
				temp_genoff_args.ts_val      = &ts_val_secs;
				temp_genoff_args.unit        = TIME_SECS;
				temp_genoff_args.operation   = T_GET;
				rc = genoff_get(&temp_genoff_args);
				/* convert the time to julian */
				pargs->ts_val =
					gmtime((time_t *)&ts_val_secs);
				break;
			default:
				TIME_LOGE("%s:Invalid time unit %d",
						__func__, pargs->unit);
				return -EINVAL;
		}
	} else if (pargs->operation == T_SET) {
		switch (pargs->unit) {
			case TIME_MSEC:
				rc = genoff_set(pargs);
				break;
			case TIME_SECS:
				/* Convert the time to msecs */
				ts_val_secs =
					SEC_TO_MSEC(*(uint64_t *)pargs->ts_val);
				pargs->ts_val = &ts_val_secs;
				rc = genoff_set(pargs);
				break;
			case TIME_JULIAN:
				/* Convert input time to UTC */
				ts_val_secs =
					mktime((struct tm *)pargs->ts_val);
				temp_genoff_args.base        = pargs->base;
				temp_genoff_args.ts_val      = &ts_val_secs;
				temp_genoff_args.unit        = TIME_SECS;
				temp_genoff_args.operation   = T_SET;
				rc = genoff_opr(&temp_genoff_args);
				break;
			default:
				TIME_LOGE("%s:Invalid time unit %d",
						__func__, pargs->unit);
				return -EINVAL;
		}
	} else if (pargs->operation == T_IS_SET) {
		rc = genoff_check_offset(pargs);
	}

	return rc;
}

static void
genoff_add_base_subsys(struct time_genoff_struct *time_genoff,
		time_bases_type base)
{
	time_genoff->subsys_base = base;
	time_genoff->reqd_base_genoff = 1;
}

static int ats_bases_init(time_bases_type time_base,
		time_bases_type subsys_base, char *f_name,
				struct time_genoff_struct *ptime_genoff)
{
	int rc;

	genoff_pre_init(ptime_genoff, time_base);
	/* subsys_base = "parent" base */
	genoff_add_base_subsys(ptime_genoff, subsys_base);
	genoff_updates_per_storage(ptime_genoff, f_name,
			TIME_GENOFF_UPDATE_THRESHOLD_MS);

	rc = genoff_post_init(ptime_genoff);
	if (rc) {
		TIME_LOGE("%s: Post init failed for base = %d\n",
							__func__, time_base);
		return -EINVAL;
	}

	return 0;
}

static int ats_rtc_init(struct time_genoff_struct *ptime_genoff)
{
	int fd, rc;
	struct tm rtc_tm;
	time_t secs = 0;
	int64_t msecs = 0;

	memset(&rtc_tm, 0, sizeof(struct tm));
	genoff_pre_init(ptime_genoff, ATS_RTC);

	fd = open("/dev/rtc0", O_RDONLY);
	if (fd < 0) {
		TIME_LOGE("%s: Unable to open RTC device\n", __func__);
		return -EINVAL;
	}

	rc = ioctl(fd, RTC_RD_TIME, &rtc_tm);
	if (rc < 0) {
		TIME_LOGE("%s: Unable to read from RTC device\n",
								__func__);
		close(fd);
		return -EINVAL;
	}

	TIME_LOGD("%s: Time read from RTC -- year = %d, month = %d,day = %d\n",
			__func__, rtc_tm.tm_year, rtc_tm.tm_mon,
			rtc_tm.tm_mday);

	close(fd);

	/* Convert the time to UTC and then to milliseconds and store it */
	secs = mktime(&rtc_tm);
	secs += rtc_tm.tm_gmtoff;
	if (secs < 0) {
		TIME_LOGE("Invalid RTC seconds = %ld\n", secs);
		return -EINVAL;
	}

	msecs = SEC_TO_MSEC(secs);
	TIME_LOGD("Value read from RTC seconds = %lld\n", msecs);
	genoff_set_generic_offset(ptime_genoff, msecs);

	rc = genoff_post_init(ptime_genoff);
	if (rc) {
		TIME_LOGE("%s: Genoff post_init operation failed\n",
								__func__);
		return -EINVAL;
	}

	return 0;
}

static int genoff_init_config(void)
{
	int i, rc;
	char f_name[FILE_NAME_MAX];

	/* Initialize RTC values */
	rc = ats_rtc_init(&ats_bases[0]);
	if (rc) {
		TIME_LOGE("%s: RTC initilization failed\n", __func__);
		return -EINVAL;
	}

	TIME_LOGD("%s: ATS_RTC initialized\n", __func__);

	/* Initialize the other offsets */
	for (i = 1; i < ATS_MAX; i++) {
		snprintf(f_name, FILE_NAME_MAX, "ats_%d", i);
		rc = ats_bases_init(i, ATS_RTC, f_name, &ats_bases[i]);
		if (rc) {
			TIME_LOGE("%s: Init failed for base = %d\n",
								__func__, i);
			return -EINVAL;
		}
	}

	TIME_LOGD("%s: Other bases initilized, exiting genoff_init\n",
								__func__);

	return 0;
}

static int genoff_boot_tod_init(void)
{
	uint64_t tod_value;
	int fd, res;
	struct timeval tv;

	struct time_genoff_info tod_genoff;
	struct time_genoff_struct *ptime_genoff;

	tod_genoff.base = ATS_TOD;
	tod_genoff.unit = TIME_MSEC;
	tod_genoff.operation  = T_GET;
	tod_genoff.ts_val = &tod_value;
	res = genoff_opr(&tod_genoff);
	if (res < 0)
		return -EINVAL;

	ptime_genoff = genoff_get_pointer(ATS_TOD);
	if (ptime_genoff == NULL) {
		TIME_LOGE("Daemon:%s:Genoff memory not allocated\n",
				__func__);
		return -EINVAL;
	}

	if (ptime_genoff->initialized == 0) {
		TIME_LOGE("Daemon:%s:Bases not initialized\n", __func__);
		return -EINVAL;
	}

	if (ptime_genoff->generic_offset == 0) {
		tod_genoff.base = ATS_TOD_GEN;
		tod_genoff.unit = TIME_MSEC;
		tod_genoff.operation  = T_GET;
		tod_genoff.ts_val = &tod_value;
		res = genoff_opr(&tod_genoff);
		if (res < 0)
			return -EINVAL;
	}

	tv.tv_sec = (time_t) MSEC_TO_SEC(tod_value);
	tv.tv_usec = (long) ((tod_value % 1000LL) * 1000LL);

	TIME_LOGE("%s: Updating system time to sec=%ld, usec=%ld\n",
			__func__, tv.tv_sec, tv.tv_usec);

	if (settimeofday(&tv, NULL) != 0) {
		TIME_LOGE("%s: Unable to set clock to sec=%ldusec=%ld\n",
				__func__, tv.tv_sec,
				tv.tv_usec);
		return -EINVAL;
	}

	return 0;
}

static int
genoff_send_modem(struct time_genoff_info *genoff_args)
{
	uint64_t time_value;
	int rc;
	time_set_genoff_offset_req_msg_v01 time_req_msg;
	time_set_genoff_offset_resp_msg_v01 time_resp_msg;

	if (!disable_logging)
		TIME_LOGD("Daemon:%s: Sending data to MODEM !\n", __func__);

	/* Do a genoff opr call */
	genoff_args->unit = TIME_MSEC;
	time_value =  *(uint64_t *)genoff_args->ts_val;
	time_value -= (uint64_t)SEC_TO_MSEC(MODEM_EPOCH_DIFFERENCE);

	if (!disable_logging)
		TIME_LOGD("Daemon: Base = %d, Value being sent to MODEM = %llu\n",
			genoff_args->base, time_value);

	time_req_msg.base = genoff_args->base;
	time_req_msg.generic_offset = time_value;

	time_resp_msg.resp.result = QMI_RESULT_SUCCESS;
	time_resp_msg.resp.error = QMI_ERR_NONE;

	/* Locking to syncronize with indication read */
	pthread_mutex_lock(&indication.lock);
	rc = qmi_cci_send_msg_sync(modem_time_client,
			QMI_TIME_GENOFF_SET_REQ_MSG_V01, &time_req_msg,
			sizeof(time_req_msg), &time_resp_msg,
			sizeof(time_resp_msg), 5000);
	if (rc != QMI_NO_ERR || time_resp_msg.resp.result !=
			QMI_RESULT_SUCCESS){
		TIME_LOGE("Daemon: message send failed. Error Code %d\n",
				time_resp_msg.resp.error);
		rc = -EINVAL;
		goto exit;
	}

	rc = 0;
exit:
	pthread_mutex_unlock(&indication.lock);
	return rc;
}

static void genoff_handler(void *recv_arg)
{
	int rc;
	int recv_id = *(int *)recv_arg;
	struct send_recv_struct to_recv;
	struct time_genoff_info genoff_args;
	struct time_genoff_struct *ptime_genoff;

	/*
	 * Initialize base to 0 (Invalid )
	 */
	to_recv.base = 0;
	to_recv.operation = 0;
	to_recv.unit = 0;
	to_recv.value = 0;

	/*
	 * Receive data from the library
	 * Format: base, unit, operation, value (for set operation)
	 */
	if (recv(recv_id, (void *)&to_recv, sizeof(to_recv), 0) < 0) {
		TIME_LOGE("Daemon:Unable to recv data from client\n");
		goto error_invalid_input;
	}

	if (to_recv.base >= ATS_MAX) {
		TIME_LOGE("Daemon: Invalid base received\n");
		to_recv.result = -EINVAL;
		to_recv.base = to_recv.unit = to_recv.value = 0;
		if (send(recv_id, &to_recv, sizeof(to_recv), 0) < 0)
			TIME_LOGE("Daemon:Send to client failed %d\n",
						errno);
		goto error_invalid_input;
	}

	if (genoff_update_from_apps[to_recv.base] == 0 &&
			to_recv.operation == T_SET) {
		TIME_LOGE("Daemon:%s: Update is not allowed for offset[%d]\n",
				__func__, to_recv.base);
		to_recv.result = -EPERM;
		to_recv.base = to_recv.unit = to_recv.value = 0;
		if (send(recv_id, &to_recv, sizeof(to_recv), 0) < 0)
			TIME_LOGE("Daemon:Send to client failed %d\n",
						errno);

		goto error_invalid_input;
	}

	if (!disable_logging) {
		TIME_LOGD("Daemon:Received base = %d, unit = %d, operation = %d,value = %llu\n",
				to_recv.base, to_recv.unit,
					to_recv.operation, to_recv.value);
	}

	genoff_args.base = to_recv.base;
	genoff_args.unit = to_recv.unit;
	genoff_args.operation = to_recv.operation;
	genoff_args.ts_val = (uint64_t *)&to_recv.value;

	/* Check if a valid base update is received */
	if (!genoff_valid_base[to_recv.base]) {
		TIME_LOGE("Daemon: Operation on this base is not supported\n");
		to_recv.result = -EINVAL;
		to_recv.base = to_recv.unit = to_recv.value = 0;
		if (send(recv_id, &to_recv, sizeof(to_recv), 0) < 0)
			TIME_LOGE("Daemon:Send to client failed %d\n",
						errno);
		goto error_invalid_input;
	}

	if (genoff_args.operation == T_DISABLE)
		disable_logging = 1;
	else if (genoff_args.operation == T_ENABLE)
		disable_logging = 0;

	pthread_mutex_lock(&genoff_mutex);
	to_recv.result = genoff_opr(&genoff_args);
	pthread_mutex_unlock(&genoff_mutex);

	switch (genoff_args.operation) {
		case T_GET:
			if (send(recv_id, &to_recv, sizeof(to_recv), 0) < 0)
				TIME_LOGE("Daemon:Send to client failed %d\n",
						errno);
			break;
		case T_SET:
			/* Send data, result back to library */
			if (send(recv_id, &to_recv, sizeof(to_recv), 0) < 0)
				TIME_LOGE("Daemon:Send to client failed %d\n",
						errno);
			/* Send the data to MODEM, if to_modem bit is set */
			ptime_genoff = genoff_get_pointer(to_recv.base);
			if (ptime_genoff == NULL) {
				TIME_LOGE("Daemon:%s:Genoff memory not allocated\n", __func__);
				break;
			}
			if (genoff_update_to_modem[ptime_genoff->bases_type] &&
					modem_qmi_initialized) {
				if (!disable_logging)
					TIME_LOGD("Daemon:Update to modem bit set\n");
				/* Send only offset to modem instead of full-time */
				*(uint64_t *)genoff_args.ts_val = ptime_genoff->generic_offset;
				rc = genoff_send_modem(&genoff_args);
				if (rc < 0)
					TIME_LOGE("Daemon:Unable to send data to MODEM\n");
			}
			break;
		case T_IS_SET:
			if (send(recv_id, &to_recv, sizeof(to_recv), 0) < 0)
				TIME_LOGE("Daemon:Send to client failed %d\n",
						errno);
			break;
		case T_DISABLE:
			if (send(recv_id, &to_recv, sizeof(to_recv), 0) < 0)
				TIME_LOGE("Daemon:Send to client failed %d\n",
						errno);
			break;
		case T_ENABLE:
			if (send(recv_id, &to_recv, sizeof(to_recv), 0) < 0)
				TIME_LOGE("Daemon:Send to client failed %d\n",
						errno);
			break;
		default:
			TIME_LOGE("Daemon:%s: Invalid option\n", __func__);
			break;
	}

error_invalid_input:
	close(recv_id);
	pthread_exit(NULL);
}

/* Callback indication function for time update from modem */
static void tod_update_ind_cb(qmi_client_type handle, unsigned long msg_id,
		unsigned char *buffer, int buffer_len, void *indication_data)
{
	int rc;
	uint64_t time_value;
	struct timeval tv;

	struct time_genoff_struct *ptime_genoff;
	time_update_indication_message_v01 ind_buff;
	struct time_genoff_info genoff_update;

	TIME_LOGD("%s: Got Update from modem msg_id %lu\n", __func__,
			msg_id);

	if (msg_id != QMI_TIME_ATS_TOD_UPDATE_IND_MSG_V01)
		return;

	pthread_mutex_lock(&indication.lock);

	pthread_mutex_lock(&genoff_mutex);
	rc = qmi_cci_message_decode(handle, QMI_IDL_INDICATION, msg_id,
			buffer, buffer_len, &ind_buff,
			sizeof(time_update_indication_message_v01));
	if (rc != QMI_NO_ERR) {
		TIME_LOGE("%s: TOD update message decode error\n",
				__func__);
		goto error;
	}

	ptime_genoff = genoff_get_pointer(ind_buff.base);
	if (ptime_genoff == NULL) {
		TIME_LOGE("%s: ptime_genoff is NULL\n", __func__);
		goto error;
	}

	if (genoff_update_from_modem[ptime_genoff->bases_type] == 0) {
		TIME_LOGE("%s: Ignore time update from MODEM,for base = %d\n",
			__func__,
					ptime_genoff->bases_type);
		goto error;
	}

	indication.offset = ind_buff.base;
	indication.ind_received = 1;
	pthread_cond_signal(&read_cond);

error:
	pthread_mutex_unlock(&genoff_mutex);
	pthread_mutex_unlock(&indication.lock);


}

static void genoff_qmi_error_cb(qmi_client_type clnt, qmi_cci_error_type error, void *error_cb_data)
{
	int rc;

	if (clnt == NULL)
		return;

	TIME_LOGD("Daemon:%s: Error callback called\n", __func__);

	pthread_mutex_lock(&qmi_clnt_mutex);
	modem_qmi_initialized = 0;
	qmi_serv_up = 0;
	pthread_cond_signal(&qmi_clnt_cond);
	pthread_mutex_unlock(&qmi_clnt_mutex);
}

void time_service_modem_serv_notify_cb
(
  qmi_client_type               user_handle,
  qmi_idl_service_object_type   time_service_object,
  qmi_client_notify_event_type  service_event,
  void                          *notify_cb_data
)
{
	(void)user_handle;
	(void)time_service_object;
	(void)notify_cb_data;

	if (service_event == QMI_CLIENT_SERVICE_COUNT_INC) {
		if (!disable_logging)
			TIME_LOGE("Daemon:%s: QMI service is up\n", __func__);
		pthread_mutex_lock(&qmi_clnt_mutex);
		qmi_serv_up = 1;
		pthread_cond_signal(&qmi_serv_up_cond);
		pthread_mutex_unlock(&qmi_clnt_mutex);
	}
}

void *genoff_modem_qmi_service_handle_cb(void)
{
	int i = 0, rc, retry_count;
	unsigned int num_entries = 1, num_services;
	uint64_t time_value;

	static time_get_genoff_offset_resp_msg_v01 resp_message;
	struct timeval tv;
	qmi_service_info modem_info;
	time_get_genoff_offset_req_msg_v01 time_request;
	struct time_genoff_info genoff_update;
	time_turn_off_ind_req_msg_v01 ind_turn_off_req;
	time_turn_off_ind_resp_msg_v01 ind_turn_off_rsp;

	/* Signal on qmi service handle thread creation */
	pthread_mutex_lock(&qmi_clnt_mutex);
	pthread_cond_signal(&qmi_serv_hdl_thread_cond);
	pthread_mutex_unlock(&qmi_clnt_mutex);

	while (1) {
	/* Wait for peripheral up notification */
	pthread_mutex_lock(&qmi_clnt_mutex);
	if (!qmi_serv_up) {
		if (!disable_logging)
			TIME_LOGD("Daemon:%s: Waiting for service up\n", __func__);
		pthread_cond_wait(&qmi_serv_up_cond, &qmi_clnt_mutex);
	}
	pthread_mutex_unlock(&qmi_clnt_mutex);

	if (!disable_logging)
		TIME_LOGD("Daemon:%s: QMI service handle cb called\n", __func__);

	if (!modem_qmi_initialized) {

		if (modem_time_client) {
			qmi_cci_release(modem_time_client);
			modem_time_client = NULL;
		}

		/* The server has come up, store the information in modem_info variable */
		rc = qmi_cci_get_service_list(modem_time_service_object, &modem_info,
					&num_entries, &num_services);
		if (rc != QMI_NO_ERR) {
			TIME_LOGE("%s: qmi_cci_get_service_list returned %dnum_service %d num_entries %d\n",
					__func__,
					rc, num_services, num_entries);
			qmi_cci_release(notifier);
			notifier = NULL;
			return NULL;
		}

		rc = qmi_cci_init(&modem_info, modem_time_service_object, tod_update_ind_cb,
				NULL, &modem_os_signals, &modem_time_client);

		if (rc != QMI_NO_ERR) {
			TIME_LOGE("%s:Modem client init failed %d\n", __func__, rc);
			qmi_cci_release(notifier);
			notifier = NULL;
			return NULL;
		}

		/* Read time from modem */
		TIME_LOGD("%s: Sending initial transaction to read time", __func__);
		memset(&time_request, 0, sizeof(time_request));
		memset(&resp_message, 0, sizeof(resp_message));
		time_request.base = ATS_TOD;
		rc = qmi_cci_send_msg_sync(modem_time_client, QMI_TIME_GENOFF_GET_REQ_MSG_V01,
						&time_request, sizeof(time_request),
						&resp_message, sizeof(resp_message), 1000);

		if (rc == QMI_NO_ERR && resp_message.resp.error == 0) {
			resp_message.generic_offset +=
				(uint64_t)SEC_TO_MSEC(MODEM_EPOCH_DIFFERENCE);
			TIME_LOGD("Daemon:%s:Time received %llu\n",
					__func__, resp_message.generic_offset);
		} else {
			TIME_LOGE("Daemon:%s: Error in reading full time ignoring update rc=%d"
					" resp=%d ", __func__, rc,
					resp_message.resp.error);
			qmi_cci_release(modem_time_client);
			modem_time_client = NULL;
			return NULL;
		}

		/* Turn off 3GPP indication from modem time-service */
		memset(&ind_turn_off_req, 0, sizeof(ind_turn_off_req));
		memset(&ind_turn_off_rsp, 0, sizeof(ind_turn_off_rsp));
		ind_turn_off_req.msg_id = TIME_SERVICE_ATS_3GPP_IND_MSG;
		TIME_LOGD("%s: Sending indication turn off request msg_id %d\n",
				__func__, ind_turn_off_req.msg_id);

		rc = qmi_cci_send_msg_sync(modem_time_client,
				QMI_TIME_TURN_OFF_IND_REQ_MSG_V01,
				&ind_turn_off_req, sizeof(ind_turn_off_req),
				&ind_turn_off_rsp, sizeof(ind_turn_off_rsp), 1000);
		if (rc == QMI_NO_ERR && ind_turn_off_rsp.resp.error == 0)
			TIME_LOGD("%s: indication turn off request for msg_id %d success\n",
				__func__, ind_turn_off_req.msg_id);
		else
			TIME_LOGE("%s: indication turn off request for msg_id %d failed rc %d error %d\n",
			__func__, ind_turn_off_req.msg_id, rc, ind_turn_off_rsp.resp.error);

		/* Update the offset */
		pthread_mutex_lock(&genoff_mutex);
		genoff_update.base = resp_message.base;
		genoff_update.unit = TIME_MSEC;
		genoff_update.operation  = T_SET;
		genoff_update.ts_val = &resp_message.generic_offset;
		rc = genoff_opr(&genoff_update);
		if (rc)
			TIME_LOGE("Daemon:%s: Offset update failed\n",
					__func__);
		else
			TIME_LOGE("Daemon:%s: offset %d updated\n",
					__func__, resp_message.base);

		pthread_mutex_unlock(&genoff_mutex);
		//Update system time
		time_value = resp_message.generic_offset;
		tv.tv_sec = (time_t) MSEC_TO_SEC(time_value);
		tv.tv_usec = (long) ((time_value % 1000LL) * 1000LL);

		TIME_LOGE("%s: Updating system time to sec=%ld, usec=%ld\n",
			__func__, tv.tv_sec, tv.tv_usec);

		if (settimeofday(&tv, NULL) != 0)
		TIME_LOGE("%s: Unable to set clock to sec=%ldusec=%ld\n",
				__func__, tv.tv_sec,
				tv.tv_usec);

		TIME_LOGD("%s: Local Genoff update for base = %d , rc = %d\n",
				__func__, genoff_update.base, rc);

		pthread_mutex_lock(&qmi_clnt_mutex);
		modem_qmi_initialized = 1;
		pthread_mutex_unlock(&qmi_clnt_mutex);

		rc = qmi_cci_register_error_cb(modem_time_client, genoff_qmi_error_cb,
							NULL);
		if (rc != QMI_NO_ERR) {
		TIME_LOGE("Daemon:%s: register error cb failed %d\n",
							__func__, rc);
		qmi_cci_release(modem_time_client);
		modem_time_client = NULL;
		return NULL;
		}
	}

	/* QMI initialization Done */
	pthread_mutex_lock(&qmi_clnt_mutex);
	while (modem_qmi_initialized)
		pthread_cond_wait(&qmi_clnt_cond, &qmi_clnt_mutex);
	pthread_mutex_unlock(&qmi_clnt_mutex);
	}
}

int genoff_modem_qmi_init(void)
{
	int rc;
	struct timespec time;
	struct timeval now;

	modem_time_service_object = time_get_service_object_v01();
	if (!modem_time_service_object) {
		TIME_LOGE("Daemon:%s: time_get_service_object_v01 failed\n",
				__func__);
		return -EINVAL;
	}
	rc = qmi_cci_notifier_init(modem_time_service_object, &os_params,
					&notifier);
	if (rc != QMI_NO_ERR) {
		TIME_LOGE("Daemon:%s: Notifier init failed %d\n", __func__, rc);
		return -EINVAL;
	}

	rc = pthread_create(&qmi_clnt_thread, NULL,
				genoff_modem_qmi_service_handle_cb, NULL);
	if (rc != 0) {
		TIME_LOGE("Daemon:%s: Failed to create thread to handle modem qmi cb\n",
								__func__);
		qmi_cci_release(notifier);
		notifier = NULL;
		return -EINVAL;
	}

	/* Wait time is 1 sec */
	gettimeofday(&now, NULL);
	time.tv_sec = now.tv_sec + 1000 / 1000;
	time.tv_nsec = now.tv_usec + (1000 % 1000) * 1000000;

	/* Wait for qmi service handle thread creation */
	pthread_mutex_lock(&qmi_clnt_mutex);
	pthread_cond_timedwait(&qmi_serv_hdl_thread_cond, &qmi_clnt_mutex, &time);
	pthread_mutex_unlock(&qmi_clnt_mutex);

	rc = qmi_cci_register_notify_cb(notifier, time_service_modem_serv_notify_cb,
			NULL);

	if (rc != QMI_NO_ERR) {
		TIME_LOGE("Daemon:%s: Register Notifier cb failed %d\n", __func__, rc);
		qmi_cci_release(notifier);
		notifier = NULL;
		return -EINVAL;
	}
	return 0;
}

static void thread_func(void *param)
{
	/* Wait for termination of service */
	pthread_mutex_lock(&mutex);
	pthread_cond_wait(&cond, &mutex);

	TIME_LOGE("Time-services exitting .....\n");
	pthread_mutex_unlock(&mutex);
	pthread_mutex_destroy(&mutex);
	pthread_mutex_destroy(&genoff_mutex);
	pthread_cancel(read_time);
	pthread_cancel(time_thread);
	pthread_cancel(connection_mgr);
	pthread_detach(pthread_self());
	pthread_exit(NULL);

}

/* Thread for handling connections from genoff library */
static void conn_handler(void *recv_arg)
{
	int rc;
	int sock_id, recv_id, length, recv_val;
	struct sockaddr_un time_socket, time_recv;

	/* Start a server to accept connections from the shared library */
	sock_id = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock_id < 0) {
		TIME_LOGE("Daemon: Unable to create socket:time_genoff\n");
		pthread_exit(NULL);
	}
	time_socket.sun_family = AF_UNIX;
	strlcpy(time_socket.sun_path, GENOFF_SOCKET_NAME, UNIX_PATH_MAX);

	/* abstract domain socket */
	time_socket.sun_path[0] = 0;
	length = strlen(GENOFF_SOCKET_NAME) + sizeof(time_socket.sun_family);

	/* Remove any existing socket with the same name */
	unlink(time_socket.sun_path);
	if (bind(sock_id, (struct sockaddr *)&time_socket, length) < 0) {
		TIME_LOGE("Daemon: Unable to bind socket:time_genoff\n");
		goto err_close_socket;
	}

	if (listen(sock_id, GENOFF_MAX_CONCURRENT_CONN) < 0) {
		TIME_LOGE("Daemon: Unable to listen on socket:time_genoff\n");
		goto err_close_socket;
	}

	if (!disable_logging)
		TIME_LOGD("Daemon: Time-services: All initializations done\n");

	while (1) {
		/* Loop to accept connections from the shared library */
		if (!disable_logging)
			TIME_LOGE("Daemon: Time-services: Waiting to acceptconnection\n");
		errno = 0;
		recv_val = sizeof((struct sockaddr *) &time_recv);
		recv_id = accept(sock_id, (struct sockaddr *)&time_recv,
								&recv_val);
		if (recv_id < 0) {
			TIME_LOGE("Daemon: Unable to accept connection:time_genoff errno: %d\n",
							errno);
			continue;
		}

		if (!disable_logging)
			TIME_LOGD("Daemon: Connection accepted:time_genoff\n");

		/* Thread to handle this request */
		rc = pthread_create(&time_thread, NULL,
				(void *)&genoff_handler, (void *)&recv_id);
		if (rc < 0)
			TIME_LOGE("Daemon: Cannot create pthread:time_genoff\n");
		pthread_join(time_thread, NULL);
	}

err_close_socket:
	close(sock_id);
	pthread_exit(NULL);
}

/* Thread to handle full read */
static void read_offset(void *recv_arg)
{
	int rc = 0;
	uint64_t time_value;
	struct timeval tv;
	time_get_genoff_offset_req_msg_v01 time_request;
	static time_get_genoff_offset_resp_msg_v01 resp_message;
	struct time_genoff_info genoff_update;

	while (1) {
		pthread_mutex_lock(&indication.lock);
		if (!indication.ind_received)
			pthread_cond_wait(&read_cond,
						&indication.lock);

		TIME_LOGD("Daemon:%s: Sending read request for offset %d\n",
				__func__, indication.offset);

		memset(&time_request, 0, sizeof(time_request));
		memset(&resp_message, 0, sizeof(resp_message));

		time_request.base = indication.offset;
		rc = qmi_cci_send_msg_sync(modem_time_client,
				QMI_TIME_GENOFF_GET_REQ_MSG_V01,
				&time_request, sizeof(time_request),
				&resp_message, sizeof(resp_message), 1000);

		if (rc == QMI_NO_ERR &&	resp_message.resp.error == 0) {
			resp_message.generic_offset +=
				(uint64_t)SEC_TO_MSEC(MODEM_EPOCH_DIFFERENCE);
			TIME_LOGD("Daemon:%s:Time received %llu\n",
					__func__,
					resp_message.generic_offset);
		} else {
			TIME_LOGE("Daemon:%s: Error in reading full time ignoring update rc=%d"
					" resp=%d ", __func__, rc,
					resp_message.resp.error);
			pthread_mutex_unlock(&indication.lock);
			indication.ind_received = 0;
			continue;
		}

		/* Update the offset */
		pthread_mutex_lock(&genoff_mutex);
		genoff_update.base = resp_message.base;
		genoff_update.unit = TIME_MSEC;
		genoff_update.operation  = T_SET;
		genoff_update.ts_val = &resp_message.generic_offset;
		rc = genoff_opr(&genoff_update);
		if (rc)
			TIME_LOGE("Daemon:%s: Offset update failed\n",
							__func__);
		else
			TIME_LOGE("Daemon:%s: offset %d updated\n",
				__func__, resp_message.base);

		indication.ind_received = 0;

		//Update system time
		time_value = resp_message.generic_offset;
		tv.tv_sec = (time_t) MSEC_TO_SEC(time_value);
		tv.tv_usec = (long) ((time_value % 1000LL) * 1000LL);

		TIME_LOGE("%s: Updating system time to sec=%ld, usec=%ld\n",
				__func__, tv.tv_sec, tv.tv_usec);

		if (settimeofday(&tv, NULL) != 0)
			TIME_LOGE("%s: Unable to set clock to sec=%ldusec=%ld\n",
					__func__, tv.tv_sec,
					tv.tv_usec);

		TIME_LOGD("%s: Local Genoff update for base = %d , rc = %d\n",
				__func__, genoff_update.base, rc);

		pthread_mutex_unlock(&genoff_mutex);
		pthread_mutex_unlock(&indication.lock);

	}
}

int main(void)
{
	int rc;
	struct sigaction sa;

	sa.sa_handler = time_service_exit;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

#ifdef SYSLOG_ENABLE
	openlog(SYSLOG_PREFIX, LOG_NDELAY | LOG_PID | LOG_CONS, LOG_USER);
#endif

	if (sigaction(SIGTERM, &sa, NULL) == -1)
		TIME_LOGE("Sigaction error: graceful shutdown disabled\n");

	/* Initialization of bases */
	rc = genoff_init_config();
	if (rc) {
		TIME_LOGE(" Unable to initialize bases, exiting\n");
		goto error_return;
	}

	if (pthread_mutex_init(&genoff_mutex, NULL)) {
		TIME_LOGE(" Pthread mutex init failed\n");
		goto error_return;
	}

	if (pthread_mutex_init(&indication.lock, NULL)) {
		TIME_LOGE(" Pthread mutex init failed\n");
		goto error_return;
	}

	/* Initialize TOD if stored previously */
	if (genoff_boot_tod_init() < 0)
		TIME_LOGE(" Unable to set TOD at boot up\n");

	rc = genoff_modem_qmi_init();
	if (rc)
		TIME_LOGE(" QMI init failed, QMI calls inactive\n");

	/* Thread for readin full time from modem */
	rc = pthread_create(&read_time, NULL, (void *)read_offset, NULL);
	if (rc < 0) {
		TIME_LOGE("Daemon: Cannot create thread: read thread\n");
		goto out;
	}

	TIME_LOGE(" starting with pid (%d)\n", getpid());

	rc = pthread_create(&sleep_thread, NULL, (void *)thread_func,
			NULL);
	if (rc < 0) {
		TIME_LOGE("Daemon: Unable to create sleep thread exiting...\n");
		pthread_kill(read_time, SIGKILL);
		goto out;
	}

	/* Create  a thread to manage socket connection */
	rc = pthread_create(&connection_mgr, NULL, (void *)conn_handler,
			NULL);
	if (rc < 0) {
		TIME_LOGE("Daemon: Cannot create thread:connection_mgr\n");
		pthread_kill(read_time, SIGKILL);
		pthread_kill(sleep_thread, SIGKILL);
		goto error_return;
	}

	rc = pthread_join(sleep_thread, NULL);
	TIME_LOGE("Daemon: Connection thread joined closing QMI connectionand exiting ...\n");

out:
	if (modem_qmi_initialized) {
		qmi_cci_release(modem_time_client);
		modem_time_client = NULL;
	}
	return 0;

error_return:
	return -EINVAL;
}

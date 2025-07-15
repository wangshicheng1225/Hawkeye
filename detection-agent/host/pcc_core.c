/*
 * Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>

#include <doca_argp.h>

#include "pcc_core.h"

/*
 * Formats of the trace message to be printed from the device
 */
static char *trace_message_formats[] = {
	"format 0 - user init: port num = %#lx, algo index = %#lx, algo slot = %#lx, algo enable = %#lx, disable event bitmask = %#lx\n",
	"format 1 - user algo: algo slot = %#lx, result rate = %#lx, result rtt req = %#lx, port num = %#lx, timestamp = %#lx\n",
	NULL};

/* Default PCC RP threads */
const uint32_t default_pcc_rp_threads_list[PCC_RP_THREADS_NUM_DEFAULT_VALUE] = {
	176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 192, 193, 194, 195, 196,
	197, 198, 199, 200, 201, 202, 203, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217,
	218, 219, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 240};
/* Default PCC NP threads */
const uint32_t default_pcc_np_threads_list[PCC_NP_THREADS_NUM_DEFAULT_VALUE] =
	{16, 17, 18, 19, 20, 21, 22, 23, 32, 33, 34, 35, 36, 37, 38, 39};
/*
 * Declare default threads flag
 */
static bool use_default_threads = true;

/*
 * Check if the provided device name is a name of a valid IB device
 *
 * @device_name [in]: The wanted IB device name
 * @role [in]: Role of the PCC context
 * @return: True if device_name is an IB device, false otherwise.
 */
static bool pcc_device_exists_check(const char *device_name)
{
	struct doca_devinfo **dev_list;
	uint32_t nb_devs = 0;
	doca_error_t result;
	bool exists = false;
	char ibdev_name[DOCA_DEVINFO_IBDEV_NAME_SIZE] = {0};
	uint32_t i = 0;

	result = doca_devinfo_create_list(&dev_list, &nb_devs);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to load DOCA devices list: %s\n", doca_error_get_descr(result));
		return false;
	}

	/* Search device with same device name */
	for (i = 0; i < nb_devs; i++) {
		result = doca_devinfo_get_ibdev_name(dev_list[i], ibdev_name, sizeof(ibdev_name));
		if (result != DOCA_SUCCESS)
			continue;

		/* Check if we found the device with the wanted name */
		if (strncmp(device_name, ibdev_name, DOCA_DEVINFO_IBDEV_NAME_SIZE) == 0) {
			exists = true;
			break;
		}
	}

	doca_devinfo_destroy_list(dev_list);

	return exists;
}

/*
 * Open DOCA device that supports PCC
 *
 * @device_name [in]: Requested IB device name
 * @role [in]: Role of the PCC context
 * @doca_device [out]: An allocated DOCA device that supports PCC on success and NULL otherwise
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t open_pcc_device(const char *device_name, pcc_role_t role, struct doca_dev **doca_device)
{
	struct doca_devinfo **dev_list;
	uint32_t nb_devs = 0;
	doca_error_t result;
	char ibdev_name[DOCA_DEVINFO_IBDEV_NAME_SIZE] = {0};
	uint32_t i = 0;

	result = doca_devinfo_create_list(&dev_list, &nb_devs);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to load DOCA devices list: %s\n", doca_error_get_descr(result));
		return result;
	}

	/* Search device with same device name and PCC capabilites supported */
	for (i = 0; i < nb_devs; i++) {
		if (role == PCC_ROLE_RP)
			result = doca_devinfo_get_is_pcc_supported(dev_list[i]);
		else if (role == PCC_ROLE_NP)
			result = doca_pcc_np_cap_is_supported(dev_list[i]);
		if (result != DOCA_SUCCESS)
			continue;
		result = doca_devinfo_get_ibdev_name(dev_list[i], ibdev_name, sizeof(ibdev_name));
		if (result != DOCA_SUCCESS)
			continue;

		/* Check if the device has the requested device name */
		if (strncmp(device_name, ibdev_name, DOCA_DEVINFO_IBDEV_NAME_SIZE) != 0)
			continue;

		result = doca_dev_open(dev_list[i], doca_device);
		if (result != DOCA_SUCCESS) {
			doca_devinfo_destroy_list(dev_list);
			PRINT_ERROR("Error: Failed to open DOCA device: %s\n", doca_error_get_descr(result));
			return result;
		}
		break;
	}

	doca_devinfo_destroy_list(dev_list);

	if (*doca_device == NULL) {
		PRINT_ERROR("Error: Couldn't get DOCA device\n");
		return DOCA_ERROR_NOT_FOUND;
	}

	return result;
}

doca_error_t pcc_init(struct pcc_config *cfg, struct pcc_resources *resources)
{
	doca_error_t result, tmp_result;
	uint32_t min_num_threads, max_num_threads;

	/* Open DOCA device that supports PCC */
	result = open_pcc_device(cfg->device_name, cfg->role, &(resources->doca_device));
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to open DOCA device that supports PCC\n");
		return result;
	}

	/* Create DOCA PCC context */
	if (cfg->role == PCC_ROLE_RP)
		result = doca_pcc_create(resources->doca_device, &(resources->doca_pcc));
	else if (cfg->role == PCC_ROLE_NP)
		result = doca_pcc_np_create(resources->doca_device, &(resources->doca_pcc));
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create DOCA PCC context\n");
		goto close_doca_dev;
	}

	/* Define default threads if not set according to role */
	if (use_default_threads) {
		if (cfg->role == PCC_ROLE_RP) {
			memcpy(cfg->threads_list, default_pcc_rp_threads_list, sizeof(default_pcc_rp_threads_list));
			cfg->threads_num = PCC_RP_THREADS_NUM_DEFAULT_VALUE;
		} else if (cfg->role == PCC_ROLE_NP) {
			memcpy(cfg->threads_list, default_pcc_np_threads_list, sizeof(default_pcc_np_threads_list));
			cfg->threads_num = PCC_NP_THREADS_NUM_DEFAULT_VALUE;
		}
	}

	result = doca_pcc_get_min_num_threads(resources->doca_pcc, &min_num_threads);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Failed to get minimum DOCA PCC number of threads\n");
		goto destroy_pcc;
	}

	result = doca_pcc_get_max_num_threads(resources->doca_pcc, &max_num_threads);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Failed to get maximum DOCA PCC number of threads\n");
		goto destroy_pcc;
	}

	if (cfg->threads_num < min_num_threads || cfg->threads_num > max_num_threads) {
		PRINT_ERROR(
			"Invalid number of PCC threads: %u. The Minimum number of PCC threads is %d and the maximum number of PCC threads is %d\n",
			cfg->threads_num,
			min_num_threads,
			max_num_threads);
		result = DOCA_ERROR_INVALID_VALUE;
		goto destroy_pcc;
	}

	result = doca_pcc_set_app(resources->doca_pcc, cfg->app);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to set DOCA PCC app\n");
		goto destroy_pcc;
	}

	/* Set DOCA PCC thread affinity */
	result = doca_pcc_set_thread_affinity(resources->doca_pcc, cfg->threads_num, cfg->threads_list);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to set thread affinity for DOCA PCC\n");
		goto destroy_pcc;
	}

	/* Set DOCA PCC probe packet format */
	switch (cfg->probe_packet_format) {
	case PCC_DEV_PROBE_PACKET_CCMAD:
		result = doca_pcc_set_ccmad_probe_packet_format(resources->doca_pcc, 0);
		if (result != DOCA_SUCCESS) {
			PRINT_ERROR("Error: Failed to set CCMAD probe packet format for DOCA PCC\n");
			goto destroy_pcc;
		}
		if (cfg->role == PCC_ROLE_RP) {
			result =
				doca_pcc_rp_set_ccmad_remote_sw_handler(resources->doca_pcc, 0, cfg->remote_sw_handler);
			if (result != DOCA_SUCCESS) {
				PRINT_ERROR("Error: Failed to set CCMAD remote SW handler for DOCA PCC\n");
				goto destroy_pcc;
			}
		}
		break;
	case PCC_DEV_PROBE_PACKET_IFA1:
		result = doca_pcc_set_ifa1_probe_packet_format(resources->doca_pcc, 0);
		if (result != DOCA_SUCCESS) {
			PRINT_ERROR("Error: Failed to set IFA1 probe packet format for DOCA PCC\n");
			goto destroy_pcc;
		}
		break;
	case PCC_DEV_PROBE_PACKET_IFA2:
		result = doca_pcc_set_ifa2_probe_packet_format(resources->doca_pcc, 0);
		if (result != DOCA_SUCCESS) {
			PRINT_ERROR("Error: Failed to set IFA2 probe packet format for DOCA PCC\n");
			goto destroy_pcc;
		}
		if (cfg->role == PCC_ROLE_RP) {
			result = doca_pcc_rp_set_ifa2_gns(resources->doca_pcc, 0, cfg->gns);
			if (result != DOCA_SUCCESS) {
				PRINT_ERROR("Error: Failed to set IFA2 GNS for DOCA PCC\n");
				goto destroy_pcc;
			}
		} else if (cfg->role == PCC_ROLE_NP) {
			result = doca_pcc_np_set_ifa2_gns_ignore(resources->doca_pcc,
								 0,
								 cfg->gns_ignore_mask,
								 cfg->gns_ignore_value);
			if (result != DOCA_SUCCESS) {
				PRINT_ERROR("Error: Failed to set IFA2 GNS ignore for DOCA PCC\n");
				goto destroy_pcc;
			}
		}
		break;
	}

	/* Set DOCA PCC print buffer size */
	result = doca_pcc_set_print_buffer_size(resources->doca_pcc, PCC_PRINT_BUFFER_SIZE_DEFAULT_VALUE);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to set print buffer size for DOCA PCC\n");
		goto destroy_pcc;
	}

	/* Set DOCA PCC trace message formats */
	result = doca_pcc_set_trace_message(resources->doca_pcc, trace_message_formats);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to set trace message for DOCA PCC\n");
		goto destroy_pcc;
	}

	/* Set DOCA PCC coredump file pathname */
	result = doca_pcc_set_dev_coredump_file(resources->doca_pcc, cfg->coredump_file);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to set cordump file for DOCA PCC\n");
		goto destroy_pcc;
	}

	/* Set DOCA PCC mailbox */
	result = doca_pcc_set_mailbox(resources->doca_pcc, PCC_MAILBOX_REQUEST_SIZE, PCC_MAILBOX_RESPONSE_SIZE);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to set mailbox for DOCA PCC\n");
		goto destroy_pcc;
	}

	return result;

destroy_pcc:
	tmp_result = doca_pcc_destroy(resources->doca_pcc);
	if (tmp_result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to destroy DOCA PCC context: %s\n", doca_error_get_descr(result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
close_doca_dev:
	tmp_result = doca_dev_close(resources->doca_device);
	if (tmp_result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to close DOCA device: %s\n", doca_error_get_descr(result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	return result;
}

void print_flow_metas(struct pcc_config *cfg, struct flow_meta *flow_metas) {
	printf("\n\nstart to print flow metas\n");
	for (uint32_t i = 0; i < MAX_NB_FLOWS; i ++) {
		struct flow_meta flow_meta = flow_metas[i];
		if(flow_meta.rtt > cfg->rtt_threshold && flow_meta.flowtag != 0) {
			printf("flowtag is %u\n", flow_meta.flowtag);
			printf("rtt is %u\n", flow_meta.rtt);
			printf("src ip is: ");
			for(uint32_t i = 0; i < 4; i++)
				printf("%u%c", ((uint8_t *)&(flow_meta.src_ip))[i], i < 3 ? '.' : '\n');
			printf("dst ip is: ");
			for(uint32_t i = 0; i < 4; i++)
				printf("%u%c", ((uint8_t *)&(flow_meta.dst_ip))[i], i < 3 ? '.' : '\n');
			printf("src port is: %u\n", flow_meta.src_port);
			printf("dst port is: %u\n", flow_meta.dst_port);
		}
	}
	printf("finished printing flow metas\n\n\n");
}

doca_error_t get_flow_metas(struct pcc_resources *resources, struct flow_meta *flow_metas) {
	doca_error_t result;
	uint32_t *request_buf;
	void *response_buf;
	uint32_t response_size, cb_ret_val;

	/* Get the request buffer of the mailbox */
	result = doca_pcc_mailbox_get_request_buffer(resources->doca_pcc, (void **)&request_buf);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to get the request buffer of the PCC mailbox\n");
		return result;
	}

	*request_buf = GET_FLOW_INFO_OP;

	result = doca_pcc_mailbox_send(resources->doca_pcc, PCC_MAILBOX_REQUEST_SIZE, &response_size, &cb_ret_val);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: fuck\n");
		PRINT_ERROR("Error: Failed to send the PCC mailbox request buffer\n");
		return result;
	}

	if (cb_ret_val != 0) {
		PRINT_ERROR("Error: Mailbox callback returned error status\n");
		return DOCA_ERROR_UNEXPECTED;
	}

	if(response_size != sizeof(struct flow_meta) * MAX_NB_FLOWS) {
		PRINT_ERROR("Error: Failed to get expected flow metadatas\n");
		return DOCA_ERROR_UNEXPECTED;
	}
	
	result = doca_pcc_mailbox_get_response_buffer(resources->doca_pcc, &response_buf);
	if(result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to get flow meta response\n");
		return result;
	}

	memcpy((void *)flow_metas, (void *)response_buf, response_size);

	return DOCA_SUCCESS;
}

doca_error_t pcc_mailbox_send(struct pcc_config *cfg, struct pcc_resources *resources)
{
	doca_error_t result;
	uint32_t *request_buf;
	uint32_t response_size, cb_ret_val;

	/* Get the request buffer of the mailbox */
	result = doca_pcc_mailbox_get_request_buffer(resources->doca_pcc, (void **)&request_buf);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to get the request buffer of the PCC mailbox\n");
		return result;
	}

	if (cfg->role == PCC_ROLE_NP) /* send port id to device */
		*request_buf = cfg->port_id;
	else if (cfg->role == PCC_ROLE_RP) { /* send port bandwidth to device */
		/* Get the bandwidth of the device port */
		double port_active_rate;

		result = doca_devinfo_get_active_rate(doca_dev_as_devinfo(resources->doca_device), &port_active_rate);
		if (result != DOCA_SUCCESS) {
			PRINT_ERROR("Error: Failed to get active rate for DOCA device\n");
			return result;
		}
		/* convert bandwidth from Gb/s to MB/s units */
		port_active_rate = ((port_active_rate * 1000) / 8);
		/* set the buffer value to the port bandwidth */
		*request_buf = (uint32_t)(port_active_rate);
	}

	/* Send the request buffer that holds the ports bandwidth */
	result = doca_pcc_mailbox_send(resources->doca_pcc, PCC_MAILBOX_REQUEST_SIZE, &response_size, &cb_ret_val);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to send the PCC mailbox request buffer\n");
		return result;
	}

	if (cb_ret_val != 0) {
		PRINT_ERROR("Error: Mailbox callback returned error status\n");
		return DOCA_ERROR_UNEXPECTED;
	}

	return DOCA_SUCCESS;
}

doca_error_t pcc_destroy(struct pcc_resources *resources)
{
	doca_error_t result, tmp_result;

	result = doca_pcc_destroy(resources->doca_pcc);
	if (result != DOCA_SUCCESS)
		PRINT_ERROR("Error: Failed to destroy DOCA PCC context: %s\n", doca_error_get_descr(result));

	tmp_result = doca_dev_close(resources->doca_device);
	if (tmp_result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to close DOCA device: %s\n", doca_error_get_descr(result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	return result;
}

/*
 * ARGP Callback - Handle IB device name parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t device_name_callback(void *param, void *config)
{
	struct pcc_config *pcc_cfg = (struct pcc_config *)config;
	char *device_name = (char *)param;
	int len;

	len = strnlen(device_name, DOCA_DEVINFO_IBDEV_NAME_SIZE);
	if (len == DOCA_DEVINFO_IBDEV_NAME_SIZE) {
		PRINT_ERROR("Error: Entered IB device name exceeding the maximum size of %d\n",
			    DOCA_DEVINFO_IBDEV_NAME_SIZE - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}
	strncpy(pcc_cfg->device_name, device_name, len + 1);

	if (!pcc_device_exists_check(pcc_cfg->device_name)) {
		PRINT_ERROR("Error: Entered IB device name: %s doesn't exist\n", pcc_cfg->device_name);
		return DOCA_ERROR_INVALID_VALUE;
	}

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle PCC NP NIC Telemetry parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t np_nic_telemetry_callback(void *param, void *config)
{
	struct pcc_config *pcc_cfg = (struct pcc_config *)config;
	bool np_nic_telemetry = *((bool *)param);

	if (np_nic_telemetry) {
		pcc_cfg->app = pcc_np_nic_telemetry_app;
		pcc_cfg->role = PCC_ROLE_NP;
	}

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle PCC threads list parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t threads_list_callback(void *param, void *config)
{
	struct pcc_config *pcc_cfg = (struct pcc_config *)config;
	char *threads_list_string = (char *)param;
	static const char delim[2] = " ";
	char *curr_pcc_string;
	int curr_pcc_check, i, len;
	uint32_t curr_pcc;

	len = strnlen(threads_list_string, MAX_ARG_SIZE);
	if (len == MAX_ARG_SIZE) {
		PRINT_ERROR("Error: Entered PCC threads list exceeded buffer size: %d\n", MAX_USER_ARG_SIZE);
		return DOCA_ERROR_INVALID_VALUE;
	}

	use_default_threads = false;
	pcc_cfg->threads_num = 0;

	/* Check and fill out the PCC threads list */
	/* Get the first PCC thread number */
	curr_pcc_string = strtok(threads_list_string, delim);
	if (curr_pcc_string == NULL) {
		PRINT_ERROR("Error: Invalid PCC threads list: %s\n", threads_list_string);
		return DOCA_ERROR_INVALID_VALUE;
	}

	/* Walk through rest of the PCC threads numbers */
	while (curr_pcc_string != NULL) {
		/* Check if it's a number by checking its digits */
		len = strnlen(threads_list_string, MAX_ARG_SIZE);
		for (i = 0; i < len; i++) {
			if (!isdigit(curr_pcc_string[i])) {
				PRINT_ERROR("Error: Invalid PCC thread number: %s\n", curr_pcc_string);
				return DOCA_ERROR_INVALID_VALUE;
			}
		}

		/* Convert to integer to check if it is non-negative */
		curr_pcc_check = (int)atoi(curr_pcc_string);
		if (curr_pcc_check < 0) {
			PRINT_ERROR("Error: Invalid PCC thread number %d. PCC threads numbers must be non-negative\n",
				    curr_pcc_check);
			return DOCA_ERROR_INVALID_VALUE;
		}

		curr_pcc = (uint32_t)atoi(curr_pcc_string);
		pcc_cfg->threads_list[pcc_cfg->threads_num++] = curr_pcc;
		curr_pcc_string = strtok(NULL, delim);
	}

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle PCC wait time parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t wait_time_callback(void *param, void *config)
{
	struct pcc_config *pcc_cfg = (struct pcc_config *)config;
	int wait_time = *((int *)param);

	/* Wait time must be either positive or infinity (meaning -1 )*/
	if (wait_time == 0) {
		PRINT_ERROR(
			"Error: Entered wait time can't be zero. Must be either positive or infinity (meaning negative value)\n");
		return DOCA_ERROR_INVALID_VALUE;
	}

	pcc_cfg->wait_time = wait_time;

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle PCC probe packet format parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t probe_packet_format_callback(void *param, void *config)
{
	struct pcc_config *pcc_cfg = (struct pcc_config *)config;
	int probe_packet_format = *((int *)param);

	if (!((probe_packet_format == PCC_DEV_PROBE_PACKET_CCMAD) ||
	      (probe_packet_format == PCC_DEV_PROBE_PACKET_IFA1) ||
	      (probe_packet_format == PCC_DEV_PROBE_PACKET_IFA2))) {
		PRINT_ERROR(
			"Error: Entered invalid probe packet format %d. Must be one of the following values: %d, %d, %d\n",
			probe_packet_format,
			PCC_DEV_PROBE_PACKET_CCMAD,
			PCC_DEV_PROBE_PACKET_IFA1,
			PCC_DEV_PROBE_PACKET_IFA2);
		return DOCA_ERROR_INVALID_VALUE;
	}

	pcc_cfg->probe_packet_format = probe_packet_format;

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle PCC remote SW handler parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t ccmad_remote_sw_handler_callback(void *param, void *config)
{
	struct pcc_config *pcc_cfg = (struct pcc_config *)config;

	pcc_cfg->remote_sw_handler = *((bool *)param);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle PCC gns parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t ifa2_gns_callback(void *param, void *config)
{
	struct pcc_config *pcc_cfg = (struct pcc_config *)config;

	pcc_cfg->gns = *((uint8_t *)param);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle PCC gns ignore mask parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t ifa2_gns_ignore_mask_callback(void *param, void *config)
{
	struct pcc_config *pcc_cfg = (struct pcc_config *)config;

	pcc_cfg->gns_ignore_mask = *((uint8_t *)param);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle PCC gns ignore value parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t ifa2_gns_ignore_value_callback(void *param, void *config)
{
	struct pcc_config *pcc_cfg = (struct pcc_config *)config;

	pcc_cfg->gns_ignore_value = *((uint8_t *)param);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle PCC device coredump file parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t coredump_file_callback(void *param, void *config)
{
	struct pcc_config *pcc_cfg = (struct pcc_config *)config;
	const char *path = (char *)param;
	int path_len;

	path_len = strnlen(path, MAX_ARG_SIZE);
	if (path_len == MAX_ARG_SIZE) {
		PRINT_ERROR("Entered path exceeded buffer size: %d\n", MAX_USER_ARG_SIZE);
		return DOCA_ERROR_INVALID_VALUE;
	}

	/* The string will be '\0' terminated due to the strnlen check above */
	strncpy(pcc_cfg->coredump_file, path, path_len + 1);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle PCC port ID parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t port_id_callback(void *param, void *config)
{
	struct pcc_config *pcc_cfg = (struct pcc_config *)config;
	int port_id = *((int *)param);

	if (port_id > (NUM_AVAILABLE_PORTS - 1)) {
		PRINT_ERROR("Error: Entered port ID %d is not available. Maximum port ID available is %d\n",
			    port_id,
			    (NUM_AVAILABLE_PORTS - 1));
		return DOCA_ERROR_INVALID_VALUE;
	}

	pcc_cfg->port_id = port_id;

	return DOCA_SUCCESS;
}

static doca_error_t rtt_threshold_callback(void *param, void *config) {
	struct pcc_config *pcc_cfg = (struct pcc_config *)config;
	uint32_t rtt_threshold = *(uint32_t *)param;
	pcc_cfg->rtt_threshold = rtt_threshold;
	return DOCA_SUCCESS;
}

doca_error_t register_pcc_params(void)
{
	doca_error_t result;
	struct doca_argp_param *device_param;
	struct doca_argp_param *np_nic_telemetry_param;
	struct doca_argp_param *threads_list_param;
	struct doca_argp_param *wait_time_param;
	struct doca_argp_param *probe_packet_format_param;
	struct doca_argp_param *remote_sw_handler_param;
	struct doca_argp_param *gns_param;
	struct doca_argp_param *rtt_param;
	struct doca_argp_param *gns_ignore_mask_param;
	struct doca_argp_param *gns_ignore_value_param;
	struct doca_argp_param *coredump_file_param;
	struct doca_argp_param *port_id_param;

	/* Create and register DOCA device name parameter */
	result = doca_argp_param_create(&device_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create ARGP param: %s\n", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(device_param, "d");
	doca_argp_param_set_long_name(device_param, "device");
	doca_argp_param_set_arguments(device_param, "<IB device names>");
	doca_argp_param_set_description(device_param, "IB device name that supports PCC (mandatory).");
	doca_argp_param_set_callback(device_param, device_name_callback);
	doca_argp_param_set_type(device_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(device_param);
	result = doca_argp_register_param(device_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register program param: %s\n", doca_error_get_descr(result));
		return result;
	}

	/* Create and register PCC NP NIC Telemetry parameter */
	result = doca_argp_param_create(&np_nic_telemetry_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create ARGP param: %s\n", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(np_nic_telemetry_param, "np-nt");
	doca_argp_param_set_long_name(np_nic_telemetry_param, "np-nic-telemetry");
	doca_argp_param_set_arguments(np_nic_telemetry_param, "<PCC Notification Point NIC Telemetry>");
	doca_argp_param_set_description(
		np_nic_telemetry_param,
		"Flag to indicate running as a Notification Point NIC Telemetry (optional). By default the flag is set to false.");
	doca_argp_param_set_callback(np_nic_telemetry_param, np_nic_telemetry_callback);
	doca_argp_param_set_type(np_nic_telemetry_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(np_nic_telemetry_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register program param: %s\n", doca_error_get_descr(result));
		return result;
	}

	/* Create and register PCC threads list parameter */
	result = doca_argp_param_create(&threads_list_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create ARGP param: %s\n", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(threads_list_param, "t");
	doca_argp_param_set_long_name(threads_list_param, "threads");
	doca_argp_param_set_arguments(threads_list_param, "<PCC threads list>");
	doca_argp_param_set_description(
		threads_list_param,
		"A list of the PCC threads numbers to be chosen for the DOCA PCC context to run on (optional). Must be provided as a string, such that the number are separated by a space.");
	doca_argp_param_set_callback(threads_list_param, threads_list_callback);
	doca_argp_param_set_type(threads_list_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(threads_list_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register program param: %s\n", doca_error_get_descr(result));
		return result;
	}

	/* Create and register PCC wait time parameter */
	result = doca_argp_param_create(&wait_time_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create ARGP param: %s\n", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(wait_time_param, "w");
	doca_argp_param_set_long_name(wait_time_param, "wait-time");
	doca_argp_param_set_arguments(wait_time_param, "<PCC wait time>");
	doca_argp_param_set_description(
		wait_time_param,
		"The duration of the DOCA PCC wait (optional), can provide negative values which means infinity. If not provided then -1 will be chosen.");
	doca_argp_param_set_callback(wait_time_param, wait_time_callback);
	doca_argp_param_set_type(wait_time_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(wait_time_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register program param: %s\n", doca_error_get_descr(result));
		return result;
	}

	/* Create and register PCC probe packet format parameter */
	result = doca_argp_param_create(&probe_packet_format_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create ARGP param: %s\n", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(probe_packet_format_param, "p");
	doca_argp_param_set_long_name(probe_packet_format_param, "probe-packet-format");
	doca_argp_param_set_arguments(probe_packet_format_param, "<PCC probe-packet format>");
	doca_argp_param_set_description(
		probe_packet_format_param,
		"The probe packet format of the DOCA PCC (optional). Available values for each type: CCMAD-0, IFA1-1, IFA2-2. By default format is set to CCMAD.");
	doca_argp_param_set_callback(probe_packet_format_param, probe_packet_format_callback);
	doca_argp_param_set_type(probe_packet_format_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(probe_packet_format_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register program param: %s\n", doca_error_get_descr(result));
		return result;
	}

	/* Create and register PCC remote SW handler */
	result = doca_argp_param_create(&remote_sw_handler_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create ARGP param: %s\n", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(remote_sw_handler_param, "r-handler");
	doca_argp_param_set_long_name(remote_sw_handler_param, "remote-sw-handler");
	doca_argp_param_set_arguments(remote_sw_handler_param, "<CCMAD remote SW handler>");
	doca_argp_param_set_description(
		remote_sw_handler_param,
		"CCMAD remote SW handler flag (optional). If not provided then false will be chosen.");
	doca_argp_param_set_callback(remote_sw_handler_param, ccmad_remote_sw_handler_callback);
	doca_argp_param_set_type(remote_sw_handler_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(remote_sw_handler_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register program param: %s\n", doca_error_get_descr(result));
		return result;
	}

	/* Create and register PCC gns parameter */
	result = doca_argp_param_create(&gns_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create ARGP param: %s\n", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(gns_param, "gns");
	doca_argp_param_set_long_name(gns_param, "global-namespace");
	doca_argp_param_set_arguments(gns_param, "<IFA2 global namespace>");
	doca_argp_param_set_description(
		gns_param,
		"The IFA2 probe packet global namespace (optional). If not provided then 0XF will be chosen.");
	doca_argp_param_set_callback(gns_param, ifa2_gns_callback);
	doca_argp_param_set_type(gns_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(gns_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register program param: %s\n", doca_error_get_descr(result));
		return result;
	}

	/* Create and register PCC gns ignore mask parameter */
	result = doca_argp_param_create(&gns_ignore_mask_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create ARGP param: %s\n", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(gns_ignore_mask_param, "gns-ignore_mask");
	doca_argp_param_set_long_name(gns_ignore_mask_param, "global-namespace-ignore-mask");
	doca_argp_param_set_arguments(gns_ignore_mask_param, "<IFA2 global namespace ignore mask>");
	doca_argp_param_set_description(
		gns_ignore_mask_param,
		"The IFA2 probe packet global namespace ignore mask (optional). If not provided then 0 will be chosen.");
	doca_argp_param_set_callback(gns_ignore_mask_param, ifa2_gns_ignore_mask_callback);
	doca_argp_param_set_type(gns_ignore_mask_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(gns_ignore_mask_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register program param: %s\n", doca_error_get_descr(result));
		return result;
	}

	/* Create and register PCC gns ignore value parameter */
	result = doca_argp_param_create(&gns_ignore_value_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create ARGP param: %s\n", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(gns_ignore_value_param, "gns-ignore_val");
	doca_argp_param_set_long_name(gns_ignore_value_param, "global-namespace-ignore-value");
	doca_argp_param_set_arguments(gns_ignore_value_param, "<IFA2 global namespace ignore value>");
	doca_argp_param_set_description(
		gns_ignore_value_param,
		"The IFA2 probe packet global namespace ignore value (optional). If not provided then 0 will be chosen.");
	doca_argp_param_set_callback(gns_ignore_value_param, ifa2_gns_ignore_value_callback);
	doca_argp_param_set_type(gns_ignore_value_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(gns_ignore_value_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register program param: %s\n", doca_error_get_descr(result));
		return result;
	}

	/* Create and register PCC device coredump file parameter */
	result = doca_argp_param_create(&coredump_file_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create ARGP param: %s\n", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(coredump_file_param, "f");
	doca_argp_param_set_long_name(coredump_file_param, "coredump-file");
	doca_argp_param_set_arguments(coredump_file_param, "<PCC coredump file>");
	doca_argp_param_set_description(
		coredump_file_param,
		"A pathname to the file to write coredump data in case of unrecoverable error on the device (optional). Must be provided as a string.");
	doca_argp_param_set_callback(coredump_file_param, coredump_file_callback);
	doca_argp_param_set_type(coredump_file_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(coredump_file_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register program param: %s\n", doca_error_get_descr(result));
		return result;
	}

	/* Create and register physical port ID parameter */
	result = doca_argp_param_create(&port_id_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create ARGP param: %s\n", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(port_id_param, "i");
	doca_argp_param_set_long_name(port_id_param, "port-id");
	doca_argp_param_set_arguments(port_id_param, "<Physical port ID>");
	doca_argp_param_set_description(
		port_id_param,
		"The physical port ID of the device running the application (optional). If not provided then ID 0 will be chosen.");
	doca_argp_param_set_callback(port_id_param, port_id_callback);
	doca_argp_param_set_type(port_id_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(port_id_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register program param: %s\n", doca_error_get_descr(result));
		return result;
	}

	/* Create and register RTT threshold parameter */
	result = doca_argp_param_create(&rtt_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to create ARGP param: %s\n", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(rtt_param, "rtt");
	doca_argp_param_set_long_name(rtt_param, "rtt_threshold");
	doca_argp_param_set_arguments(rtt_param, "<rtt_threshold>");
	doca_argp_param_set_description( rtt_param, "RTT threshold");
	doca_argp_param_set_callback(rtt_param, rtt_threshold_callback);
	doca_argp_param_set_type(rtt_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(rtt_param);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register program param: %s\n", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

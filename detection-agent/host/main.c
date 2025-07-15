#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_pcc.h>
#include <unistd.h>
#include <sys/time.h>

#include "pcc_core.h"
#include "detection_agent.h"

static const char *status_str[DOCA_PCC_PS_ERROR + 1] = {"Active", "Standby", "Deactivated", "Error"};
static bool host_stop;
int log_level;

struct config_t config = {
    "mlx5_0",  /* dev_name */
    NULL,  /* server_name */
    19875, /* tcp_port */
    1,     /* ib_port */
    -1,    /* gid_idx */
    0,     /* udp_sport */
    1000   /* rtt_threshold */
};
struct polling_config_t polling_config;

struct flow_meta flow_metas[MAX_NB_FLOWS];

/*
 * Signal sigint handler
 *
 * @dummy [in]: Dummy parameter because this handler must accept parameter of type int
 */
static void sigint_handler(int dummy)
{
	(void)dummy;
	host_stop = true;
	signal(SIGINT, SIG_DFL);
}

/*
 * Application main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv)
{
	struct pcc_config cfg = {0};
	struct pcc_resources resources = {0};
	doca_pcc_process_state_t process_status;
	doca_error_t result, tmp_result;
	int exit_status = EXIT_FAILURE;

	/* Set the default configuration values (Example values) */
	cfg.wait_time = -1;
	cfg.role = PCC_ROLE_RP;
	cfg.app = pcc_rp_app;
	memcpy(cfg.threads_list, default_pcc_rp_threads_list, sizeof(default_pcc_rp_threads_list));
	cfg.threads_num = PCC_RP_THREADS_NUM_DEFAULT_VALUE;
	cfg.probe_packet_format = PCC_DEV_PROBE_PACKET_CCMAD;
	cfg.remote_sw_handler = true;
	cfg.gns = IFA2_GNS_DEFAULT_VALUE;
	cfg.gns_ignore_value = IFA2_GNS_IGNORE_DEFAULT_VALUE;
	cfg.gns_ignore_mask = IFA2_GNS_IGNORE_DEFAULT_MASK;
	strcpy(cfg.coredump_file, PCC_COREDUMP_FILE_DEFAULT_PATH);
	cfg.port_id = PCC_PHYSICAL_PORT_DEFAULT_ID;
	log_level = LOG_LEVEL_INFO;
    cfg.rtt_threshold = 1000000000;

	/* Add SIGINT signal handler for graceful exit */
	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
		PRINT_ERROR("Error: SIGINT error\n");
		return DOCA_ERROR_OPERATING_SYSTEM;
	}


	/* Initialize argparser */
	result = doca_argp_init("doca_pcc", &cfg);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to init ARGP resources: %s\n", doca_error_get_descr(result));
		return EXIT_FAILURE;
	}

	/* Register DOCA PCC application params */
	result = register_pcc_params();
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to register parameters: %s\n", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	/* Start argparser */
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to parse input: %s\n", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	/* Get the log level */
	result = doca_argp_get_log_level(&log_level);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to get log level: %s\n", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	/* Initialize DOCA PCC application resources */
	result = pcc_init(&cfg, &resources);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to initialize PCC resources: %s\n", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	PRINT_INFO("Info: Welcome to DOCA Programable Congestion Control (PCC) application\n");
	PRINT_INFO("Info: Starting DOCA PCC\n");

	/* Start DOCA PCC */
	result = doca_pcc_start(resources.doca_pcc);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to start PCC\n");
		goto destroy_pcc;
	}

	/* Send request to device */
	result = pcc_mailbox_send(&cfg, &resources);
	if (result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to send mailbox request\n");
		goto destroy_pcc;
	}

	host_stop = false;
	PRINT_INFO("Info: Press ctrl + C to exit\n");


	while (!host_stop) {
		result = doca_pcc_get_process_state(resources.doca_pcc, &process_status);
		if (result != DOCA_SUCCESS) {
			PRINT_ERROR("Error: Failed to query PCC\n");
			goto destroy_pcc;
		}

		if (process_status == DOCA_PCC_PS_DEACTIVATED || process_status == DOCA_PCC_PS_ERROR) {
            PRINT_INFO("Info: PCC host status %s\n", status_str[process_status]);
			break;
        }


		if(process_status == DOCA_PCC_PS_ACTIVE) {
			result = get_flow_metas(&resources, flow_metas);
			if (result != DOCA_SUCCESS) {
				PRINT_ERROR("Error: Failed to get flow metadata\n");
				goto destroy_pcc;
			}
			for(int i = 0; i < MAX_NB_FLOWS; i++) {
				if(flow_metas[i].rtt > cfg.rtt_threshold) {
					struct timeval cur_time;
					unsigned long cur_time_usec;
					gettimeofday(&cur_time, NULL);
				    cur_time_usec = (cur_time.tv_sec * 1000000) + (cur_time.tv_usec);
					config.server_name = (char *)(&(flow_metas[i].dst_ip));
					init_polling_pkt();
					int res = send_polling_pkt(cur_time_usec / 1000);
					if(res != 0)
						printf("Failed to send polling packet\n");
				}
			}
		}
	}
	PRINT_INFO("Info: Finished waiting on DOCA PCC\n");

	exit_status = EXIT_SUCCESS;

destroy_pcc:
	tmp_result = pcc_destroy(&resources);
	if (tmp_result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to destroy DOCA PCC application resources: %s\n",
			    doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
argp_cleanup:
	tmp_result = doca_argp_destroy();
	if (tmp_result != DOCA_SUCCESS) {
		PRINT_ERROR("Error: Failed to destroy ARGP: %s\n", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
	return exit_status;
}

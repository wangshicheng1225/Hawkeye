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

#ifndef PCC_CORE_H_
#define PCC_CORE_H_

#include <doca_pcc.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <stdint.h>

#define PCC_RP_THREADS_NUM_DEFAULT_VALUE \
	(48 + 1) /* Default Number of PCC RP threads, the extra one is used for communication */
#define PCC_NP_THREADS_NUM_DEFAULT_VALUE (16)			      /* Default Number of PCC NP threads */
#define WAIT_TIME_DEFAULT_VALUE (-1)				      /* Wait time - default value (infinity) */
#define IFA2_GNS_DEFAULT_VALUE (0xF)				      /* IFA2 packet GNS value */
#define IFA2_GNS_IGNORE_DEFAULT_VALUE (0)			      /* IFA2 packet GNS value */
#define IFA2_GNS_IGNORE_DEFAULT_MASK (0)			      /* IFA2 packet GNS value */
#define PCC_COREDUMP_FILE_DEFAULT_PATH ("/tmp/doca_pcc_coredump.txt") /* Default pathname for device coredump file */
#define PCC_PRINT_BUFFER_SIZE_DEFAULT_VALUE (512 * 2048)	      /* Device print buffer size - default value */
#define PCC_MAILBOX_REQUEST_SIZE \
	(sizeof(uint32_t))		     /* Size of the mailbox request. Currently used to pass port bandwidth */
#define PCC_MAILBOX_RESPONSE_SIZE (512)	     /* Size of the mailbox response. Currently not used */
#define PCC_PHYSICAL_PORT_DEFAULT_ID (0)     /* Physical port ID - default value */
#define NUM_AVAILABLE_PORTS (4)		     /* Number of available physical ports */
#define MAX_USER_ARG_SIZE (256)		     /* Maximum size of user input argument */
#define MAX_ARG_SIZE (MAX_USER_ARG_SIZE + 1) /* Maximum size of input argument */

#define LOG_LEVEL_CRIT (20)    /* Critical log level */
#define LOG_LEVEL_ERROR (30)   /* Error log level */
#define LOG_LEVEL_WARNING (40) /* Warning log level */
#define LOG_LEVEL_INFO (50)    /* Info log level */
#define LOG_LEVEL_DEBUG (60)   /* Debug log level */

#define GET_FLOW_INFO_OP 1

struct flow_meta {
	uint32_t flowtag;
	uint32_t src_ip, dst_ip;
	uint16_t src_port, dst_port;
	uint32_t rtt;
};
#define MAX_NB_FLOWS 16

/* Default PCC RP threads */
extern const uint32_t default_pcc_rp_threads_list[PCC_RP_THREADS_NUM_DEFAULT_VALUE];
/* Default PCC NP threads */
extern const uint32_t default_pcc_np_threads_list[PCC_NP_THREADS_NUM_DEFAULT_VALUE];

/* Log level */
extern int log_level;

#define PRINT_CRIT(...) \
	do { \
		if (log_level >= LOG_LEVEL_CRIT) \
			printf(__VA_ARGS__); \
	} while (0)

#define PRINT_ERROR(...) \
	do { \
		if (log_level >= LOG_LEVEL_ERROR) \
			printf(__VA_ARGS__); \
	} while (0)

#define PRINT_WARNING(...) \
	do { \
		if (log_level >= LOG_LEVEL_WARNING) \
			printf(__VA_ARGS__); \
	} while (0)

#define PRINT_INFO(...) \
	do { \
		if (log_level >= LOG_LEVEL_INFO) \
			printf(__VA_ARGS__); \
	} while (0)

#define PRINT_DEBUG(...) \
	do { \
		if (log_level >= LOG_LEVEL_DEBUG) \
			printf(__VA_ARGS__); \
	} while (0)

/*
 * DOCA PCC Reaction Point DPA program name
 */
extern struct doca_pcc_app *pcc_rp_app;

/*
 * DOCA PCC Notification Point NIC Telemetry DPA program name
 */
extern struct doca_pcc_app *pcc_np_nic_telemetry_app;

/**
 * @brief intelemetry request packet format
 */
typedef enum {
	PCC_DEV_PROBE_PACKET_CCMAD = 0, /**< request packet follows ccmad format */
	PCC_DEV_PROBE_PACKET_IFA1 = 1,	/**< request packet follows ifa1.0 format */
	PCC_DEV_PROBE_PACKET_IFA2 = 2,	/**< request packet follows ifa2.0 format */
} pcc_dev_probe_packet_type_t;

/**
 * @brief intelemetry request packet format
 */
typedef enum {
	PCC_ROLE_RP = 0, /**< Reaction Point Role */
	PCC_ROLE_NP = 1, /**< Notification Point Role */
} pcc_role_t;

struct pcc_config {
	char device_name[DOCA_DEVINFO_IBDEV_NAME_SIZE];	 /* DOCA device name */
	pcc_role_t role;				 /* PCC role */
	struct doca_pcc_app *app;			 /* Device program */
	uint32_t threads_num;				 /* Number of PCC threads */
	uint32_t threads_list[MAX_ARG_SIZE];		 /* Threads numbers */
	int wait_time;					 /* Wait duration */
	pcc_dev_probe_packet_type_t probe_packet_format; /* Probe packet format */
	bool remote_sw_handler;				 /* CCMAD probe type remote SW handler flag */
	uint8_t gns;					 /* IFA2 GNS value */
	uint8_t gns_ignore_value;			 /* IFA2 GNS ignore value */
	uint8_t gns_ignore_mask;			 /* IFA2 GNS ignore mask */
	char coredump_file[MAX_ARG_SIZE];		 /* Coredump file pathname */
	uint32_t port_id;				 /* Physical port ID of device */
	uint32_t rtt_threshold; /*RTT threshold */
};

struct pcc_resources {
	struct doca_dev *doca_device; /* DOCA device */
	struct doca_pcc *doca_pcc;    /* DOCA PCC context */
};

/*
 * Initialize the PCC application resources
 *
 * @cfg [in]: PCC application user configurations
 * @resources [in/out]: PCC resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t pcc_init(struct pcc_config *cfg, struct pcc_resources *resources);

/*
 * Send the ports bandwidth to device via mailbox
 *
 * @cfg [in]: PCC application user configurations
 * @resources [in]: PCC resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t pcc_mailbox_send(struct pcc_config *cfg, struct pcc_resources *resources);

/*
 * Destroy the PCC application resources
 *
 * @resources [in]: PCC resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t pcc_destroy(struct pcc_resources *resources);

/*
 * Register the command line parameters for the PCC application.
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t register_pcc_params(void);

doca_error_t get_flow_metas(struct pcc_resources *resources, struct flow_meta *flow_metas);

void print_flow_metas(struct pcc_config *cfg, struct flow_meta *flow_metas);

#endif /* PCC_CORE_H_ */

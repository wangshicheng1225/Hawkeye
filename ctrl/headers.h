#ifndef _HEADERS_H
#define _HEADERS_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <inttypes.h>
#include <time.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <bf_rt/bf_rt_init.h>
#include <bf_rt/bf_rt_common.h>
#include <bf_rt/bf_rt_table_key.h>
#include <bf_rt/bf_rt_table_data.h>
#include <bf_rt/bf_rt_table.h>
#include <bf_rt/bf_rt_session.h>
#include <bf_switchd/bf_switchd.h>
#include <tofino/pdfixed/pd_conn_mgr.h>
#include <tofino/pdfixed/pd_mirror.h>
#include <bf_pm/bf_pm_intf.h>
#include <mc_mgr/mc_mgr_intf.h>
#include <tofino/bf_pal/bf_pal_port_intf.h>
#include <traffic_mgr/traffic_mgr_types.h>
#include <traffic_mgr/traffic_mgr_ppg_intf.h>
#include <traffic_mgr/traffic_mgr_port_intf.h>
#include <traffic_mgr/traffic_mgr_q_intf.h>

// for channel
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
#include <unistd.h>
//#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <sys/socket.h>
//#include <time.h>

#include "../config.h"

#define ARRLEN(arr) sizeof(arr)/sizeof(arr[0])
#if __TOFINO_MODE__ == 0
const char *P4_PROG_NAME = "hawkeye";
static const char CPUIF_NAME[] = "bf_pci0";
#else
const char *P4_PROG_NAME = "hawkeye";
// static const char CPUIF_NAME[] = "veth251";
static const char CPUIF_NAME[] = "veth251";
#endif


typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int callback_completed;
    struct timespec record_sync_time_start;
    struct timespec record_sync_time_end;

} sync_context_t;



typedef struct switch_port_s {
    char fp_port[32];
} switch_port_t;

typedef struct switch_s {
    bf_rt_target_t dev_tgt;
    bf_rt_session_hdl *session;

} switch_t;

typedef struct forward_entry_s{
	uint64_t ingress_port;
	const char* ipv4_addr;
	// char ipv4_addr[20];
	uint64_t egress_port;
} forward_entry_t;

// helper struct for forward polling table entry
typedef struct forward_polling_entry_s{
	uint32_t TP_type;
	uint64_t ingress_port;
	const char* vf_dst_ip_addr;
	// char ipv4_addr[20];
	const char* action;
	uint64_t egress_port;
	uint16_t mc_grp_id;
} forward_polling_entry_t;

typedef struct forward_2d_table_info_s {
    // Key field ids
    bf_rt_id_t kid_ipv4_dst_ip;
    bf_rt_id_t kid_ingress_port;
    // Action Ids
    bf_rt_id_t aid_ai_unicast;
    bf_rt_id_t aid_drop;
    // Data field Ids for ai_unicast
    bf_rt_id_t did_port;
    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
} forward_2d_table_info_t;

typedef struct forward_table_info_s {
    // Key field ids
    bf_rt_id_t kid_dst_mac;
    // Action Ids
    bf_rt_id_t aid_unicast;
    bf_rt_id_t aid_broadcast;
    bf_rt_id_t aid_drop;
    // Data field Ids for ai_unicast
    bf_rt_id_t did_port;
    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    // Multicast info
    bf_mc_session_hdl_t mc_session;
    bf_mc_mgrp_hdl_t mc_mgrp;
    bf_mc_node_hdl_t mc_node;
    bf_mc_port_map_t mc_port_map;
    bf_mc_lag_map_t mc_lag_map;
} forward_table_info_t;

typedef struct forward_2d_table_entry_s {
    // Key value
    bf_dev_port_t ingress_port;
    uint32_t ipv4_addr;
    
    // Match length (for LPM)
    //uint16_t match_length;
    // Action
    char action[20];
    // Data value
    bf_dev_port_t egress_port;
} forward_2d_table_entry_t;

typedef struct forward_table_entry_s {
    // Key value
    uint64_t dst_mac;
    // Match length (for LPM)
    uint16_t match_length;
    // Action
    char action[16];
    // Data value
    bf_dev_port_t egress_port;
} forward_table_entry_t;


typedef struct forward_polling_table_entry_s {
    // Key value
    uint16_t polling_TP_type;
    bf_dev_port_t ingress_port;
	uint32_t polling_vf_dst_ip;
    
    // Match length (for LPM)
    //uint16_t match_length;
    // Action
    char action[64];
    // Data value
    bf_dev_port_t egress_port;
	uint16_t mc_grp_id;

} forward_polling_table_entry_t;

typedef struct forward_polling_table_info_s {
    // Key field ids
	bf_rt_id_t kid_TP_type;
    bf_rt_id_t kid_ingress_port;
	bf_rt_id_t kid_vf_dst_ip;
    // Action Ids
    bf_rt_id_t aid_ai_unicast;
    bf_rt_id_t aid_ai_broadcast;
    bf_rt_id_t aid_ai_drop;
    // Data field Ids for ai_unicast
    bf_rt_id_t did_unicast_port;
    bf_rt_id_t did_broadcast_port;
	bf_rt_id_t did_mc_grp_id;
    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
    // Multicast info
//    bf_mc_session_hdl_t mc_session;
//    bf_mc_mgrp_hdl_t mc_mgrp;
//    bf_mc_node_hdl_t mc_node;
//    bf_mc_port_map_t mc_port_map;
//    bf_mc_lag_map_t mc_lag_map;
} forward_polling_table_info_t;


typedef struct register_info_s {
    // Key field ids
    bf_rt_id_t kid_register_index;
    // Data field Ids for register table
    bf_rt_id_t did_value;
    // Key and Data objects
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
} register_info_t;

typedef struct register_entry_s {
    // Key value
    uint32_t register_index;
    // Data value
    uint32_t value;
    uint32_t value_array_size;
    uint64_t *value_array;
} register_entry_t;

typedef struct {
    bf_rt_table_key_hdl *key;
    bf_rt_table_data_hdl *data;
} key_data_pair_t;


typedef struct re_lock_flag_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} re_lock_flag_t;

typedef struct re_port_meter_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} re_port_meter_t;

typedef struct re_port_paused_num_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} re_port_paused_num_t;

typedef struct re_port_enq_depth_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} re_port_enq_depth_t;

typedef struct telemetry_enq_qdepth_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} telemetry_enq_qdepth_t;

typedef struct telemetry_pkt_num_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} telemetry_pkt_num_t;

typedef struct telemetry_paused_num_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} telemetry_paused_num_t;

typedef struct telemetry_src_ip_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} telemetry_src_ip_t;

typedef struct telemetry_dst_ip_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} telemetry_dst_ip_t;

typedef struct telemetry_src_port_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} telemetry_src_port_t;

typedef struct telemetry_reg_s {
    const bf_rt_table_hdl *reg;
    register_info_t reg_info;
    register_entry_t entry;
} telemetry_reg_t;
// typedef struct telemtry_pkt_num_table {
//     const bf_rt_table_hdl *reg;
//     register_info_t reg_info;
// } telemetry_pkt_num_table_t;

// typedef struct telemtry_egress_port_s {
//     const bf_rt_table_hdl *reg;
//     register_info_t reg_info;
//     register_entry_t entry;
// } telemetry_egress_port_t;


// typedef struct telemtry_dst_port_s {
//     const bf_rt_table_hdl *reg;
//     register_info_t reg_info;
//     register_entry_t entry;
// } telemtry_dst_port_t;

static void register_setup(const bf_rt_info_hdl *bfrt_info,
                           const char *reg_name,
                           const char *value_field_name,
                           const bf_rt_table_hdl **reg,
                           register_info_t *reg_info);
static void register_write(const bf_rt_target_t *dev_tgt,
                           const bf_rt_session_hdl *session,
                           const bf_rt_table_hdl *reg,
                           register_info_t *reg_info,
                           register_entry_t *reg_entry);
static void register_write_no_wait(const bf_rt_target_t *dev_tgt,
                                   const bf_rt_session_hdl *session,
                                   const bf_rt_table_hdl *reg,
                                   register_info_t *reg_info,
                                   register_entry_t *reg_entry);
static void register_read(const bf_rt_target_t *dev_tgt,
                          const bf_rt_session_hdl *session,
                          const bf_rt_table_hdl *reg,
                          register_info_t *reg_info,
                          register_entry_t *reg_entry);


static void telemetry_reg_setup(const bf_rt_info_hdl *bfrt_info,
                               telemetry_reg_t *telemetry_reg,
                               char* reg_name);

static void re_lock_flag_setup(const bf_rt_info_hdl *bfrt_info,
                               re_lock_flag_t *re_lock_flag);

static void re_port_meter_setup(const bf_rt_info_hdl *bfrt_info,
                               re_port_meter_t *re_port_meter_reg, uint32_t win_idx);

static void re_port_paused_num_setup(const bf_rt_info_hdl *bfrt_info,
                               re_port_paused_num_t *re_port_paused_num_reg, uint32_t win_idx);

static void re_port_enq_depth_setup(const bf_rt_info_hdl *bfrt_info,
                               re_port_enq_depth_t *re_port_enq_depth_reg, uint32_t win_idx);


static void telemetry_unpaused_enq_depth_setup(const bf_rt_info_hdl *bfrt_info,
                               telemetry_enq_qdepth_t *telemetry_enq_qdepth_reg, uint32_t win_idx);

static void telemetry_pkt_num_setup(const bf_rt_info_hdl *bfrt_info,
                               telemetry_pkt_num_t *telemetry_pkt_num_reg, uint32_t win_idx);

static void telemetry_paused_num_setup(const bf_rt_info_hdl *bfrt_info,
                               telemetry_paused_num_t *telemetry_paused_num_reg, uint32_t win_idx); 


static void telemetry_dst_ip_setup(const bf_rt_info_hdl *bfrt_info,
                               telemetry_dst_ip_t *telemetry_dst_ip_reg, uint32_t win_idx);

static void telemetry_src_ip_setup(const bf_rt_info_hdl *bfrt_info,
                               telemetry_src_ip_t *telemetry_src_ip_reg, uint32_t win_idx);

static void telemetry_src_port_setup(const bf_rt_info_hdl *bfrt_info,
                               telemetry_src_port_t *telemetry_src_port_reg, uint32_t win_idx); 




void telemetry_reg_read(const bf_rt_target_t *dev_tgt,
							   const bf_rt_session_hdl *session,
                               telemetry_reg_t *telemetry_reg,
                               const uint32_t reg_idx, FILE* file);

void re_lock_flag_read(const bf_rt_target_t *dev_tgt,
							   const bf_rt_session_hdl *session,
                               re_lock_flag_t *re_lock_flag);

void re_lock_flag_write_to_completion(const bf_rt_target_t *dev_tgt,
							   const bf_rt_session_hdl *session,
                               re_lock_flag_t *re_lock_flag, uint8_t value);

void re_lock_flag_write_no_wait(const bf_rt_target_t *dev_tgt,
							   const bf_rt_session_hdl *session,
                               re_lock_flag_t *re_lock_flag);

void re_port_meter_read(const bf_rt_target_t *dev_tgt,
                            const bf_rt_session_hdl *session,
                            re_port_meter_t *re_port_meter_ptr,
                            const uint32_t reg_idx,
                            FILE* file);

void re_port_paused_num_read(const bf_rt_target_t *dev_tgt,
                                const bf_rt_session_hdl *session,
                                re_port_paused_num_t *re_port_paused_num_ptr,
                                const uint32_t reg_idx,
                                FILE* file);

void re_port_enq_qdepth_read(const bf_rt_target_t *dev_tgt,
                                const bf_rt_session_hdl *session,
                                re_port_enq_depth_t *re_port_enq_depth_ptr,
                                const uint32_t reg_idx,
                                FILE* file);

void telemetry_unpaused_enq_depth_read(const bf_rt_target_t *dev_tgt,
                                const bf_rt_session_hdl *session,
                                telemetry_enq_qdepth_t *telemetry_enq_qdepth_ptr,
                                const uint32_t reg_idx,
                                FILE* file);

void telemetry_pkt_num_read(const bf_rt_target_t *dev_tgt,
                                const bf_rt_session_hdl *session,
                                telemetry_pkt_num_t *telemetry_pkt_num_ptr,
                                const uint32_t reg_idx,
                                FILE* file);

void telemetry_paused_num_read(const bf_rt_target_t *dev_tgt,
                                const bf_rt_session_hdl *session,
                                telemetry_paused_num_t *telemetry_paused_num_ptr,
                                const uint32_t reg_idx,
                                FILE* file);

void telemetry_dst_ip_read(const bf_rt_target_t *dev_tgt,
                            const bf_rt_session_hdl *session,
                            telemetry_dst_ip_t *telemetry_dst_ip_ptr,
                            const uint32_t reg_idx,
                            FILE* file);

void telemetry_src_ip_read(const bf_rt_target_t *dev_tgt,
                            const bf_rt_session_hdl *session,
                            telemetry_src_ip_t *telemetry_src_ip_ptr,
                            const uint32_t reg_idx,
                            FILE* file);

void telemetry_src_port_read(const bf_rt_target_t *dev_tgt,
                            const bf_rt_session_hdl *session,
                            telemetry_src_port_t *telemetry_src_port_ptr,
                            const uint32_t reg_idx,
                            FILE* file);



// ---------Channel ---------------
// track event id
uint8_t used_flag[EVENT_ID_MAX];

typedef struct {
//    uint8_t TP_type: 2;
//    uint8_t padding_0: 6;
	uint8_t TP_type_w_padding_0; // 1bytes for polling flag and padding
    uint8_t bytes_ingress[2];  // 2bytes for ingress_port and padding_1
    uint8_t bytes_egress[2];   // 2bytes for egress_port and padding_2
    uint8_t event_id;
    uint32_t vf_src_ip;
    uint32_t vf_dst_ip;
    uint8_t vf_protocol;
    uint16_t vf_src_port;
    uint16_t vf_dst_port;
} __attribute__((packed)) polling_h;

typedef struct update_polling_channel_s {
	int sockfd;
	char recvbuf[PKTBUF_SIZE];
//    uint8_t  probe_table;
//    uint16_t pipr_idx;
    uint16_t egress_port;
	polling_h *polling;
} update_polling_channel_t;



int create_update_polling_channel(update_polling_channel_t *channel);
int recv_update_polling(update_polling_channel_t *channel);
int process_event_id(uint8_t event_id) {
	printf(" Debug: Processing event id %u\n", event_id);
    if (used_flag[event_id] == 1) {
        printf("Duplicate event ID %d detected, dropping packet.\n", event_id);
        return 1;
    } else {
        used_flag[event_id] = 1;  // 
        printf("New event ID %d received and processed.\n", event_id);
        if (event_id == 255) {
            memset(used_flag, 0, sizeof(used_flag));
            printf("Resetting event ID tracking array.\n");
        }
        return 0;
    }
}





#endif

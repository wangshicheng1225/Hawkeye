#ifndef _CONFIG_H
#define _CONFIG_H

#define IP_TYPE 4
// #define __TOFINO_MODE__ 1 // 0: ASIC 1: Model
#define __TOFINO_MODE__ 0 // 0: ASIC 1: Model


#define EPOCH_NUM 4
#define PORT_METER_SIZE 4096 // 2**12
#define TUPLE_IDX_SIZE 12
#define PADDING_TUPLE_IDX_SIZE 4
#define PORT_RATE_WIDTH 12
#define PORT_NUM 64 // 2**6 
#define PORT_METER_TH 2


#define FLAG_WIDTH 1
#define TSTAMP_US_WIDTH 16 

#define ETHER_TYPE_SIGNAL_BROADCAST 0x6666
//#define ETHER_TYPE_SIGNAL 0x6668
//#define ETHER_TYPE_TRACING 0x6688
#define ETHER_TYPE_POLLING 0x6888
#define ETHER_TYPE_PAUSE 0x8808

// Only for data plane
#if __TOFINO_MODE__ == 0 
#define CPU_PORT 192
// #define CPU_PORT 64
#define RESULT_SERVER_PORT 144
#else
#define CPU_PORT 64
#define RESULT_SERVER_PORT 3
#endif

#define POLLING_FLW_TRC 1
#define POLLING_PFC_TRC 2
#define POLLING_ALL_TRC 3

#define RECIRC_PORT 196
//#define BROADCAST_MC_GID 255
#define SIGNAL_MC_GID 131
#define POLLING_MC_GID_A 126
#define POLLING_MC_GID_B 127

#define UPDATE_NOTIFY_MIRROR_SID 66
#define PKTBUF_SIZE 2048
//#define H1_PORT 4
//#define H2_PORT 5
//#define RESULT_SERVER_MC_GID 192
#define EGRESS_MIRROR_SID 2
#define ALL_PIPES 0xffff

#define EVENT_ID_MAX 256  // 

#endif
/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2018-2019 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 *
 ******************************************************************************/

#ifndef _HEADERS_
#define _HEADERS_
#include "../config.h"



typedef bit<9>   port_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;
typedef bit<8> ipr_idx_t;
typedef bit<16> ether_type_t;

typedef bit<8> pkt_label_t;
typedef bit<8> mirror_flag_t;

const pkt_label_t PKT_LABEL_NORMAL        = 0;
const pkt_label_t PKT_LABEL_INACTIVE_RESP = 1;
const pkt_label_t PKT_LABEL_ACTIVE_RESP   = 2;
const pkt_label_t PKT_LABEL_TEMPLATE      = 3;
const pkt_label_t PKT_LABEL_SEED          = 4;
const pkt_label_t PKT_LABEL_ARP_REQUEST   = 5;
const pkt_label_t PKT_LABEL_FLUSH_REQUEST = 6;
const pkt_label_t PKT_LABEL_UPDATE_NOTIFY = 7;

typedef bit<8> pkt_type_t;

const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;

typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;
// const ether_type_t ETHERTYPE_MIR_RECIRC = 16w0x6789;
//const ether_type_t ETHERTYPE_SIGNAL_BROADCAST = ETHER_TYPE_SIGNAL_BROADCAST;
//const ether_type_t ETHERTYPE_SIGNAL = ETHER_TYPE_SIGNAL;
//const ether_type_t ETHERTYPE_TRACING = ETHER_TYPE_TRACING;
const ether_type_t ETHERTYPE_POLLING = ETHER_TYPE_POLLING;
const ether_type_t ETHERTYPE_PAUSE = ETHER_TYPE_PAUSE;


const bit<8> MIR_RECIRC_FLAG = 0x89;
const bit<8> MIR_CPU_FLAG = 0x78;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

header ethernet_h {
    mac_addr_t dst_mac;
    mac_addr_t src_mac;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    bit<16> ether_type;
}

header mpls_h {
    bit<20> label;
    bit<3> exp;
    bit<1> bos;
    bit<8> ttl;
}



header pause_h {
	bit<16> opcode;
	bit<16> pause_time;
}

header pfc_h {
	bit<16> opcode;	
	bit<8> class;
	bit<16> pause_time;
	bit<48> padding; // for other class
}

header signal_h {
	bit<9> egrs_port_idx;// downstream egrs port 
	bit<7> epoch_idx;
	bit<16> congst_contrb;//port_meter_rate[egress_port][egrs_port_idx] 
}

header signal_broadcast_h {
	
}

header polling_h {
    //ipv4_addr_t src_ip;
    //ipv4_addr_t dst_ip;
    bit<2> TP_type;
    bit<6> padding_0;
    bit<9> ingress_port;
    bit<7> padding_1;
    bit<9> egress_port;
    bit<7> padding_2;
    bit<8> event_id;// event+switchID
    bit<32> vf_src_ip;
    bit<32> vf_dst_ip;
    bit<8> vf_protocol;
    bit<16> vf_src_port;
    bit<16> vf_dst_port;

}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> checksum;
    ipv4_addr_t src_ip;
    ipv4_addr_t dst_ip;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_ip;
    ipv6_addr_t dst_ip;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<6>  res;
    // Here we employ 6 byte flags
    // bit<6> flags;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

// header icmp_h {
//     bit<8> type_;
//     bit<8> code;
//     bit<16> checksum;
// }
header icmp_h {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
    bit<16> id;
    bit<16> seq_no;
    // bit<64> tstamp;
}
// Address Resolution Protocol -- RFC 6747
header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    // ...
}
header arp_ipv4_h {
    mac_addr_t  src_hw_addr;
    ipv4_addr_t src_proto_addr;
    mac_addr_t  dst_hw_addr;
    ipv4_addr_t dst_proto_addr;
}
// Segment Routing Extension (SRH) -- IETFv7
header ipv6_srh_h {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> seg_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}

// VXLAN -- RFC 7348
header vxlan_h {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

// Generic Routing Encapsulation (GRE) -- RFC 1701
header gre_h {
    bit<1> C;
    bit<1> R;
    bit<1> K;
    bit<1> S;
    bit<1> s;
    bit<3> recurse;
    bit<5> flags;
    bit<3> version;
    bit<16> proto;
}

header telemetry_data_h {
    // bit<48> ingress_mac_tstamp;
    // bit<48> ingress_parser_tstamp;
    // bit<32> tm_enq_tstamp;
    // bit<32> tm_deq_tdelta;
    bit<48> egress_timestamp;
    bit<16> flow_idx;
    // bit<6> _pad;
    bit<8> win_id;
    bit<32> telemetry_data;
}

header timestamp_h {
    bit<48> ingress_mac_tstamp;
    bit<48> ingress_parser_tstamp;
    bit<32> tm_enq_tstamp;
    bit<32> tm_deq_tdelta;
    bit<48> egress_parser_tstamp;
}

struct header_t {
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    pause_h pause;
	signal_h singal;
	//singal_broadcast_h signal_broadcast;
	ipv4_h ipv4;
    ipv6_h ipv6;
    tcp_h tcp;
    udp_h udp;
    // Add more headers here.
}

struct metadata_t {
//    bit<16> temp;
}

header meter_result_h {
	bit<16> idx;
	bit<8> value;
}


header result_pack_h {
    bit<32> target_0;
    bit<32> target_1;
    bit<32> target_2;
    bit<32> target_3;
    bit<32> target_4;
    bit<32> target_5;
    bit<32> target_6;
    bit<32> target_7;
    bit<32>  result_0;
    bit<32>  result_1;
    bit<32>  result_2;
    bit<32>  result_3;
    bit<32>  result_4;
    bit<32>  result_5;
    bit<32>  result_6;
    bit<32>  result_7;
}

header result_meta_h {
    bit<8>  resp_pkt_count;
}

struct result_h {
    result_meta_h result_meta;
    result_pack_h result_pack_0;
    result_pack_h result_pack_1;
}

header update_notification_h {
    bit<8>    probe_table;
    ipr_idx_t pipr_idx; // Probe IP Range Index
    bit<7>    _pad;     // For aligning
    port_t    egress_port;
}

// #define INTERNAL_MD  \
//     pkt_label_t pkt_label

struct internal_metadata_t {
    pkt_label_t pkt_label;
}


header bridged_h {
    // Indicate the imap packet type
    // INTERNAL_MD;
    // pkt_label_t pkt_label;
	//bit<8> pkt_type;
	PortId_t ingress_port;
	bit<7> padding;
}
header simple_mirror_h {
	pkt_type_t pkt_type;
}


header mirror_data_h {

	mirror_flag_t mirror_flag;	
//	bit<16> src_port;
//	bit<16> dst_port;
	bit<9> egress_port;
//    bit<9> ingress_port;
//	bit<2> epoch_idx;
	//bit<5> padding_0;
//	bit<16> congst_contrb; 
//    bit<6> padding_1;
//	MirrorId_t egr_mir_ses; // bit<10> Egress mirror session ID 
	bit<7> padding;
}

//header mirror_h {
//    // INTERNAL_MD;
//		
//    mac_addr_t dst_mac;
//    mac_addr_t src_mac;
//	bit<16> ether_type;
//	
//	mirror_data_h mirror_data; 
//	// pkt_label_t pkt_label;
//    //bit<8> pkt_type;
//	//bit<8>    probe_table;
//    //ipr_idx_t pipr_idx; // Probe IP Range Index
//    //bit<7>    _pad;     // For aligning
//    //port_t    egress_port;
//    // bit<16>   probe_port_stride;
//}

struct ingress_metadata_t {
    bridged_h bridged;
    mirror_data_h    mirror_data;
}

struct egress_metadata_t {
    bridged_h   bridged;
    mirror_data_h    mirror_data;
	pkt_type_t pkt_type;
    MirrorId_t ing_mir_ses;   // Ingress mirror session ID
    MirrorId_t egr_mir_ses; // Egress mirror session ID
    
	bit<TUPLE_IDX_SIZE>  port_tuple_idx; // padded to 16bit
	bit<PADDING_TUPLE_IDX_SIZE> padding_1; // 2 marco MUST be modified together
	bit<16>  port_meter_rate;
	// result_h              result;
    bit<16>     icmp_csum;
    bit<16>     tcp_csum;


    bit<16> flow_idx;
    bit<2> epoch_idx;
    bit<8> comp_egress_port;
	bit<1> padding;
    bit<FLAG_WIDTH> change_epoch;
	bit<FLAG_WIDTH> lock_flag;
	bit<FLAG_WIDTH> should_reset_flow_epoch_data;
	bit<FLAG_WIDTH> should_reset_port_epoch_data;
	bit<FLAG_WIDTH> is_paused;
    
	
	bit<32> reltv_tstamp;	 
	bit<TSTAMP_US_WIDTH> time_delta;
	bit<8> ingress_port; // from intrinsic metadata
    bit<16> pkt_num; // from register
    bit<16> port_pkt_num; // from port level telem 
    bit<16> enq_qdepth; // metadata
    bit<16> port_enq_qdepth;
    bit<16> flow_paused_num; // from reg
    bit<16> port_paused_num; 

}

struct egress_deparser_metadata_t {
	
}
header telemetry_data_header_h {

    bit<32> data_byte_0;
    bit<32> data_byte_4;
    bit<32> data_byte_8;
    bit<32> data_byte_12;
    bit<32> data_byte_16;
    bit<32> data_byte_20;
}

struct custom_header_t {
    ethernet_h ethernet;
    pause_h    pause;
    polling_h  polling;
//	signal_h   signal;
//	arp_h      arp;
//	arp_ipv4_h arp_ipv4;
    ipv4_h     ipv4;
//    ipv6_h     ipv6;
    icmp_h     icmp;
    tcp_h      tcp;
    udp_h      udp;
    // timestamp_h timestamp;
    //telemetry_data_header_h telemetry_data_header;
}

 


#endif /* _HEADERS_ */
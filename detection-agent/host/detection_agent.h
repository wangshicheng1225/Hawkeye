#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>
#include <byteswap.h>
#include <getopt.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <ifaddrs.h>
#include <dirent.h>

#define BUF_SIZ         1024
#define RDMAMSGW "RDMA write operation"
#define MSG_S "SEND operation from server"

struct polling_header {
    uint8_t padding_0:6;
    uint8_t TP_type:2;
    uint8_t ingress_port_low;
    uint8_t padding_1:7;
    uint8_t ingress_port_high:1;
    uint8_t egress_port_low;
    uint8_t padding_2:7;
    uint8_t egress_port_high:1;
    uint8_t event_id;
    uint32_t vf_src_ip;
    uint32_t vf_dst_ip;
    uint8_t vf_protocol;
    uint16_t vf_src_port;
    uint16_t vf_dst_port;
}__attribute__((packed));


/* poll CQ timeout in millisec (2 seconds) */
#define SQ_NUM_DESC 512
#define RQ_NUM_DESC 512
#define MAX_POLL_CQ_TIMEOUT 2000
#define MSG_SIZE 8192000

struct polling_config_t
{
    int sockfd;
    struct sockaddr_ll sa;
    struct ether_header eh;
    struct polling_header ph;
    char* send_buf;
};

/* structure of test parameters */
struct config_t
{
    const char *dev_name; /* IB device name */
    char *server_name;    /* server host name */
    uint32_t tcp_port;    /* server TCP port */
    int ib_port;          /* local IB port to work with */
    int gid_idx;          /* gid index to use */
    int udp_sport;        /* udp src port */
    int rtt_threshold;    /* rtt threshold */
};

/* structure to exchange data which is needed to connect the QPs */
struct cm_con_data_t
{
    uint64_t addr;        /* Buffer address */
    uint32_t rkey;        /* Remote key */
    uint32_t qp_num;      /* QP number */
    uint16_t lid;         /* LID of the IB port */
    uint8_t gid[16];      /* gid */
} __attribute__((packed));

/* structure of system resources */
struct resources
{
    struct ibv_device_attr device_attr; /* Device attributes */
    struct ibv_port_attr port_attr;     /* IB port attributes */
    struct cm_con_data_t remote_props;  /* values to connect to remote side */
    struct ibv_context *ib_ctx;         /* device handle */
    struct ibv_pd *pd;                  /* PD handle */
    struct ibv_cq *cq;                  /* CQ handle */
    struct ibv_qp *qp;                  /* QP handle */
    struct ibv_mr *mr;                  /* MR handle for buf */
    char *buf;                          /* memory buffer pointer, used for RDMA and send ops */
    int sock;                           /* TCP socket file descriptor */
};

int init_polling_pkt();
int send_polling_pkt(uint8_t event_id);
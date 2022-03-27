#ifndef PROTO_H
#define PROTO_H

#ifdef __cplusplus
extern "C" {
#endif

#define CODE_ETH_IP4 0x0800
#define CODE_ETH_IP6 0x86DD
#define CODE_ETH_ARP 0x0806
#define CODE_ETH_ARP_REPLY 0x0808

#define CODE_IP_TCP 6
#define CODE_IP_UDP 17
#define CODE_IP_ICMP 1

#define CODE_APP_HTTP 80
#define CODE_APP_HTTPS 443
#define CODE_APP_SMTP 25
#define CODE_APP_DNS 53 

#define CODE_ICMP_PING_REQ 0
#define CODE_ICMP_PING_RLY 8
#define CODE_ICMP_UA 3
#define CODE_ICMP_TIMEOUT 11
#define CODE_ICMP_REDIR 5
#define CODE_ICMP_UA_NET 0
#define CODE_ICMP_UA_HOST 1 

#define CODE_ARP_REQ 1
#define CODE_ARP_RLY 2
#define CODE_ARP_RARP_REQ 3
#define CODE_ARP_RARP_RLY 4

typedef enum eth_type {ETH_IP4, ETH_IP6, ETH_ARP, ETH_ARP_REPLY, OTHER} eth_type;
typedef enum ip_type {IP_IP4, IP_IP6, IP_ICMP, IP_NONE} ip_type;
typedef enum trans_type {TRANS_TCP, TRANS_UDP, TRANS_NONE} trans_type;
typedef enum app_type {APP_HTTP, APP_HTTPS, APP_SMTP, APP_DNS, APP_NONE} app_type;
typedef enum icmp_type {ICMP_PING_REQ, ICMP_PING_RLY, ICMP_NET_UA, ICMP_HOST_UA, ICMP_REDIR, ICMP_TIMEOUT} icmp_type;
#include <pcap.h>

struct eth_header {
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short type;
};

struct arp_header {
    u_short hardware_type;
    u_short proto_type;
    u_char addr_len;
    u_char proto_len;
    u_short op_code;
    u_char src_mac[6];
    u_char src_ip[4];
    u_char dst_mac[6];
    u_char dst_ip[4];
};

struct ip4_header {
    u_char version_header;
    u_char tos;
    u_short total_len;
    u_short ident;
    u_short flags;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    u_char sourceIP[4];
    u_char destIP[4];
};

struct icmp_header {
    u_char type;
    u_char code;
};


struct ip6_header {
    int version:4;
    int traffic_class:8;
    int flow_label:20;
    int total_len:16;
    int next_header:8;
    int hop_limit:8;
    u_char sourceIP[16];
    u_char destIP[16];

};

struct tcp_header {
    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack;
    u_char head_len;
    u_char flags;
    u_short wind_size;
    u_short check_sum;
    u_short urg_ptr;
};

struct udp_header {
    u_short sport;
    u_short dport;
    u_short tot_len;
    u_short check_sum;
};

struct dns_header {
    u_short trans_ID;
    u_short flags;
    u_short question;
    u_short answer_RRs;
    u_short Authority_RRs;
    u_short Additional_RRs;
};

#define eth_len sizeof(struct eth_header)
#define ip4_len sizeof(struct ip4_header)
#define ip6_len sizeof(struct ip6_header)
#define udp_len sizeof(struct udp_header)

struct parse_struct {
    u_char dst_mac[6];
    u_char src_mac[6];
    eth_type ETH_type;

    u_short hardware_type;
    u_short proto_type;
    u_short op_code;
    u_char arp_src_mac[6];
    u_char arp_src_ip[4];
    u_char arp_dst_mac[6];
    u_char arp_dst_ip[4];

    u_char dst_ip[16];
    u_char src_ip[16];
    u_short ip_len;
    u_char ttl;

    int icmp_type_int;
    int icmp_code_int;
    u_char icmp_type;
    ip_type IP_type;

    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack;
    u_char SYN;
    u_char FIN;
    u_short wind_size;
    u_short check_sum;
    trans_type TRANS_type;


    app_type APP_type;

    u_short trans_ID;
    u_short flags;
    u_short question;
    u_short answer_RRs;
    u_short Authority_RRs;
    u_short Additional_RRs;
};


void parseProtoHeader(const unsigned char *packet_content, struct parse_struct * parse_res);

#ifdef __cplusplus
}
#endif

#endif

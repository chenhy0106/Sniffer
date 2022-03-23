#ifndef SNIFFER_BACK_H
#define SNIFFER_BACK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <tchar.h>

typedef enum ps {SEL_ALL,  \
                SEL_HTTP, SEL_HTTPS, SEL_DNS, SEL_SMTP, \
                SEL_TCP, SEL_UDP, \
                SEL_ICMP, SEL_IPV4, SEL_IPV6, \
                SEL_ARP \
                } ProtoSel;

struct dev {
    char * name;
    char * description;
    pcap_if_t * dev;
};

BOOL LoadNpcapDlls();
BOOL getDevList(struct dev ** dev_list, int * dev_count);
void freeDevList(struct dev * dev_list, int dev_count);

struct packet {
    struct pcap_pkthdr *header;
	const u_char *data;
};

typedef int filter_t;

int getPackets(struct packet * buff, unsigned offset, struct dev * dev, int max_packet_count, int timeout, 
				ProtoSel filter, int promiscuous);


#ifdef __cplusplus
}
#endif

#endif

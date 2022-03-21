#ifndef SNIFFER_BACK_H
#define SNIFFER_BACK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <tchar.h>

struct dev {
    char * name;
    char * description;
};

BOOL LoadNpcapDlls();
BOOL getDevList(struct dev ** dev_list, int * dev_count);
void freeDevList(struct dev * dev_list, int dev_count);

struct packet {
    struct pcap_pkthdr *header;
	const u_char *data;
};

typedef int filter_t;

int getPackets(struct packet * buff, unsigned offset, char * dev_name, int max_packet_count, int timeout, 
				filter_t filter, int promiscuous);


#ifdef __cplusplus
}
#endif

#endif

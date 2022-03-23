#include "sniffer_back.h"
#include "string.h"
#include <stdio.h>

pcap_t * adhandle;
pcap_if_t * alldevs;
struct dev * cur_dev;

BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}


BOOL getDevList(struct dev ** dev_list, int * dev_count) {
	// clear current dev list	
	if (*dev_list) {
		free(*dev_list);
	}

	// find all dev
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        return 0;
	}

	for (pcap_if_t * dev = alldevs; dev; dev = dev->next) {
		*dev_count = *dev_count + 1;
	}

	*dev_list = (struct dev *)malloc(sizeof(struct dev) * *dev_count);

	int i = 0;
	for(pcap_if_t * dev = alldevs; dev; dev = dev->next, i++)
	{
		(*dev_list)[i].name = (char *)malloc(strlen(dev->name));
		strcpy((*dev_list)[i].name, dev->name);
		(*dev_list)[i].description = (char *)malloc(strlen(dev->description));
		strcpy((*dev_list)[i].description, dev->description);
		(*dev_list)[i].dev = dev;
	}

    
    return 1;
}

void freeDevList(struct dev * dev_list, int dev_count) {
	if (adhandle) { // close last adhandle
		pcap_close(adhandle);
	}
	
	for (int i = 0; i < dev_count; i++) {
		free(dev_list[i].description);
		free(dev_list[i].name);
	}

	free(dev_list);
	pcap_freealldevs(alldevs);
}


int getPackets(struct packet * buff, 
				unsigned offset, 
				struct dev * dev, 
				int max_packet_count, 
				int timeout, 
				ProtoSel filter,
				int promiscuous) {
	char errbuf[PCAP_ERRBUF_SIZE];

	if (dev != cur_dev) {
		if (adhandle) { // close last adhandle
			pcap_close(adhandle);
		}
		
        if ((adhandle = pcap_open_live(dev->name, 65536, promiscuous, 1000, errbuf)) == NULL) {
			return -1;
		}
	}

	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		return -1;
	}

	cur_dev = dev;

    u_int netmask = 0xffffffff;
    struct bpf_program fcode;
	//compile the filter
	char filter_str[11] = {0}; 
	if (filter != SEL_ALL) {
		switch (filter)
		{
			case SEL_TCP: {
				strcpy(filter_str, "tcp");
				break;
			}
			case SEL_UDP: {
				strcpy(filter_str, "udp");
				break;			
			}
			case SEL_ICMP: {
				strcpy(filter_str, "icmp");
				break;			
			}
			case SEL_ARP: {
				strcpy(filter_str, "arp");
				break;			
			}
			case SEL_IPV4: {
				strcpy(filter_str, "ip");
				break;			
			}
			case SEL_IPV6: {
				strcpy(filter_str, "ip6");
				break;	
			}	
			case SEL_DNS: {
				strcpy(filter_str, "port 53");
				break;	
			}	
			case SEL_HTTP: {
				strcpy(filter_str, "port 80");
				break;	
			}	
			case SEL_HTTPS: {
				strcpy(filter_str, "port 443");
				break;	
			}	
			case SEL_SMTP: {
				strcpy(filter_str, "port 25");
				break;	
			}	
		}
        if (pcap_compile(adhandle, &fcode, filter_str, 1, netmask) < 0)
		{
			printf("pcap compile\n");
			return -1;
		}
		
		//set the filter
		if (pcap_setfilter(adhandle, &fcode) < 0)
		{
			printf("set compile\n");
			return -1;
		}
	}
	

	int packet_count = 0;
    int res;
    while(timeout && ((res = pcap_next_ex(adhandle, &(buff[packet_count+offset].header), &(buff[packet_count+offset].data))) >= 0)) {
        if (packet_count >= max_packet_count) {
			break;
		}
		
		if(res == 0) {
			timeout--;
			continue;
		}

		packet_count++;
	}

	if(res == -1){
		return -1;
	}

	return packet_count;
}

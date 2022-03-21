#include "sniffer_back.h"
#include "string.h"

pcap_t * adhandle;
char *   cur_dev_name;

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
	pcap_if_t * alldevs;
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
	}

    pcap_freealldevs(alldevs);
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
}


int getPackets(struct packet * buff, 
				unsigned offset, 
				char * dev_name, 
				int max_packet_count, 
				int timeout, 
				filter_t filter,
				int promiscuous) {
	char errbuf[PCAP_ERRBUF_SIZE];

	if (dev_name != cur_dev_name) {
		if (adhandle) { // close last adhandle
			pcap_close(adhandle);
		}
		
		if ((adhandle = pcap_open_live(dev_name, max_packet_count, promiscuous, 1000, errbuf)) == NULL) {
			return -1;
		}
	}

	cur_dev_name = dev_name;

	int packet_count = 0;
    int res;
	while(timeout && ((res = pcap_next_ex(adhandle, &buff[packet_count+offset].header, &buff[packet_count+offset].data )) >= 0)) {
        if (packet_count > max_packet_count) {
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
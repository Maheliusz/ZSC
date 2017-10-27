#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

int main(int argc, char* argv[]){
    char port[] = "ethernet";
	pcap_t *capturer = pcap_create(port, NULL);
    pcap_activate(capturer);
	struct pcap_pkthdr data;
	pcap_next(capturer, &data);
	printf("%d", data.len);
	pcap_close(capturer);
	return 0;
}
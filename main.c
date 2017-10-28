// sudo modprobe usbmon

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <errno.h>

void print_packets(pcap_t *capturer, int num) {
    struct pcap_pkthdr *data = calloc(1, sizeof(struct pcap_pkthdr));
    for (int i = 0; i < num; i++) {
        printf("%.*s", data->caplen,
               pcap_next(capturer, data)
        );
    }
}

char *devprompt() {
	pcap_if_t *alldevsp, *device;
	int devcount = 1;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	//find all available devices
	if (pcap_findalldevs(&alldevsp, errbuf) < 0) {
		printf("Error finding devices : %s\n" , errbuf);
		exit(-1);
	}
	
	//print available devices
	for (device = alldevsp; device != NULL; device = device -> next) {
		printf("%d. %s - %s\n", devcount, device -> name, device -> description);
		devcount++;
	}
	
	int n;
	printf("Enter the number of the device you want to sniff: ");
    scanf("%d" , &n);
    if (n < 1) return NULL;
    for (device = alldevsp; device != NULL && --n; device = device -> next);
    if (device == NULL) return NULL;
	return device -> name;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("1st argument: number of packets to read\n");
        exit(-1);
    }
    int how_many = atoi(argv[1]);
    
    pcap_t *capturer = pcap_create(devprompt(), NULL);
    if (pcap_activate(capturer) < 0) {
        perror("A");
        exit(-1);
    }
    print_packets(capturer, how_many);
    pcap_close(capturer);
    return 0;
}

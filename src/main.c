// sudo modprobe usbmon

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

#include <common.h>
#include <packet_processor.h>

typedef struct packet {
	unsigned char *data;
	int size;
} packet_t;

pcap_t *capturer;
struct pcap_pkthdr *pkt;
packet_t *packets;

void exit_handler() {
	free(packets);
	free(pkt);
	pcap_close(capturer);
}

void signal_handler(int signum) {
	switch (signum) {
		case SIGINT:
			fterm++;
	}
}

void capture_packet(pcap_t *capturer, struct pcap_pkthdr *pkt, packet_t *pack) {
	pack -> data = pcap_next(capturer, pkt);
	pack -> size = pkt -> caplen;
}

char *devprompt() {
	pcap_if_t *alldevsp, *device;
	int devcount = 1;
	char errbuf[PCAP_ERRBUF_SIZE];

	//find all available devices
	if (pcap_findalldevs(&alldevsp, errbuf) < 0) {
		printf("Error finding devices : %s\n", errbuf);
		exit(-1);
	}

	//print available devices
	for (device = alldevsp; device != NULL; device = device->next) {
		printf("%d. %s - %s\n", devcount, device->name, device->description);
		devcount++;
	}

	int n;
	printf("Enter the number of the device you want to sniff: ");
	scanf("%d", &n);
	if (n < 1 || n > devcount) return NULL;
	for (device = alldevsp; device != NULL && --n; device = device->next);
	if (device == NULL) return NULL;
	return device->name;
}

int pack_num_prompt() {
	int how_many;
	printf("Enter the number of the packages to sniff: (-1 for endless loop) ");
	scanf("%d", &how_many);
	return how_many;
}

pcap_t *init_capture() {
	pcap_t *handle = pcap_create(devprompt(), NULL);
	if (pcap_activate(handle) < 0) {
		perror("Capture handle activation error: ");
		exit(-1);
	}
	return handle;
}

int main(int argc, char *argv[]) {
	struct sigaction sigact;
	memset (&sigact, 0, sizeof sigact);
	sigact.sa_handler = &signal_handler;
	fterm = 0;
	
	capturer = init_capture();
	int how_many = pack_num_prompt();
	finft = (how_many < 0) ? how_many = 1 : 0;
	
	pkt = calloc(1, sizeof(struct pcap_pkthdr));
	packets = calloc((size_t) how_many, sizeof(packet_t)); 
	
	atexit(exit_handler);
	sigaction(SIGINT, &sigact, NULL);
	
	do for (int i = 0; i < how_many; i++) {
		capture_packet(capturer, pkt, &packets[i]);
		process_packet(packets[i].data, packets[i].size);
		
		if (fterm > 0) return 0;
		
		if (fsend != 0) {
			if (pcap_inject(capturer, packets[i].data, packets[i].size) == -1) {
				pcap_perror(capturer, "Failed to inject packet");
				pcap_close(capturer);
				exit(1);
			}
		}
		
		if (fterm > 0) return 0;
	} while (finft);
	return 0;
}

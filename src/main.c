// sudo modprobe usbmon

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include <ethernet.h>
#include "packet_processor.h"

struct packet {
    unsigned char c[ETH_FRAME_LEN];
    int size;
};

typedef struct packet packet_t;

packet_t encapsulate_packet(const unsigned char *c, int size) {
    packet_t pck;
    memcpy(pck.c, c, (size_t) size);
    pck.size = size;
    return pck;
}

packet_t *capture_packets(pcap_t *capturer, int num) {
    struct pcap_pkthdr *data = calloc(1, sizeof(struct pcap_pkthdr));
    packet_t *packets = calloc((size_t) num, sizeof(packet_t));
    const unsigned char *c;
    
    for (int i = 0; i < num; i++) {
		pcap_next_ex(capturer, &data, &c);
        packets[i] = encapsulate_packet(c, data->caplen);
    }
    
    return packets;
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
    printf("Enter the number of the packages to sniff: ");
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
    pcap_t *capturer = init_capture();
    int how_many = pack_num_prompt();
    
    packet_t *packets = capture_packets(capturer, how_many);
    for (int i = 0; i < how_many; i++) print_packet(packets[i].c, packets[i].size);
    
    free(packets);
    pcap_close(capturer);
    return 0;
}

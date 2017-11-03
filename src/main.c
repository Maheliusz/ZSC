// sudo modprobe usbmon

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <string.h>
#include <ethernet.h>
#include "packet_processor.h"

void print_packets(pcap_t *capturer, int num) {
    struct pcap_pkthdr *data = calloc(1, sizeof(struct pcap_pkthdr));
    for (int i = 0; i < num; i++)
        print_ethernet_header(pcap_next(capturer, data), data->caplen);
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

int main(int argc, char *argv[]) {
    pcap_t *capturer = pcap_create(devprompt(), NULL);
    if (pcap_activate(capturer) < 0) {
        perror("Capture handle activation error: ");
        exit(-1);
    }

    int how_many;
    printf("Enter the number of the packages to sniff: ");
    scanf("%d", &how_many);

    print_packets(capturer, how_many);
    pcap_close(capturer);
    return 0;
}

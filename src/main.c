// sudo modprobe usbmon

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <string.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pthread.h>

struct packet {
    unsigned char c[1024];
    int size;
};

typedef struct packet packet_t;

unsigned short from_net_order(unsigned short n) {
    unsigned short x = 0x0001;
    if (!(*(unsigned char *) &x)) return n;    //big endian

    //convert from network order to little endian
    unsigned char *c = (unsigned char *) &n;
    return *c << 8 | *(c + 1);
}

void hex_dump(const unsigned char *c, int len) {
    printf("%.2X", c[0]);
    for (int i = 1; i < len; i++) printf(":%.2X", c[i]);
}

void print_bits(int bytelen, const u_char *string) {
    u_char symbol;
    for (int i = 0; i < bytelen; i++) {
        printf("Symbol %d:\n", i);
        symbol = string[i];
        for (int j = 7; j >= 0; j--) {
            printf("%d", (symbol & 1 << j) ? 1 : 0);
        }
        printf("\n");
    }
    printf("\n\n");
}

void print_ethernet_header(unsigned char *c, int size) {
    struct ethhdr *eth = (struct ethhdr *) c;

    //TODO: create semaphore for writing to output
    printf("Ethernet Header");
    printf("\n\t|-Destination Address: ");
    hex_dump(eth->h_dest, 6);
    printf("\t (");
    hex_dump(c, 6);
    printf(")");
    printf("\n\t|-Source Address:      ");
    hex_dump(eth->h_source, 6);
    printf("\t (");
    hex_dump(c + 6, 6);
    printf(")");

    unsigned short proto = ntohs((unsigned short) eth->h_proto);
    printf("\n\t|-Protocol:            %.4x", proto);
    switch (from_net_order((unsigned short) eth->h_proto)) {
        case 0x0800:
            printf("\t (IPv4)");
            break;
        case 0x86DD:
            printf("\t (IPv6)");
            break;
        default:
            break;
    }
    printf("\n");

    hex_dump(c + 14, size - 14);

    printf("\n\n");
}

packet_t encapsulate_packet(const unsigned char *c, int size) {
    packet_t pck;
    memcpy(pck.c, c, (size_t) size);
    pck.size = size;
    return pck;
}

void *start_processing_thread(void *arg) {
    packet_t *pck = (packet_t *) arg;
    print_ethernet_header(pck->c, pck->size);
    return NULL;
}

void capture_packets(pcap_t *capturer, int num) {
    struct pcap_pkthdr *data = calloc(1, sizeof(struct pcap_pkthdr));
    pthread_t *processing_threads = calloc((size_t) num, sizeof(pthread_t));
    packet_t *packets = calloc((size_t) num, sizeof(packet_t));
    for (int i = 0; i < num; i++) {
        packets[i] = encapsulate_packet(pcap_next(capturer, data), data->caplen);
        pthread_create(&processing_threads[i], NULL, start_processing_thread, (void *) &packets[i]);
    }
    for (int i = 0; i < num; i++) {
        pthread_join(processing_threads[i], NULL);
    }
    free(processing_threads);
    free(packets);
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

int packet_number() {
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
    capture_packets(capturer, packet_number());
    pcap_close(capturer);
    return 0;
}

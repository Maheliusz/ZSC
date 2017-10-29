// sudo modprobe usbmon

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

void print_bits(int bytelen, const u_char *string) {
    u_char symbol;
    for (int i = 0; i < bytelen; i++) {
        printf("Symbol %d:\n", i);
        symbol = string[i];
        for (int j = 7; j >= 0; j++) {
            printf("%d", (symbol & 1 << j) ? 1 : 0);
        }
        printf("\n");
    }
    printf("\n\n");
}

void print_packets(pcap_t *capturer, int num) {
    struct pcap_pkthdr *data = calloc(1, sizeof(struct pcap_pkthdr));
    for (int i = 0; i < num; i++) {
//        printf("%.*s", data->caplen,
//               pcap_next(capturer, data)
//        );
        print_bits(data->caplen, pcap_next(capturer, data));
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("1st argument: name of the port\n2nd argument: number of packets to read\n");
        exit(-1);
    }
    char *port = argv[1];
    int how_many = atoi(argv[2]);
    pcap_t *capturer = pcap_create(port, NULL);
    if (pcap_activate(capturer) < 0) {
        perror("A");
        exit(-1);
    }
    print_packets(capturer, how_many);
    pcap_close(capturer);
    return 0;
}

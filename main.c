// sudo modprobe usbmon

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <string.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

unsigned short from_net_order(unsigned short n) {
    unsigned short x = 0x0001;
    if(!(*(unsigned char*) &x)) return n;    //big endian
    
    //convert from network order to little endian
    unsigned char *c = (unsigned char*) &n;
    return *c << 8 | *(c + 1);
}

void hex_dump(const unsigned char* c, int len) {
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

void print_ethernet_header(const unsigned char *c, int size) {	
	struct ethhdr *eth = (struct ethhdr *) c;
	
	printf("Ethernet Header");
    printf("\n\t|-Destination Address: "); hex_dump(eth -> h_dest, 6);
    printf("\t ("); hex_dump(c, 6); printf(")");
    printf("\n\t|-Source Address:      "); hex_dump(eth -> h_source, 6);
    printf("\t ("); hex_dump(c + 6, 6); printf(")");
    
    unsigned short proto = ntohs((unsigned short) eth -> h_proto);
    printf("\n\t|-Protocol:            %.4x", proto);
    switch(from_net_order((unsigned short) eth -> h_proto)) {
		case 0x0800: printf("\t (IPv4)"); break;
		case 0x86DD: printf("\t (IPv6)"); break;
	}
	printf("\n");
	
	hex_dump(c + 14, size - 14);
	
	printf("\n\n");
}

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
    pcap_t *capturer = pcap_create(devprompt(), NULL);
    if (pcap_activate(capturer) < 0) {
        perror("A");
        exit(-1);
    }
    
    int how_many;
    printf("Enter the number of the packages to sniff: ");
    scanf("%d", &how_many);
    
    print_packets(capturer, how_many);
    pcap_close(capturer);
    return 0;
}

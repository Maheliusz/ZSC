#include "packet_processor.h"

void print_packet(const unsigned char *buf, int size) {
    print_ethernet_header(buf, size);
	printf("\n\n");
}

void print_ethernet_header(const unsigned char *buf, int size) {
	struct ethhdr *eth = (struct ethhdr *) buf;
	
	printf("Ethernet Header\n");
	
	//dump hex value of the header separating its fields
	hex_dump(buf, ETH_ALEN);
	printf("|");
	hex_dump(buf + ETH_ALEN, ETH_ALEN);
	printf("|");
	hex_dump(buf + 2 * ETH_ALEN, ETH_HLEN - 2 * ETH_ALEN);
	
	//calculate offset for next header
	buf += ETH_HLEN;
    size -= ETH_HLEN;
	
	//print header with description
    printf("\n\t|-Destination Address: ");
    hex_dump(eth -> h_dest, ETH_ALEN);
    printf("\n\t|-Source Address:      ");
    hex_dump(eth -> h_source, ETH_ALEN);
    
    h_uint16_t proto = ntohs(eth -> h_proto);
    printf("\n\t|-Protocol:            ");
    switch (proto) {
        case ETH_P_IP:
            printf("IPv4\n");
            dump_ip_header(buf, ((struct iphdr *) buf) -> ihl);
            break;
        case ETH_P_IPV6:
            printf("IPv6\n");
			dump_ip6_header(buf, IP6_HLEN);
            break;
        default:
			printf("%.4x\n", proto);
			hex_dump(buf, size);
            break;
    }
}

void dump_ip_header(const unsigned char *buf, int len) {
	for (int i = 1; i < IPHDR_FIELDC; i++) {
		hex_dump(buf + IPHDR_OFFSET(i - 1), IPHDR_OFFSET(i));
		printf("|");
	}
	printf("\b\n");
}

void dump_ip6_header(const unsigned char *buf, int len) {
	for (int i = 1; i < IP6HDR_FIELDC; i++) {
		hex_dump(buf + IP6HDR_OFFSET(i - 1), IP6HDR_OFFSET(i));
		printf("|");
	}
	printf("\b\n");
	
	printf("%d", IP6HDR_FIELDC);
}

void hex_dump(const unsigned char *buf, int len) {
    printf("%.2X", buf[0]);
    for (int i = 1; i < len; i++) printf(":%.2X", buf[i]);
}

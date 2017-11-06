#include "packet_processor.h"

void print_packet(const unsigned char *buf, int size) {
	struct ethhdr *eth = (struct ethhdr *) buf;
	
	printf("Ethernet Header\n");
	dump_ethernet_header(buf);
    print_ethernet_header(eth);
    buf += ETH_HLEN;
    size -= ETH_HLEN;
    
    switch(eth -> h_proto) {
		case ETH_P_IP:;
			struct iphdr *ip = (struct iphdr*) buf;
            dump_ip_header(buf, (int) ip -> ihl);
            break;
        case ETH_P_IPV6:
        default:
			hex_dump(buf, size);
            break;
	}
	printf("\n\n");
}

void dump_ethernet_header(const unsigned char *buf) {
	hex_dump(buf, ETH_ALEN);
	printf("|");
	hex_dump(buf + ETH_ALEN, ETH_ALEN);
	printf("|");
	hex_dump(buf + 2 * ETH_ALEN, ETH_HLEN - 2 * ETH_ALEN);
}

void print_ethernet_header(const struct ethhdr *eth) {
    printf("\n\t|-Destination Address: ");
    hex_dump(eth -> h_dest, ETH_ALEN);
    printf(")");
    printf("\n\t|-Source Address:      ");
    hex_dump(eth -> h_source, ETH_ALEN);
    printf(")");
    
    h_uint16_t proto = ntohs(eth -> h_proto);
    printf("\n\t|-Protocol:            ");
    switch (proto) {
        case ETH_P_IP:
            printf("IPv4\n");
            break;
        case ETH_P_IPV6:
            printf("IPv6\n");
            break;
        default:
			printf("%.4x\n", proto);
            break;
    }
}

void dump_ip_header(const unsigned char *buf, int len) {
	hex_dump(buf, 1);
}

void hex_dump(const unsigned char *buf, int len) {
    printf("%.2X", buf[0]);
    for (int i = 1; i < len; i++) printf(":%.2X", buf[i]);
}

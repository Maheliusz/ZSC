#include "packet_processor.h"

void hex_dump(const unsigned char *buf, int len) {
    printf("%.2X", buf[0]);
    for (int i = 1; i < len; i++) printf(":%.2X", buf[i]);
}

void print_ethernet_header(const unsigned char *buf, int size) {
	struct ethhdr *eth = (struct ethhdr *) buf;
    printf("Ethernet Header\n");
    
    //dump the header
    hex_dump(buf, ETH_ALEN);
    printf("|");
    hex_dump(buf + ETH_ALEN, ETH_ALEN);
    printf("|");
    hex_dump(buf + 2 * ETH_ALEN, ETH_HLEN - 2 * ETH_ALEN);
    
    //describe the fields
    printf("\n\t|-Destination Address: ");
    hex_dump(eth -> h_dest, ETH_ALEN);
    printf(")");
    printf("\n\t|-Source Address:      ");
    hex_dump(eth -> h_source, ETH_ALEN);
    printf(")");
    
    h_uint16_t proto = ntohs(eth -> h_proto);
    printf("\n\t|-Protocol:            ");
    switch (proto) {
        case 0x0800:
            printf("(IPv4)\n");
            break;
        case 0x86DD:
            printf("(IPv6)\n");
            break;
        default:
			printf("%.4x\n", proto);
            break;
    }
    
    hex_dump(buf + 14, size - 14);
    
    printf("\n\n");
}

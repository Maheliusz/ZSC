#include <stdio.h>
#include <ethernet.h>
#include <packet_processor.h>

void print_ethernet_header(const struct ethhdr *eth, int size) {
    printf("\n\t|-Destination Address: ");
    hex_dump(eth -> h_dest, ETH_ALEN);
    printf("\n\t|-Source Address:      ");
    hex_dump(eth -> h_source, ETH_ALEN);

    h_uint16_t proto = ntohs(eth->h_proto);
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
    }
}

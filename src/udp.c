#include <stdio.h>
#include <udp.h>
#include <common.h>

void print_udp_header(const struct udphdr *udp, int size) {
	printf("\n\t|-Source Port:      ");
	printf("%u", ntohs(udp -> uh_sport));
	printf("\n\t|-Destination Port: ");
	printf("%u", ntohs(udp -> uh_dport));
	printf("\n\t|-Length:           ");
	printf("%u", ntohs(udp -> uh_ulen));
	printf("\n\t|-Checksum:         ");
	printf("%.4x", ntohs(udp -> uh_sum));
	printf("\n\t|-Data:             ");
}

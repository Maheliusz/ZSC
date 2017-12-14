#include <stdio.h>
#include <ipv6.h>
#include <common.h>

void print_ip6_header(const struct ipv6hdr *ip, int size) {
	printf("\n\t|-IP Version:          ");
	printf("%.1x", get_ip6_version(ip));
	printf("\n\t|-Traffic Class:       ");
	printf("%.1x", get_ip6_tclass(ip));
	printf("\n\t|-Flow Label:          ");
	printf("%.3x", get_ip6_flow_lbl(ip));
	printf("\n\t|-Payload Length:      ");
	printf("%u", ntohs(ip -> payload_len));

	printf("\n\t|-Next Header:         ");
	switch (ip -> nexthdr) {
		case IP6_NEXT_ICMP:
			printf("ICMP");
			break;
		case IP6_NEXT_ICMPv6:
			printf("ICMPv6");
			break;
		case IP6_NEXT_TCP:
			printf("TCP");
			break;
		case IP6_NEXT_UDP:
			printf("UDP");
			break;
		case IP6_NEXT_NONE:
			printf("No next header");
			break;
		default:
			printf("%.2x", ip -> nexthdr);
	}
	
	printf("\n\t|-Hop Limit:           ");
	printf("%u", ip -> hop_limit);
	printf("\n\t|-Source Address:      ");
	hex_dump(ip -> saddr, IP6_ALEN);
	printf("\n\t|-Destination Address: ");
	hex_dump(ip -> daddr, IP6_ALEN);
	printf("\n");
    //printf("%d\n", sizeof(ip->saddr)/sizeof(n_uint16_t));
}

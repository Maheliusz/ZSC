#include <stdio.h>
#include <icmpv6.h>
#include <packet_processor.h>

void print_icmp6_header(const struct icmp6hdr *icmp, int size) {
	printf("\n\t|-Type:     ");
	switch ((icmp -> type)) {
		case ICMP6_ECHOREQUEST:
			printf("Echo Request");
			break;
		case ICMP6_ECHOREPLY:
			printf("Echo Reply");
			break;
		default:
			printf("%d", (icmp -> type));
	}

	printf("\n\t|-Code:     ");
	printf("%u", icmp -> code);
	printf("\n\t|-Checksum: ");
	printf("%.4x", ntohs(icmp -> cksum));
	printf("\n\t|-Data:     ");
	printf("%.8x\n", ntohl(icmp -> dataun.un_data32[0]));
}

void print_icmp6_echo(const struct icmp6hdr *icmp, int size) {
	printf("\n\t|-Identifier:      ");
	printf("%.1x", ntohs(icmp->dataun.un_data16[0]));
	printf("\n\t|-Sequence Number: ");
	printf("%.1x", ntohs(icmp->dataun.un_data16[1]));
	printf("\n\t|-Data:            ");
}

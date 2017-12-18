#include <stdio.h>
#include <tcp.h>
#include <common.h>

void print_tcp_header(const struct tcphdr *tcp, int size) {
	printf("\n\t|-Source Port:            ");
	printf("%u", ntohs(tcp -> th_sport));
	printf("\n\t|-Destination Port:       ");
	printf("%u", ntohs(tcp -> th_dport));
	printf("\n\t|-Sequence Number:        ");
	printf("%ul", ntohl(tcp -> th_seq));
	printf("\n\t|-Acknowledgement Number: ");
	printf("%ul", ntohl(tcp -> th_ack));
	printf("\n\t|-Data Offset:            ");
	printf("%u", get_tcp_offset(tcp));
	
	printf("\n\t|-Flags:                  ");
	h_uint16_t th_flags = get_tcp_flags(tcp);
	if (th_flags & TH_FIN)	printf("FIN ");
	if (th_flags & TH_SYN)	printf("SYN ");
	if (th_flags & TH_RST)	printf("RST ");
	if (th_flags & TH_PUSH)	printf("PUSH ");
	if (th_flags & TH_ACK)	printf("ACK ");
	if (th_flags & TH_URG)	printf("URG ");
	
	printf("\n\t|-Window:                 ");
	printf("%u", ntohs(tcp -> th_win));
	printf("\n\t|-Checksum:               ");
	printf("%.4x", ntohs(tcp -> th_sum));
	printf("\n\t|-Urgent pointer:         ");
	printf("%.4x", ntohs(tcp -> th_urp));
	printf("\n\t|-Data:             ");
}

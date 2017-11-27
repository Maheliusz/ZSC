#include "packet_processor.h"

void process_packet(unsigned char *buf, int size) {
	fsend = 0;
	printf("Ethernet Header\n");
	
	//dump hex value of the header separating its fields
	hex_dump(buf, ETH_ALEN);
	printf("|");
	hex_dump(buf + ETH_ALEN, ETH_ALEN);
	printf("|");
	hex_dump(buf + 2 * ETH_ALEN, ETH_HLEN - 2 * ETH_ALEN);
	
	//print header with description
	print_ethernet_header((struct ethhdr *) buf, size);
	
	//process next header
	switch (ntohs(((struct ethhdr *) buf) -> h_proto)) {
		case ETH_P_IP:
			process_ip_header(buf, ETH_HLEN, size);
			break;
		case ETH_P_IPV6:
			process_ip6_header(buf, ETH_HLEN, size);
			break;
		default:
			hex_dump(buf + ETH_HLEN, size - ETH_HLEN);
	}
	
	printf("\n\n");
}

void process_ip_header(unsigned char *buf, int offset, int size) {
	printf("IP Header\n");
	const unsigned char *header = buf + offset;
	
	//dump hex value of the header separating its fields
	for (int i = 0; i < IPHDR_FIELDC; i++) {
		if (i > 0) printf("|");
		hex_dump(header, IPHDR_OFFSET(i));
		header += IPHDR_OFFSET(i);
	}
	
	//print header with description
	struct iphdr *ip = (struct iphdr *) header;
	print_ip_header(ip, ip -> ihl);
}

void process_ip6_header(unsigned char *buf, int offset, int size) {
	printf("IPv6 Header\n");
	const unsigned char *header = buf + offset;
	
	//dump hex value of the header separating its fields
	for (int i = 0; i < IP6HDR_FIELDC; i++) {
		hex_dump(header, IP6HDR_OFFSET(i));
		printf("|");
		header += IP6HDR_OFFSET(i);
	}
	
	hex_dump(header, IP6_ALEN);
	printf("|");
	hex_dump(header + IP6_ALEN, IP6_ALEN);
	
	header = buf + offset;
	
	//print header with description
	print_ip6_header((struct ipv6hdr *) header, IP6_HLEN);
	
	//process next header
	switch (((struct ipv6hdr *) header) -> nexthdr) {
		case IP6_NEXT_ICMPv6:
			process_icmp6_header(buf, offset, offset + IP6_HLEN, size);
			break;
		default:
			hex_dump(buf + offset + IP6_HLEN, size - offset - IP6_HLEN);
	}
}

void process_icmp6_header(unsigned char *buf, int ip_offset, int offset, int size) {
	printf("ICMP6 Header\n");
	const unsigned char *header = buf + offset;
	struct icmp6hdr *icmp = (struct icmp6hdr *) header;
	
	//dump hex value of the header separating its fields
	printf("%.2x|%.2x|", header[0], header[1]);
	hex_dump(header + 2, 2);
	printf("|");
	hex_dump(header + 4, size - 4);

	//print header with description
	print_icmp6_header(icmp, IP6_HLEN);
	
	//process data
	switch (icmp -> type) {
		case ICMP6_ECHOREQUEST:
			process_icmp6_echo_request(buf, ip_offset, offset, size);
			break;
		case ICMP6_ECHOREPLY:
			process_icmp6_echo_reply(buf, ip_offset, offset, size);
			break;
		default:
			hex_dump(buf + 4, size - 4);
	}
}

static inline void process_icmp6_echo(const unsigned char *buf, int ip_offset, int offset, int size) {
	printf("ICMP6 Echo Request");
	const unsigned char *header = buf + offset;
	struct icmp6hdr *icmp = (struct icmp6hdr *) header;
	offset += ICMP6_HLEN;
	
	print_icmp6_echo(icmp, ICMP6_HLEN);
	hex_dump(buf + offset, size - offset);
	printf("\n");
	fflush(stdout);
	for (int i = offset; i < size; i++)
		if (buf[i] >= ' ' && buf[i] < '~') putchar(buf[i]);
		else putchar(' ');
}

void process_icmp6_echo_request(unsigned char *buf, int ip_offset, int offset, int size) {
	process_icmp6_echo(buf, ip_offset, offset, size);
	
	const unsigned char *header = buf + offset;
	struct icmp6hdr *icmp = (struct icmp6hdr *) header;
	
	//swap ethernet addresses
	struct ethhdr *eth = (struct ethhdr *) buf;
	byte_swap(eth -> h_dest, eth -> h_source, ETH_ALEN);
	
	//swap ip addresses
	struct ipv6hdr *ip6 = (struct ipv6hdr *) (buf + ip_offset);
	byte_swap(ip6 -> daddr, ip6 -> saddr, IP6_ALEN);
	
	//change message type
	//icmp -> type = ICMP6_ECHOREPLY;
	
	//calculate the checksum
	//icmp -> cksum = chksum(...);
	
	fsend = 1;
}

void process_icmp6_echo_reply(const unsigned char *buf, int ip_offset, int offset, int size) {
	process_icmp6_echo(buf, ip_offset, offset, size);
}

n_uint16_t chksum(const unsigned char *buf, int size) {
}

void hex_dump(const unsigned char *buf, int len) {
	printf("%.2X", buf[0]);
	for (int i = 1; i < len; i++) printf(":%.2X", buf[i]);
}

void byte_swap(unsigned char *c1, unsigned char *c2, int size) {
	unsigned char tmp;
	
	for (int i = 0; i < size; i++) {
		tmp = c2[i];
		c2[i] = c1[i];
		c1[i] = tmp;
	}
}

#include <stdlib.h>
#include <icmpv6.h>
#include <tcp.h>
#include <udp.h>
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
    switch (ntohs(((struct ethhdr *) buf)->h_proto)) {
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
    print_ip_header(ip, ip->ihl);
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
			process_icmp6_header(buf, offset, offset + IP6_HLEN, size, (struct ipv6hdr *) header);
			break;
		case IP6_NEXT_UDP:
			process_udp_header(buf, offset, offset + IP6_HLEN, size);
			break;
		case IP6_NEXT_TCP:
			process_tcp_header(buf, offset, offset + IP6_HLEN, size);
		default:
			hex_dump(buf + offset + IP6_HLEN, size - offset - IP6_HLEN);
	}
}

void process_icmp6_header(unsigned char *buf, int ip_offset, int offset, int size, struct ipv6hdr *hdrv6) {
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
    switch (icmp->type) {
        case ICMP6_ECHOREQUEST:
            process_icmp6_echo_request(buf, ip_offset, offset, size);
            break;
        case ICMP6_ECHOREPLY:
            process_icmp6_echo_reply(buf, ip_offset, offset, size);
            break;
        default:
            hex_dump(buf + 4, size - 4);
    }
    printf("\nChksum: %x\n", ntohs(icmpv6_chksum(hdrv6, icmp)));
}

static inline void process_icmp6_echo(const unsigned char *buf, int ip_offset, int offset, int size) {
	printf("ICMP6 Echo Request");
	const unsigned char *header = buf + offset;
	struct icmp6hdr *icmp = (struct icmp6hdr *) header;
	offset += ICMP6_HLEN;
	
	print_icmp6_echo(icmp, ICMP6_HLEN);
	
	print_data(buf, offset, size);
}

void process_icmp6_echo_request(unsigned char *buf, int ip_offset, int offset, int size) {
    process_icmp6_echo(buf, ip_offset, offset, size);

    const unsigned char *header = buf + offset;
    struct icmp6hdr *icmp = (struct icmp6hdr *) header;

    //swap ethernet addresses
    struct ethhdr *eth = (struct ethhdr *) buf;
    byte_swap(eth->h_dest, eth->h_source, ETH_ALEN);

    //swap ip addresses
    struct ipv6hdr *ip6 = (struct ipv6hdr *) (buf + ip_offset);
    byte_swap(ip6->daddr, ip6->saddr, IP6_ALEN);

    //change message type
    //icmp -> type = ICMP6_ECHOREPLY;

    //calculate the checksum
    //icmp -> cksum = chksum(...);

    fsend = 1;
}

void process_icmp6_echo_reply(const unsigned char *buf, int ip_offset, int offset, int size) {
    process_icmp6_echo(buf, ip_offset, offset, size);
}

n_uint16_t icmpv6_chksum(struct ipv6hdr *ip6, struct icmp6hdr *icmp) {

    //bufor o maksymalnym rozmiarze pakietu ipv6
    unsigned char buf[65535];
    unsigned char *ptr = &(buf[0]);
    int chksumlen = 0;

    //source address
    memcpy(ptr, &ip6->saddr, sizeof(ip6->saddr));
    ptr += sizeof(ip6->saddr);
    chksumlen += sizeof(ip6->saddr);

    //dest address
    memcpy(ptr, &ip6->daddr, sizeof(ip6->daddr));
    ptr += sizeof(ip6->daddr);
    chksumlen += sizeof(ip6->daddr);

    //ICMP6 length = payload len + ICMP6 header len
//    /*
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    *ptr = (ICMP6_HLEN + sizeof(icmp->dataun))/256; ptr++;
    *ptr = (ICMP6_HLEN + sizeof(icmp->dataun))%256; ptr++;
//    */
    /*
    n_uint32_t upprlen = sizeof(icmp->dataun.un_data32) + ICMP6_HLEN;
    memcpy(ptr, &upprlen, sizeof(n_uint32_t));
    ptr += 4;
     */
    chksumlen += 4;


    //3 oktety zer, potem IPv6 Next Header
//    /*
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen+=3;
    memcpy(ptr, &ip6->nexthdr, sizeof(ip6->nexthdr));
    ptr+=sizeof(ip6->nexthdr);
    chksumlen+=sizeof(ip6->nexthdr);
//     */
    /*
    n_uint32_t hdr = ip6->nexthdr;
    memcpy(ptr, &hdr, sizeof(hdr));
    ptr += sizeof(hdr);
    chksumlen += sizeof(hdr);
     */


    //ICMPv6 typ
    memcpy(ptr, &icmp->type, sizeof(icmp->type));
    ptr += sizeof(icmp->type);
    chksumlen += sizeof(icmp->type);

    //ICMPv6 kod
    memcpy(ptr, &icmp->code, sizeof(icmp->code));
    ptr += sizeof(icmp->code);
    chksumlen += sizeof(icmp->code);

    //ICMPv6 suma kontrolna - na czas liczenia sumy kontrolnej = 0
    n_uint16_t tmpchksum = 0;
    memcpy(ptr, &tmpchksum, sizeof(tmpchksum));
    ptr += sizeof(tmpchksum);
    chksumlen += sizeof(tmpchksum);


    //ICMPv6 payload
    memcpy(ptr, &icmp->dataun.un_data32, sizeof(icmp->dataun.un_data32));
    ptr += sizeof(icmp->dataun.un_data32);
    chksumlen += sizeof(icmp->dataun);

    //wyrownujemy do 16-bitowej granicy zerami
    for(int i=0; i<sizeof(icmp->dataun.un_data32); i++, ptr++){
        *ptr=0;
        ptr++;
        chksumlen++;
    }

    return chksum((n_uint16_t *) buf, chksumlen);
}

//funkcja liczaca internet checksum
n_uint16_t chksum(n_uint16_t *buf, int len) {
    int count = len;
    n_uint32_t sum = 0;
    while (count > 1) {
        sum += *(buf++);
        count -= 2;
    }
    if (count > 0) {
        sum += *(uint8_t *) buf;
    }
    while (sum >> 16) {
        sum = (n_uint16_t) sum + (sum >> 16);
    }
    return ~((n_uint16_t) sum);
}
void process_udp_header(unsigned char *buf, int ip_offset, int offset, int size) {
	printf("UDP Header\n");
	const unsigned char *header = buf + offset;
	struct udphdr *udp = (struct udphdr *) header;
	
	//dump hex value of the header separating its fields
	hex_dump(header + 0, 2);
	for (int i = 1; i < 4; i++) {
		printf("|");
		hex_dump(header + 2 * i, 2);
	}

	//print header with description
	print_udp_header(udp, IP6_HLEN);
	
	print_data(buf, offset, size);
}

void process_tcp_header(unsigned char *buf, int ip_offset, int offset, int size) {
	printf("TCP Header\n");
	const unsigned char *header = buf + offset;
	struct tcphdr *tcp = (struct tcphdr *) header;
	
	//dump hex value of the header separating its fields
//	hex_dump(header + 0, 2);
//	for (int i = 1; i < 4; i++) {
//		printf("|");
//		hex_dump(header + 2 * i, 2);
//	}

	//print header with description
	print_tcp_header(tcp, IP6_HLEN);
	
	print_data(buf, offset, size);
}

void print_data(const unsigned char *buf, int offset, int size) {
	hex_dump(buf + offset, size - offset);
	printf("\n");
	fflush(stdout);
	for (int i = offset; i < size; i++)
		if (buf[i] >= ' ' && buf[i] < '~') putchar(buf[i]);
		else putchar(' ');
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

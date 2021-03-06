#include <stdlib.h>
#include <icmpv6.h>
#include <tcp.h>
#include <udp.h>
#include "packet_processor.h"

void process_udp_data_answer(unsigned char *string, int size);

//process raw Ethernet packet
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
            process_ip_header(buf, ETH_HLEN, size - ETH_HLEN);
            break;
        case ETH_P_IPV6:
            process_ip6_header(buf, ETH_HLEN, size - ETH_HLEN);
            break;
        default:
            hex_dump(buf + ETH_HLEN, size - ETH_HLEN);
    }

    printf("\n\n");
}

//process raw IPv4 packet
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

//process raw IPv6 packet
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
    switch (((struct ipv6hdr *) header)->nexthdr) {
        case IP6_NEXT_ICMPv6:
            process_icmp6_header(buf, offset, offset + IP6_HLEN, size - IP6_HLEN, (struct ipv6hdr *) header);
            break;
        case IP6_NEXT_UDP:
            process_udp_header(buf, offset, offset + IP6_HLEN, size - IP6_HLEN, (struct ipv6hdr *) header);
            break;
        case IP6_NEXT_TCP:
            process_tcp_header(buf, offset, offset + IP6_HLEN, size - IP6_HLEN);
        default:
            hex_dump(buf + offset + IP6_HLEN, size - offset - IP6_HLEN);
    }
}

//process raw ICMPv6 packet
void process_icmp6_header(unsigned char *buf, int ip_offset, int offset, int size, struct ipv6hdr *hdrv6) {
    printf("ICMP6 Header\n");
    unsigned char *header = buf + offset;
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
            hex_dump(buf + ICMP6_HLEN, size - ICMP6_HLEN);
    }
}

static inline void process_icmp6_echo(const unsigned char *buf, int ip_offset, int offset, int size) {
    printf("ICMP6 Echo");
    const unsigned char *header = buf + offset;
    struct icmp6hdr *icmp = (struct icmp6hdr *) header;
    offset += ICMP6_HLEN;

    print_icmp6_echo(icmp, ICMP6_HLEN);

    print_data(buf, offset, size);
}

//answer ICMPv6 echo request
void process_icmp6_echo_request(unsigned char *buf, int ip_offset, int offset, int size) {
    process_icmp6_echo(buf, ip_offset, offset, size);

    unsigned char *header = buf + offset;
    struct icmp6hdr *icmp = (struct icmp6hdr *) header;

    //swap ethernet addresses
    struct ethhdr *eth = (struct ethhdr *) buf;
    byte_swap(eth->h_dest, eth->h_source, ETH_ALEN);

    //swap ip addresses
    struct ipv6hdr *ip6 = (struct ipv6hdr *) (buf + ip_offset);
    byte_swap(ip6->daddr, ip6->saddr, IP6_ALEN);

    //change message type
    icmp->type = ICMP6_ECHOREPLY;

    //calculate the checksum
    icmp->cksum = icmpv6_chksum(ip6, icmp, header + ICMP6_HLEN, size);

    SEND_PACKET();
}

void process_icmp6_echo_reply(const unsigned char *buf, int ip_offset, int offset, int size) {
    process_icmp6_echo(buf, ip_offset, offset, size);
}

//setting up checksum buffer with ICMPv6 header
n_uint16_t icmpv6_chksum(struct ipv6hdr *ip6, struct icmp6hdr *icmp, unsigned char *data, int len) {
    unsigned char buf[65535];
    unsigned char *ptr = &(buf[0]);
    int chksumlen = 0;

    //ICMPv6 type
    memcpy(ptr, &icmp->type, sizeof(icmp->type));
    ptr += sizeof(icmp->type);
    chksumlen += sizeof(icmp->type);

    //ICMPv6 code
    memcpy(ptr, &icmp->code, sizeof(icmp->code));
    ptr += sizeof(icmp->code);
    chksumlen += sizeof(icmp->code);

    //ICMPv6 payload
    memcpy(ptr, &icmp->dataun.un_data16[0], sizeof(icmp->dataun.un_data16[0]));
    ptr += sizeof(icmp->dataun.un_data16[0]);
    chksumlen += sizeof(icmp->dataun.un_data16[0]);
    memcpy(ptr, &icmp->dataun.un_data16[1], sizeof(icmp->dataun.un_data16[1]));
    ptr += sizeof(icmp->dataun.un_data16[1]);
    chksumlen += sizeof(icmp->dataun.un_data16[1]);

    unsigned char *tmp = data;
    int i;
    for (i = 0; i < len * sizeof(unsigned char); i++) {
        memcpy(ptr, tmp, sizeof(unsigned char));
        ptr += sizeof(unsigned char);
        tmp += sizeof(unsigned char);
        chksumlen += sizeof(unsigned char);
    }

    //pad to the 16bit boundary
    if (len % 2 != 0) {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return pseudoheader_chksum(buf, ptr, ip6, chksumlen);
}

//setting up checksum buffer with UDP header
n_uint16_t udp_checksum(struct ipv6hdr *ip6, struct udphdr *udp, unsigned char *data) {
    unsigned char buf[65535];
    unsigned char *ptr = &(buf[0]);
    int chksumlen = 0;

    memcpy(ptr, &udp->uh_dport, sizeof(udp->uh_dport));
    ptr += sizeof(udp->uh_dport);
    chksumlen += sizeof(udp->uh_dport);

    memcpy(ptr, &udp->uh_sport, sizeof(udp->uh_sport));
    ptr += sizeof(udp->uh_sport);
    chksumlen += sizeof(udp->uh_sport);

    memcpy(ptr, &udp->uh_ulen, sizeof(udp->uh_ulen));
    ptr += sizeof(udp->uh_ulen);
    chksumlen += sizeof(udp->uh_ulen);

    unsigned char *tmp = data;
    int i;
    for (i = 0; i < udp->uh_ulen * sizeof(unsigned char); i++) {
        memcpy(ptr, tmp, sizeof(unsigned char));
        ptr += sizeof(unsigned char);
        tmp += sizeof(unsigned char);
        chksumlen += sizeof(unsigned char);
    }

    if (i % 2 != 0) {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return pseudoheader_chksum(buf, ptr, ip6, chksumlen);
}

//adding pseudoheader to checksum buffer
n_uint16_t pseudoheader_chksum(unsigned char *buf, unsigned char *ptr, struct ipv6hdr *ip6, int chksumlen) {

    //source address
    memcpy(ptr, &ip6->saddr, sizeof(ip6->saddr));
    ptr += sizeof(ip6->saddr);
    chksumlen += sizeof(ip6->saddr);

    //dest address
    memcpy(ptr, &ip6->daddr, sizeof(ip6->daddr));
    ptr += sizeof(ip6->daddr);
    chksumlen += sizeof(ip6->daddr);

    //upper layer length
    uint32_t upprlen = 0;
    upprlen += (ip6->payload_len);
    memcpy(ptr, &upprlen, sizeof(upprlen));
    ptr += 4;
    chksumlen += 4;

    //3 bytes = 0, then next header byte
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 3;
    memcpy(ptr, &ip6->nexthdr, sizeof(ip6->nexthdr));
    ptr += sizeof(ip6->nexthdr);
    chksumlen += sizeof(ip6->nexthdr);

    return chksum((uint16_t *) buf, chksumlen);
}

//counting checksum
n_uint16_t chksum(uint16_t *buf, int len) {
    int count = len;
    uint32_t sum = 0;
    uint16_t res = 0;
    while (count > 1) {
        sum += (*(buf));
        buf++;
        count -= 2;
    }
    if (count > 0) {
        sum += *(unsigned char *) buf;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    res = (uint16_t) sum;
    return ~res;
}

//process raw UDP packet
void process_udp_header(unsigned char *buf, int ip_offset, int offset, int size, struct ipv6hdr *ip6) {
    printf("UDP Header\n");
    unsigned char *header = buf + offset;
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

    //HARDCODED SERVER PORT ADDRESS: 50051
    if (udp->uh_dport == htons(50051)) reply_udp(buf, ip_offset, offset, size);
}

//answer UDP client's request
void reply_udp(unsigned char *buf, int ip_offset, int offset, int size) {
    struct udphdr *udp = (struct udphdr *) (buf + offset);

    //swap ethernet addresses
    struct ethhdr *eth = (struct ethhdr *) buf;
    byte_swap(eth->h_dest, eth->h_source, ETH_ALEN);

    //swap ip addresses
    struct ipv6hdr *ip6 = (struct ipv6hdr *) (buf + ip_offset);
    byte_swap(ip6->daddr, ip6->saddr, IP6_ALEN);

    //swap udp protocols
    n_uint16_t tmp_port = udp->uh_dport;
    udp->uh_dport = udp->uh_sport;
    udp->uh_sport = tmp_port;

    process_udp_data_answer(buf + offset + UDP_HLEN, size);

    udp->uh_sum = udp_checksum(ip6, udp, buf + offset + UDP_HLEN);

    SEND_PACKET();
}

void process_udp_data_answer(unsigned char *string, int size) {
    for (int i = 0; i < size; i++) {
        if (string[i] == '\n') return;
        else {
            string[i]++;
        }
    }
}

//process raw TCP packet
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

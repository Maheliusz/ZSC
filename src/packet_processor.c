#include "packet_processor.h"

void print_packet(const unsigned char *buf, int size) {
    print_ethernet_header(buf, size);
    printf("\n\n");
}

void print_ethernet_header(const unsigned char *buf, int size) {
    struct ethhdr *eth = (struct ethhdr *) buf;

    printf("Ethernet Header\n");

    //dump hex value of the header separating its fields
    hex_dump(buf, ETH_ALEN);
    printf("|");
    hex_dump(buf + ETH_ALEN, ETH_ALEN);
    printf("|");
    hex_dump(buf + 2 * ETH_ALEN, ETH_HLEN - 2 * ETH_ALEN);

    //calculate offset for next header
    buf += ETH_HLEN;
    size -= ETH_HLEN;

    //print header with description
    printf("\n\t|-Destination Address: ");
    hex_dump(eth->h_dest, ETH_ALEN);
    printf("\n\t|-Source Address:      ");
    hex_dump(eth->h_source, ETH_ALEN);

    h_uint16_t proto = ntohs(eth->h_proto);
    printf("\n\t|-Protocol:            ");
    switch (proto) {
        case ETH_P_IP:
            printf("IPv4\n");
            dump_ip_header(buf, ((struct iphdr *) buf)->ihl);
            break;
        case ETH_P_IPV6:
            printf("IPv6\n");
            print_ip6_header(buf, IP6_HLEN);
            break;
        default:
            printf("%.4x\n", proto);
            hex_dump(buf, size);
    }
}

void dump_ip_header(const unsigned char *buf, int size) {
    for (int i = 1; i < IPHDR_FIELDC; i++) {
        hex_dump(buf + IPHDR_OFFSET(i - 1), IPHDR_OFFSET(i));
        printf("|");
    }
    printf("\b\n");
}

void print_ip6_header(const unsigned char *buf, int size) {
    struct ipv6hdr *ip = (struct ipv6hdr *) buf;

    //dump hex value of the header separating its fields
    for (int i = 1; i < IP6HDR_FIELDC; i++) {
        hex_dump(buf + IP6HDR_OFFSET(i - 1), IP6HDR_OFFSET(i));
        printf("|");
    }

    //print header with description
    printf("\n\t|-IP Version:          ");
    printf("%.1x", get_ip6_version(ip));
    printf("\n\t|-Traffic Class:       ");
    printf("%.1x", get_ip6_tclass(ip));
    printf("\n\t|-Payload Length:      ");
    printf("%.3x\n", get_ip6_flow_lbl(ip));

    printf("\n\t|-Next Header:         ");
    switch (ip->nexthdr) {
        case IP6_NEXT_ICMP:
            printf("ICMP\n");
            break;
        case IP6_NEXT_ICMPv6:
            printf("ICMPv6\n");
            break;
        case IP6_NEXT_TCP:
            printf("TCP\n");
            break;
        case IP6_NEXT_UDP:
            printf("UDP\n");
            break;
        case IP6_NEXT_NONE:
            printf("No next header\n");
            break;
        default:
            printf("%.2x", ip->nexthdr);
    }

    printf("\n\t|-Hop Limit:           ");
    printf("%.2x", ip->hop_limit);
    printf("\n\t|-Source Address:      ");
    hex_dump(ip->saddr, IP6_ALEN);
    printf("\n\t|-Destination Address: ");
    hex_dump(ip->daddr, IP6_ALEN);
    printf("\b\n");

    //calculate offset for next header
    buf += IP6_HLEN;
    size -= IP6_HLEN;

    switch (ip->nexthdr) {
        case IP6_NEXT_ICMPv6:
            print_icmp6_header(buf, size);
        default:
            break;
    }
}

void print_icmp6_header(const unsigned char *buf, int size) {
    struct icmp6hdr *icmp = (struct icmp6hdr *) buf;

    //dump hex value of the header separating its fields
    printf("%.2x|%.2x|", buf[0], buf[1]);
    hex_dump(buf + 2, 2);
    printf("|");
    hex_dump(buf + 4, size - 4);

    //print header with description
    printf("\n\t|-Type:     ");
    switch ((icmp->type)) {
        case ICMPV6_ECHOREQUEST:
            printf("Echo Request");
            break;
        case ICMPV6_ECHOREPLY:
            printf("Echo Reply");
            break;
        default:
            printf("%d", (icmp->type));
    }

    printf("\n\t|-Code:     ");
    printf("%.2x", icmp->code);
    printf("\n\t|-Checksum: ");
    printf("%.4x", ntohs(icmp->cksum));
    printf("\n\t|-Data:     ");

    switch (icmp->type) {
        case ICMPV6_ECHOREQUEST:
            print_icmp6_echo(buf, size);
            break;
        case ICMPV6_ECHOREPLY:
        default:
            hex_dump(buf + 4, size - 4);
    }
}

void print_icmp6_echo(const unsigned char *buf, int size) {
    struct icmp6hdr *icmp = (struct icmp6hdr *) buf;

    //calculate offset for data field
    buf += 8;
    size -= 8;

    printf("\n\t\t|-Identifier:          ");
    printf("%.1x", (icmp->dataun.un_data16[0]));
    printf("\n\t\t|-Sequence Number:     ");
    printf("%.1x", ntohs(icmp->dataun.un_data16[1]));
    printf("\n\t\t|-Data:                ");
    hex_dump(buf, size);
    printf("\n");
    write(STDOUT_FILENO, buf, size);
}

void hex_dump(const unsigned char *buf, int len) {
    printf("%.2X", buf[0]);
    for (int i = 1; i < len; i++) printf(":%.2X", buf[i]);
}

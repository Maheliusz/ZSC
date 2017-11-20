#pragma once
#include <byte_order.h>

#define IP6_ALEN	16				//octets in one IPv6 address
#define IP6_HLEN	40				//Total octets in header.
#define IP6_PREALEN	6				//octets preceding source address in a frame

#define __IP6HDR_OFFSETS "011211\0"
#define IP6HDR_OFFSET(i) (__IP6HDR_OFFSETS[i] - '0')
#define IP6HDR_FIELDC 6

#define IP6_NEXT_ICMP	1
#define IP6_NEXT_TCP	6
#define IP6_NEXT_UDP	17
#define IP6_NEXT_ICMPv6	58
#define IP6_NEXT_NONE	59

struct ipv6hdr {
	n_uint32_t		vtcfl;			//version, traffic class, flow label
	
	n_uint16_t		payload_len;
	unsigned char	nexthdr;
	unsigned char	hop_limit;
	
	unsigned char	saddr[IP6_ALEN];
	unsigned char	daddr[IP6_ALEN];
};

unsigned char	get_ip6_version(struct ipv6hdr);
unsigned char	get_ip6_tclass(struct ipv6hdr);
h_uint32_t		get_ip6_flow_lbl(struct ipv6hdr);

#define get_ip6_version(x)	((unsigned char) ((ntohl(x -> vtcfl) & 0xF0000000) >> 28))
#define get_ip6_tclass(x)	((unsigned char) ((ntohl(x -> vtcfl) & 0xFF00000) >> 20))
#define get_ip6_flow_lbl(x)	(ntohl(x -> vtcfl) & 0xFFFFF)

#pragma once
//#pragma pack(push, 1)
#include <byte_order.h>

#define ICMP6_HLEN			8

#define ICMP6_ECHOREQUEST	128
#define ICMP6_ECHOREPLY		129

struct icmp6hdr {
	unsigned char	type;
	unsigned char	code;
	n_uint16_t		cksum;
	
	union {
		n_uint32_t		un_data32[1];	/* type-specific field */
		n_uint16_t		un_data16[2];	/* type-specific field */
		unsigned char	un_data8[4];	/* type-specific field */
	} dataun;
}__attribute__((packed));

void print_icmp6_header(const struct icmp6hdr *icmp, int size);
void print_icmp6_echo(const struct icmp6hdr *icmp, int size);

//#pragma(pop)
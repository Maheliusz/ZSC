#pragma once
#include <byte_order.h>

#define UDP_HLEN 8

struct udphdr {
	n_uint16_t	uh_sport;		// source port
	n_uint16_t	uh_dport;		// destination port
	n_uint16_t	uh_ulen;		// packet length
	n_uint16_t	uh_sum;			// checksum
};

void print_udp_header(const struct udphdr *udp, int size);

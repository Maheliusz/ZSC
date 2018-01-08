#pragma once
#include <byte_order.h>

#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20

struct tcphdr {
	n_uint16_t		th_sport;		// source port
	n_uint16_t		th_dport;		// destination port
	n_uint32_t		th_seq;			// sequence number
	n_uint32_t		th_ack;			// acknowledgement number
	n_uint16_t		th_xof;			// data offset, (reserved), flags
	n_uint16_t		th_win;			// window
	n_uint16_t		th_sum;			// checksum
	n_uint16_t		th_urp;			// urgent pointer
};

#define get_tcp_offset(x)	((unsigned char) ((ntohs(x -> th_xof) & 0xF000) >> 12))
#define get_tcp_flags(x)	((unsigned char) (ntohs(x -> th_xof) & 0xFF))

void print_tcp_header(const struct tcphdr *tcp, int size);

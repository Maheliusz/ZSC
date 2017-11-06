#pragma once
#include <byte_order.h>

#define __IPHDR_OFFSETS "01122211244"
#define IPHDR_OFFSET(i) (__IPHDR_OFFSETS[i] - '0')
#define IPHDR_FIELDC 11

struct iphdr {
#if defined(__BYTE_ORDER__)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	unsigned char	ihl:4,
					version:4;
#else
	unsigned char	version:4,		//protocol version, should be 0100b (4)
					ihl:4;			//header length
#endif
#else
	#error "Your compiler doesn't recognize support __BYTE_ORDER__"
#endif
	
	unsigned char	tos;
	n_uint16_t		tot_len;
	n_uint16_t		id;
	n_uint16_t		frag_off;
	unsigned char	ttl;
	unsigned char	protocol;
	n_uint16_t		check;
	n_uint32_t		saddr;
	n_uint32_t		daddr;
	/*The options start here. */
};

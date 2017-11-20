#pragma once
#include <byte_order.h>

#define ICMPV6_ECHOREQUEST              128
#define ICMPV6_ECHOREPLY                129

struct icmp6hdr {
	unsigned char	type;
	unsigned char	code;
	n_uint16_t		cksum;
	
	union {
		n_uint32_t		un_data32[1];	/* type-specific field */
		n_uint16_t		un_data16[2];	/* type-specific field */
		unsigned char	un_data8[4];	/* type-specific field */
	} dataun;
};

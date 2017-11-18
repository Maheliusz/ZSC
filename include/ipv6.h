#pragma once

#define IP6_ALEN	16				//octets in one IPv6 address
#define IP6_PREALEN	6				//octets preceding source address in a frame

#define __IP6HDR_OFFSETS "011211"
#define IP6HDR_OFFSET(i) (__IP6HDR_OFFSETS[i] - '0')
#define IP6HDR_FIELDC 6

struct ipv6hdr {
#if defined(__BYTE_ORDER__)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	unsigned char	priority:4,
					version:4;
#else
	unsigned char	version:4,
					priority:4;
#endif
#else
	#error "Your compiler doesn't recognize support __BYTE_ORDER__"
#endif
	unsigned char	flow_lbl[3];
	
	n_uint16_t		payload_len;
	unsigned char	nexthdr;
	unsigned char	hop_limit;
	
	unsigned char	saddr[IP6_ALEN];
	unsigned char	daddr[IP6_ALEN];
};

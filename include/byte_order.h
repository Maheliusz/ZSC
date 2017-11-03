#pragma once
#include <stdint.h>

typedef uint16_t h_uint16_t;		//host byte order
typedef uint16_t n_uint16_t;		//network byte order

n_uint16_t htons(h_uint16_t n);
h_uint16_t ntohs(n_uint16_t n);

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	#define htons(n) n
	#define ntohs(n) n
#else
	#define htons(n) (((n & 0xFF) << 8) | ((n & 0xFF00) >> 8))
	#define ntohs(n) (((n & 0xFF) << 8) | ((n & 0xFF00) >> 8))
#endif

#pragma once
#include <stdint.h>

typedef uint16_t h_uint16_t;		//host byte order
typedef uint32_t h_uint32_t;
typedef uint16_t n_uint16_t;		//network byte order
typedef uint32_t n_uint32_t;

n_uint16_t htons(h_uint16_t n);
h_uint16_t ntohs(n_uint16_t n);

#if defined(__BYTE_ORDER__)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	#define htons(n) n
	#define ntohs(n) n
#else
	#define htons(n) (((n & 0xFF) << 8) | ((n & 0xFF00) >> 8))
	#define ntohs(n) (((n & 0xFF) << 8) | ((n & 0xFF00) >> 8))
#endif
#else
	#error "Your compiler doesn't recognize support __BYTE_ORDER__"
#endif

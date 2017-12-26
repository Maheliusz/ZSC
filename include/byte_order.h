#pragma once
#include <stdint.h>

typedef uint16_t h_uint16_t;		//host byte order
typedef uint32_t h_uint32_t;
typedef uint16_t n_uint16_t;		//network byte order
typedef uint32_t n_uint32_t;

n_uint16_t htons(uint16_t n);
h_uint16_t ntohs(uint16_t n);
n_uint32_t htonl(uint32_t n);
h_uint32_t ntohl(uint32_t n);

#if defined(__BYTE_ORDER__)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	#define htons(n) n
	#define ntohs(n) n
	#define htonl(n) n
	#define ntohl(n) n
	
#else
	#define htons(n) (((n & 0xFF) << 8) | ((n & 0xFF00) >> 8))
	#define ntohs(n) (((n & 0xFF) << 8) | ((n & 0xFF00) >> 8))
	#define htonl(n) (((n & 0xFF) << 24) | ((n & 0xFF00) << 8) | ((n & 0xFF0000) >> 8) | ((n & 0xFF000000) >> 24))
	#define ntohl(n) (((n & 0xFF) << 24) | ((n & 0xFF00) << 8) | ((n & 0xFF0000) >> 8) | ((n & 0xFF000000) >> 24))
#endif
#else
	#error "Your compiler doesn't support __BYTE_ORDER__"
#endif

#pragma once
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ethernet.h>
#include <ip.h>
#include <ipv6.h>
#include <icmpv6.h>
//#include <packet_formatter.h>
#include <udp.h>
#include <tcp.h>
#include <common.h>

void process_packet(unsigned char *buf, int size);
void process_ip_header(unsigned char *buf, int offset, int size);
void process_ip6_header(unsigned char *buf, int offset, int size);
void process_icmp6_header(unsigned char *buf, int ip_offset, int offset, int size, struct ipv6hdr *hdrv6);
void process_icmp6_echo_request(unsigned char *buf, int ip_offset, int offset, int size);
void process_icmp6_echo_reply(const unsigned char *buf, int ip_offset, int offset, int size);
void process_udp_header(unsigned char *buf, int ip_offset, int offset, int size, struct ipv6hdr* ip);
void reply_udp(unsigned char *buf, int ip_offset, int offset, int size);
void process_tcp_header(unsigned char *buf, int ip_offset, int offset, int size);

n_uint16_t chksum(n_uint16_t* buf, int len);
n_uint16_t pseudoheader_chksum(unsigned char *buf, unsigned char *ptr, struct ipv6hdr *ip6, int chksumlen);
n_uint16_t icmpv6_chksum(struct ipv6hdr *ip6, struct icmp6hdr *icmp, unsigned char *data, int len);
n_uint16_t udp_checksum(struct ipv6hdr *ip6, struct udphdr *udp, unsigned char *data);
void print_data(const unsigned char *buf, int offset, int size);
void byte_swap(unsigned char *c1, unsigned char *c2, int size);
unsigned char* inverse_bytes(unsigned char* buf, int size);

void SEND_PACKET();
#define SEND_PACKET() (fsend = 1);

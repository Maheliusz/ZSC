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
void process_udp_header(unsigned char *buf, int ip_offset, int offset, int size);
void process_tcp_header(unsigned char *buf, int ip_offset, int offset, int size);

n_uint16_t chksum(n_uint16_t* buf, int len);
n_uint16_t icmpv6_chksum(struct ipv6hdr *ip6, struct icmp6hdr *icmp);
void print_data(const unsigned char *buf, int offset, int size);
void byte_swap(unsigned char *c1, unsigned char *c2, int size);

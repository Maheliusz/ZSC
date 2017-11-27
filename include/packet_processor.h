#pragma once
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ethernet.h>
#include <ip.h>
#include <ipv6.h>
#include <icmpv6.h>
#include <packet_formatter.h>
#include <common.h>

void process_packet(unsigned char *buf, int size);
void process_ip_header(unsigned char *buf, int offset, int size);
void process_ip6_header(unsigned char *buf, int offset, int size);
void process_icmp6_header(unsigned char *buf, int ip_offset, int offset, int size);
void process_icmp6_echo_request(unsigned char *buf, int ip_offset, int offset, int size);
void process_icmp6_echo_reply(const unsigned char *buf, int ip_offset, int offset, int size);

n_uint16_t chksum(const unsigned char *buf, int size);
void byte_swap(unsigned char *c1, unsigned char *c2, int size);

#pragma once
#include <stdio.h>
#include <unistd.h>
#include <ethernet.h>
#include <ip.h>
#include <ipv6.h>
#include <icmpv6.h>

void process_packet(const unsigned char *buf, int size);
void process_ip_header(const unsigned char *buf, int offset, int size);
void process_ip6_header(const unsigned char *buf, int offset, int size);
void process_icmp6_header(const unsigned char *buf, int ip_offset, int offset, int size);
void process_icmp6_echo_request(const unsigned char *buf, int ip_offset, int offset, int size);
void process_icmp6_echo_reply(const unsigned char *buf, int ip_offset, int offset, int size);

void hex_dump(const unsigned char *buf, int len);

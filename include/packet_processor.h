#pragma once
#include <stdio.h>
#include <unistd.h>
#include <ethernet.h>
#include <ip.h>
#include <ipv6.h>
#include <icmpv6.h>

void print_packet(const unsigned char *buff, int size);

void dump_ip_header(const unsigned char *buf, int len);

void print_ethernet_header(const unsigned char *buf, int size);
void print_ip_header(const unsigned char *buf, int size);
void print_ip6_header(const unsigned char *buf, int size);
void print_icmp6_header(const unsigned char *buf, int size);

void print_icmp6_echo(const unsigned char *buf, int size);

void hex_dump(const unsigned char *buf, int len);

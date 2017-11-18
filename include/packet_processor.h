#pragma once
#include <stdio.h>
#include <ethernet.h>
#include <ip.h>
#include <ipv6.h>

void print_packet(const unsigned char *buff, int size);

void dump_ethernet_header(const unsigned char *buf);
void dump_ip_header(const unsigned char *buf, int len);
void dump_ip6_header(const unsigned char *buf, int len);

void print_ethernet_header(const struct ethhdr *eth);
void print_ip_header(const struct iphdr *ip);
void print_ip6_header(const struct iphdr *ip);

void hex_dump(const unsigned char *buf, int len);

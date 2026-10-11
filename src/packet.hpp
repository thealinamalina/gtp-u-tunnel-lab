#ifndef PACKET_HPP_
#define PACKET_HPP_

#include <cstddef>
#include <netinet/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>

bool parse_ethernet(const char* buffer, std::size_t length, struct ethhdr& header);
bool parse_ipv4(const char* buffer, std::size_t length, struct iphdr& header);
bool parse_arp(const char* buffer, std::size_t length, struct ether_arp& header);

#endif

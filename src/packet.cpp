#include "packet.hpp"
#include <cstring>
#include <arpa/inet.h>
#include <net/if_arp.h>

bool parse_ethernet(const char* buffer, std::size_t length, struct ethhdr& header) {
    if (length < sizeof(header)) {
        return false;
    }
    std::memcpy(&header, buffer, sizeof(header));
    return true;
}

bool parse_arp(const char* buffer, std::size_t length, struct ether_arp& header) {
    if (length < sizeof(header)) {
        return false;
    }
    std::memcpy(&header, buffer, sizeof(header));
    if (ntohs(header.ea_hdr.ar_hrd) == ARPHRD_ETHER && ntohs(header.ea_hdr.ar_pro) == ETH_P_IP &&
        header.ea_hdr.ar_hln == ETH_ALEN && header.ea_hdr.ar_pln == 4 && (ntohs(header.ea_hdr.ar_op) == ARPOP_REQUEST ||
        ntohs(header.ea_hdr.ar_op) == ARPOP_REPLY)) {
        return true;
    }
    return false;
}

bool parse_ipv4(const char* buffer, std::size_t length, struct iphdr& header) {
    if (length < sizeof(header)) {
        return false;
    }
    std::memcpy(&header, buffer, sizeof(header));
    if (header.version == 4 && header.ihl >= 5 && header.ihl * 4 <= length && 
        ntohs(header.tot_len) >= header.ihl * 4 && ntohs(header.tot_len) <= length) {
        return true;
    }
    return false;
}

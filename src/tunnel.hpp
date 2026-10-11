#ifndef TUNNEL_HPP_
#define TUNNEL_HPP_

#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdint>

struct Ue {
    struct in_addr ipv4_addr;
    std::uint32_t uplink_teid;
    std::uint32_t downlink_teid;
};

const Ue* find_ue_by_ip(const struct in_addr& ip4);
const Ue* find_ue_by_ul_teid(std::uint32_t ul_teid);
bool init_ue_table();

#endif

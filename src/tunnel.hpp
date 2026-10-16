#ifndef TUNNEL_HPP_
#define TUNNEL_HPP_

#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdint>
#include <array>

struct Ue {
    struct in_addr ipv4_addr;
    std::uint32_t uplink_teid;
    std::uint32_t downlink_teid;
};

class TunnelTable {
public:
    TunnelTable();
    const Ue* find_ue_by_ip(const struct in_addr& ip4) const;
    const Ue* find_ue_by_ul_teid(std::uint32_t ul_teid) const;

private:
    std::array<Ue, 4> ues_;
};

#endif

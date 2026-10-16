#include <arpa/inet.h>
#include <net/if_arp.h>
#include <cstring>

#include "arp.hpp"

bool build_arp_reply(const struct ethhdr& ethernet, const struct ether_arp& arp,
                    const unsigned char* upf_mac, char* buffer, std::size_t buffer_capacity, std::size_t& reply_length) {
    if (ntohs(arp.ea_hdr.ar_op) != ARPOP_REQUEST) {
        return false;
    }
    struct ethhdr reply_eth{};
    std::memcpy(reply_eth.h_dest, ethernet.h_source, ETH_ALEN);
    std::memcpy(reply_eth.h_source, upf_mac, ETH_ALEN);
    reply_eth.h_proto = htons(ETH_P_ARP);

    struct ether_arp reply_arp{};
    reply_arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    reply_arp.ea_hdr.ar_pro = htons(ETH_P_IP);
    reply_arp.ea_hdr.ar_hln = ETH_ALEN;
    reply_arp.ea_hdr.ar_pln = 4;
    reply_arp.ea_hdr.ar_op = htons(ARPOP_REPLY);
    std::memcpy(reply_arp.arp_sha, upf_mac, ETH_ALEN);
    std::memcpy(reply_arp.arp_spa, arp.arp_tpa, 4);
    std::memcpy(reply_arp.arp_tha, arp.arp_sha, ETH_ALEN);
    std::memcpy(reply_arp.arp_tpa, arp.arp_spa, 4);
    if (buffer_capacity < sizeof(reply_eth) + sizeof(reply_arp)) {
        return false;
    }
    std::memcpy(buffer, &reply_eth, sizeof(reply_eth));
    std::memcpy(buffer + sizeof(reply_eth), &reply_arp, sizeof(reply_arp));
    reply_length = sizeof(reply_eth) + sizeof(reply_arp);
    return true;
}

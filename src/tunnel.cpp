#include <stdexcept>

#include "tunnel.hpp"

TunnelTable::TunnelTable() {
    if (inet_pton(AF_INET, "192.168.7.1", &ues_[0].ipv4_addr) != 1 || 
        inet_pton(AF_INET, "192.168.7.2", &ues_[1].ipv4_addr) != 1 ||
        inet_pton(AF_INET, "192.168.7.3", &ues_[2].ipv4_addr) != 1 ||
        inet_pton(AF_INET, "192.168.7.4", &ues_[3].ipv4_addr) != 1) {
        throw std::runtime_error("Error: inet_pton() error.");
        
    }
    for (std::size_t i = 0; i < ues_.size(); i++) {
        ues_[i].downlink_teid = (i + 1) * 2;
        ues_[i].uplink_teid = (i + 1) * 2 + 1;
    }
}

const Ue* TunnelTable::find_ue_by_ip(const struct in_addr& ip4) const {
    for (const auto& ue : ues_) {
        if (ue.ipv4_addr.s_addr == ip4.s_addr) {
            return &ue;
        }
    }
    return nullptr;
}

const Ue* TunnelTable::find_ue_by_ul_teid(std::uint32_t ul_teid) const {
    for (const auto& ue : ues_) {
        if (ue.uplink_teid == ul_teid) {
            return &ue;
        }
    }
    return nullptr;
}

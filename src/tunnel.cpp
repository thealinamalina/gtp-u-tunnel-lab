#include <iostream>
#include <cstring>

#include "tunnel.hpp"

Ue table_ue[4];

bool init_ue_table() {
    if (inet_pton(AF_INET, "192.168.7.1", &table_ue[0].ipv4_addr) != 1 || 
        inet_pton(AF_INET, "192.168.7.2", &table_ue[1].ipv4_addr) != 1 ||
        inet_pton(AF_INET, "192.168.7.3", &table_ue[2].ipv4_addr) != 1 ||
        inet_pton(AF_INET, "192.168.7.4", &table_ue[3].ipv4_addr) != 1) {
        std::cerr << "Error: inet_pton() error." << std::endl;
        return false;
    }
    for (int i = 0; i < 4; i++) {
        table_ue[i].downlink_teid = (i + 1) * 2;
        table_ue[i].uplink_teid = (i + 1) * 2 + 1;
    }
    return true;
}

const Ue* find_ue_by_ip(const struct in_addr& ip4) {
    for (int i = 0; i < 4; i++) {
        if (table_ue[i].ipv4_addr.s_addr == ip4.s_addr) {
            return &table_ue[i];
        }
    }
    return nullptr;
}

const Ue* find_ue_by_ul_teid(std::uint32_t ul_teid) {
    for (int i = 0; i < 4; i++) {
        if (table_ue[i].uplink_teid == ul_teid) {
            return &table_ue[i];
        }
    }
    return nullptr;
}

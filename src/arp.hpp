#ifndef ARP_HPP_
#define ARP_HPP_

#include <cstddef>
#include <netinet/if_ether.h>
#include <linux/if_ether.h>


bool build_arp_reply(const struct ethhdr& ethernet, const struct ether_arp& arp,
                    const char* upf_mac, char* buffer, std::size_t buffer_capacity, std::size_t& reply_length);

#endif

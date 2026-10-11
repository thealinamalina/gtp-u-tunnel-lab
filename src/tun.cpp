#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <cstring>
#include <sys/ioctl.h>
#include <cerrno>
#include <netinet/ip.h>
#include <sys/epoll.h>

#include "packet.hpp"
#include "tunnel.hpp"
#include "gtp.hpp"
#include "arp.hpp"

int main()
{
    char upf_mac[6];
    char receive_buf[2048];
    char reply_buf[42];
    char gtp_buf[2048];
    char uplink_buf[2048];
    char uplink_frame[2048];
    char ip_destination[INET_ADDRSTRLEN];
    struct ethhdr eth_header;
    struct iphdr ipv4_header;
    std::memset(&ipv4_header, 0, sizeof(ipv4_header));
    struct ether_arp arp_header;
    std::memset(&arp_header, 0, sizeof(arp_header));
    
    const char *cn_interface_name = "upf_cn_veth";
    int cn_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (cn_socket < 0)
    {
        std::cerr << "Error: Socket creating failed - " << strerror(errno) << "." << std::endl;
        return 1;
    }
    unsigned int cn_idx = if_nametoindex(cn_interface_name);
    if (cn_idx == 0)
    {
        std::cerr << "Error: Interface not found - " << strerror(errno) << "." << std::endl;
        close(cn_socket);
        return 1;
    }

    const char *an_interface_name = "upf_an_veth";
    int an_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (an_socket < 0)
    {
        std::cerr << "Error: Socket creating failed - " << strerror(errno) << "." << std::endl;
        close(cn_socket);
        return 1;
    }
    unsigned int an_idx = if_nametoindex(an_interface_name);
    if (an_idx == 0)
    {
        std::cerr << "Error: Interface not found - " << strerror(errno) << "." << std::endl;
        close(an_socket);
        close(cn_socket);
        return 1;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, cn_interface_name, IFNAMSIZ - 1); 
    if (ioctl(cn_socket, SIOCGIFHWADDR, &ifr) < 0) { 
        std::cerr << "Error: ioctl() error - " << strerror(errno) << "." << std::endl; 
        close(an_socket);
        close(cn_socket); 
        return 1; 
    } 
    std::memcpy(upf_mac, ifr.ifr_hwaddr.sa_data, sizeof(upf_mac));
    struct sockaddr_ll cn_socket_addr;
    std::memset(&cn_socket_addr, 0, sizeof(struct sockaddr_ll));
    cn_socket_addr.sll_family = AF_PACKET;
    cn_socket_addr.sll_protocol = htons(ETH_P_ALL);
    cn_socket_addr.sll_ifindex = cn_idx;

    struct sockaddr_in an_socket_addr;
    std::memset(&an_socket_addr, 0, sizeof(struct sockaddr_in));
    an_socket_addr.sin_family = AF_INET;
    an_socket_addr.sin_port = htons(2152);
    if (inet_pton(AF_INET, "192.168.9.1", &an_socket_addr.sin_addr) != 1) {
        std::cerr << "Error: Invalid IPv4 address." << std::endl;
        close(an_socket);
        close(cn_socket);
        return 1;
    }
    struct sockaddr_in gnb_addr;
    std::memset(&gnb_addr, 0, sizeof(gnb_addr));
    gnb_addr.sin_family = AF_INET;
    gnb_addr.sin_port = htons(2152);
    if (inet_pton(AF_INET, "192.168.9.2", &gnb_addr.sin_addr) != 1) {
        std::cerr << "Error: Invalid IPv4 address." << std::endl;
        close(an_socket);
        close(cn_socket);
        return 1;
    }

    struct sockaddr_in sender_addr;
    std::memset(&sender_addr, 0, sizeof(sender_addr));
    socklen_t sender_length = sizeof(sender_addr);

    if (bind(cn_socket, (sockaddr *)&cn_socket_addr, sizeof(cn_socket_addr)) < 0)
    {
        std::cerr << "Error: Binding error - " << strerror(errno) << "." << std::endl;
        close(an_socket);
        close(cn_socket);
        return 1;
    }

    if (bind(an_socket, (sockaddr *)&an_socket_addr, sizeof(an_socket_addr)) < 0)
    {
        std::cerr << "Error: Binding error - " << strerror(errno) << "." << std::endl;
        close(an_socket);
        close(cn_socket);
        return 1;
    }

    if (!init_ue_table()) {
        close(cn_socket);
        close(an_socket);
        return 1;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        std::cerr << "Error: epoll_create1() error - " << strerror(errno) << "." << std::endl;
        close(an_socket);
        close(cn_socket);
        return 1;
    }

    struct epoll_event cn_event;
    std::memset(&cn_event, 0, sizeof(cn_event)); 
    cn_event.events = EPOLLIN;
    cn_event.data.fd = cn_socket;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cn_socket, &cn_event) < 0) {
        std::cerr << "Error: epoll_ctl() error - " << strerror(errno) << "." << std::endl;
        close(an_socket);
        close(cn_socket);
        close(epoll_fd);
        return 1;
    }

    struct epoll_event an_event;
    std::memset(&an_event, 0, sizeof(an_event)); 
    an_event.events = EPOLLIN;
    an_event.data.fd = an_socket;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, an_socket, &an_event) < 0) {
        std::cerr << "Error: epoll_ctl() error - " << strerror(errno) << "." << std::endl;
        close(an_socket);
        close(cn_socket);
        close(epoll_fd);
        return 1;
    }

    while (true)
    {
        struct epoll_event events[2];
        int ready = epoll_wait(epoll_fd, events, 2, -1);

        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "Error: epoll_wait() error - " << strerror(errno) << "." << std::endl;
            close(epoll_fd);
            close(an_socket);
            close(cn_socket);
            return 1;
        }

        for (int i = 0; i < ready; i++) {
            if (events[i].data.fd == cn_socket) {
                ssize_t bytes_read = recv(cn_socket, receive_buf, sizeof(receive_buf), 0);
                if (bytes_read < 0) 
                {
                    std::cerr << "Error: recv() error - " << strerror(errno) << "." << std::endl;
                    close(an_socket);
                    close(cn_socket);
                    close(epoll_fd);
                    return 1;
                }
                else if (!parse_ethernet(receive_buf, static_cast<std::size_t>(bytes_read), eth_header)) {
                    continue;
                } 

                if (ntohs(eth_header.h_proto) == ETH_P_ARP)
                {
                    if (!parse_arp(receive_buf + sizeof(eth_header), 
                        static_cast<std::size_t>(bytes_read) - sizeof(eth_header), arp_header)) {
                        continue;
                    } 
                    std::size_t reply_length;
                    if (!build_arp_reply(
                            eth_header,
                            arp_header,
                            upf_mac,
                            reply_buf,
                            sizeof(reply_buf),
                            reply_length)) {
                        continue;
                    }
                    struct sockaddr_ll dn; 
                    std::memset(&dn, 0, sizeof(struct sockaddr_ll)); 
                    dn.sll_family = AF_PACKET; 
                    dn.sll_ifindex = cn_idx; 
                    dn.sll_halen = ETH_ALEN; 
                    dn.sll_protocol = htons(ETH_P_ARP);
                    std::memcpy(dn.sll_addr, eth_header.h_source, ETH_ALEN); 
                    ssize_t sent = sendto( 
                        cn_socket, 
                        reply_buf, 
                        reply_length, 
                        0, 
                        reinterpret_cast<const sockaddr*>(&dn), 
                        sizeof(dn)); 
                    if (sent < 0) 
                    { 
                        std::cerr << "Error: sendto() error - " << strerror(errno) << "." << std::endl; 
                        close(an_socket);
                        close(cn_socket);
                        close(epoll_fd);
                        return 1; 
                    } 
                    else 
                    { 
                        inet_ntop(AF_INET, arp_header.arp_tpa, ip_destination, sizeof(ip_destination));
                        std::cout << "ARP reply: " << ip_destination << "." << std::endl;
                        std::cout << "Send: " << sent << " bytes." << std::endl;
                    }

                } else if (ntohs(eth_header.h_proto) == ETH_P_IP) {
                    if (!parse_ipv4(receive_buf + sizeof(eth_header), 
                        static_cast<std::size_t>(bytes_read) - sizeof(eth_header), ipv4_header)) {
                        continue;
                    }
                    inet_ntop(AF_INET, &ipv4_header.daddr, ip_destination, sizeof(ip_destination));
                    struct in_addr destination;
                    destination.s_addr = ipv4_header.daddr;

                    const Ue* ue = find_ue_by_ip(destination);
                    if (ue == nullptr) {
                        continue;
                    }
                    Gtpu_view gtp;
                    gtp.teid = ue->downlink_teid;
                    gtp.payload = receive_buf + sizeof(eth_header);
                    gtp.payload_length = ntohs(ipv4_header.tot_len);
                    std::size_t gtp_length;
                    if (!build_gtpu(gtp, gtp_buf, sizeof(gtp_buf), gtp_length)) {
                        continue;
                    }
                    ssize_t sent = sendto( 
                        an_socket, 
                        gtp_buf, 
                        gtp_length, 
                        0, 
                        reinterpret_cast<const sockaddr*>(&gnb_addr), 
                        sizeof(gnb_addr)); 
                    if (sent < 0) 
                    { 
                        std::cerr << "Error: sendto() error - " << strerror(errno) << "." << std::endl; 
                        close(an_socket);
                        close(cn_socket); 
                        close(epoll_fd);
                        return 1; 
                    } 
                    else 
                    { 
                        std::cout << "Downlink GTP-U: " << ip_destination << "." << std::endl; 
                        std::cout << "TEID: " << gtp.teid << "." << std::endl; 
                        std::cout << "Send: " << sent << " bytes." << std::endl; 
                    }
                } else {
                    continue;
                }
            } else if (events[i].data.fd == an_socket) {
                sender_length = sizeof(sender_addr);
                ssize_t bytes_read = recvfrom(an_socket, uplink_buf, sizeof(uplink_buf), 0, 
                                                reinterpret_cast<sockaddr*>(&sender_addr), &sender_length);
                if (bytes_read < 0) 
                {
                    std::cerr << "Error: recvfrom() error - " << strerror(errno) << "." << std::endl;
                    close(an_socket);
                    close(cn_socket);
                    close(epoll_fd);
                    return 1;
                }
                if (sender_addr.sin_addr.s_addr != gnb_addr.sin_addr.s_addr ||
                    sender_addr.sin_port != htons(2152)) {
                    continue;
                }
                Gtpu_view gtp;
                if (!parse_gtpu(uplink_buf, static_cast<std::size_t>(bytes_read), gtp)) {
                    continue;
                }
                const Ue* ue = find_ue_by_ul_teid(gtp.teid);
                if (ue == nullptr) {
                    continue;
                }
                struct iphdr uplink_ip;
                if (!parse_ipv4(gtp.payload, gtp.payload_length, uplink_ip)) {
                    continue;
                }
                if (uplink_ip.saddr != ue->ipv4_addr.s_addr || ntohs(uplink_ip.tot_len) != gtp.payload_length) {
                    continue;
                }
                struct ethhdr uplink_eth;
                std::memset(&uplink_eth, 0, sizeof(uplink_eth));
                for (int i = 0; i < 6; i++) {
                    uplink_eth.h_dest[i] = 0xff;
                }
                uplink_eth.h_proto = htons(ETH_P_IP);
                std::memcpy(uplink_eth.h_source, upf_mac, ETH_ALEN);
                if (sizeof(uplink_eth) + gtp.payload_length > sizeof(uplink_frame)) {
                    continue;
                }
                std::memcpy(uplink_frame, &uplink_eth, sizeof(uplink_eth));
                std::memcpy(uplink_frame + sizeof(uplink_eth), gtp.payload, gtp.payload_length);
                struct sockaddr_ll dn; 
                std::memset(&dn, 0, sizeof(struct sockaddr_ll)); 
                dn.sll_family = AF_PACKET; 
                dn.sll_ifindex = cn_idx; 
                dn.sll_halen = ETH_ALEN; 
                dn.sll_protocol = htons(ETH_P_IP);
                std::memcpy(dn.sll_addr, uplink_eth.h_dest, ETH_ALEN); 
                ssize_t sent = sendto( 
                    cn_socket, 
                    uplink_frame, 
                    sizeof(uplink_eth) + gtp.payload_length, 
                    0, 
                    reinterpret_cast<const sockaddr*>(&dn), 
                    sizeof(dn)); 
                if (sent < 0) 
                { 
                    std::cerr << "Error: sendto() error - " << strerror(errno) << "." << std::endl; 
                    close(an_socket);
                    close(cn_socket);
                    close(epoll_fd);
                    return 1; 
                } 
                else 
                { 
                    inet_ntop(AF_INET, &uplink_ip.saddr, ip_destination, sizeof(ip_destination));
                    std::cout << "Uplink GTP-U: " << ip_destination << "." << std::endl; 
                    std::cout << "TEID: " << gtp.teid << "." << std::endl; 
                    std::cout << "Send: " << sent << " bytes." << std::endl; 
                }
            }
        }
        
    }
    
    close(an_socket);
    close(cn_socket);
    close(epoll_fd);
    return 0;
}

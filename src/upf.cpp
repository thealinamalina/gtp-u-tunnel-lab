#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <cstring>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <iostream>
#include <cerrno>
#include <arpa/inet.h>

#include "upf.hpp"
#include "tunnel.hpp"
#include "gtp.hpp"
#include "packet.hpp"
#include "arp.hpp"

constexpr std::size_t reply_size = sizeof(ethhdr) + sizeof(ether_arp);

Upf::Upf() : cn_socket_(-1), an_socket_(-1), epoll_fd_(-1), cn_idx_(0), upf_mac_{}, gnb_address_{} {}
Upf::~Upf() {
    if (cn_socket_ != -1) {
        close(cn_socket_);
    } 
    if (an_socket_ != -1) {
        close(an_socket_);
    } 
    if (epoll_fd_ != -1) {
        close(epoll_fd_);
    } 
}

bool Upf::setup_cn_socket() {
    const char *cn_interface_name = "upf_cn_veth";
    cn_socket_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (cn_socket_ < 0)
    {
        std::cerr << "Error: Socket creating failed - " << strerror(errno) << "." << std::endl;
        return false;
    }
    cn_idx_ = if_nametoindex(cn_interface_name);
    if (cn_idx_ == 0)
    {
        std::cerr << "Error: Interface not found - " << strerror(errno) << "." << std::endl;
        return false;
    }
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, cn_interface_name, IFNAMSIZ - 1); 
    if (ioctl(cn_socket_, SIOCGIFHWADDR, &ifr) < 0) { 
        std::cerr << "Error: ioctl() error - " << strerror(errno) << "." << std::endl; 
        return false; 
    } 
    std::memcpy(upf_mac_.data(), ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    struct sockaddr_ll cn_socket_addr{};
    cn_socket_addr.sll_family = AF_PACKET;
    cn_socket_addr.sll_protocol = htons(ETH_P_ALL);
    cn_socket_addr.sll_ifindex = cn_idx_;
    if (bind(cn_socket_, (sockaddr *)&cn_socket_addr, sizeof(cn_socket_addr)) < 0)
    {
        std::cerr << "Error: Binding error - " << strerror(errno) << "." << std::endl;
        return false;
    }
    return true;
}

bool Upf::setup_an_socket() {
    an_socket_ = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (an_socket_ < 0)
    {
        std::cerr << "Error: Socket creating failed - " << strerror(errno) << "." << std::endl;
        return false;
    }
    struct sockaddr_in an_socket_addr{};
    an_socket_addr.sin_family = AF_INET;
    an_socket_addr.sin_port = htons(2152);
    if (inet_pton(AF_INET, "192.168.9.1", &an_socket_addr.sin_addr) != 1) {
        std::cerr << "Error: Invalid IPv4 address." << std::endl;
        return false;
    }
    gnb_address_.sin_family = AF_INET;
    gnb_address_.sin_port = htons(2152);
    if (inet_pton(AF_INET, "192.168.9.2", &gnb_address_.sin_addr) != 1) {
        std::cerr << "Error: Invalid IPv4 address." << std::endl;
        return false;
    }
    if (bind(an_socket_, (sockaddr *)&an_socket_addr, sizeof(an_socket_addr)) < 0)
    {
        std::cerr << "Error: Binding error - " << strerror(errno) << "." << std::endl;
        return false;
    }
    return true;
}
bool Upf::setup_epoll() {
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ < 0) {
        std::cerr << "Error: epoll_create1() error - " << strerror(errno) << "." << std::endl;
        return false;
    }
    struct epoll_event cn_event{};
    cn_event.events = EPOLLIN;
    cn_event.data.fd = cn_socket_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, cn_socket_, &cn_event) < 0) {
        std::cerr << "Error: epoll_ctl() error - " << strerror(errno) << "." << std::endl;
        return false;
    }

    struct epoll_event an_event{};
    an_event.events = EPOLLIN;
    an_event.data.fd = an_socket_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, an_socket_, &an_event) < 0) {
        std::cerr << "Error: epoll_ctl() error - " << strerror(errno) << "." << std::endl;
        return false;
    }
    return true;
}

bool Upf::upf_init()
{
    if (!setup_cn_socket()) {
        return false;
    }
    if (!setup_an_socket()) {
        return false;
    }
    if (!setup_epoll()) {
        return false;
    }
    return true;
}

int Upf::upf_run() {
     while (true)
    {
        struct epoll_event events[2];
        int ready = epoll_wait(epoll_fd_, events, 2, -1);

        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "Error: epoll_wait() error - " << strerror(errno) << "." << std::endl;
            return 1;
        }
        for (int i = 0; i < ready; i++) {
            if (events[i].data.fd == cn_socket_) { 
                cn_handler();
            } else if (events[i].data.fd == an_socket_) {
                an_handler();
            }
        }
    }
}

void Upf::cn_handler() {
    char buffer[65536];
    char gtp_buf[2048];
    char ip_destination[INET_ADDRSTRLEN];
    struct ethhdr eth_header{};
    struct ether_arp arp_header{};
    struct iphdr ipv4_header{};
    ssize_t bytes_read = recv(cn_socket_, buffer, sizeof(buffer), 0);
    if (bytes_read < 0) 
    {
        std::cerr << "Error: recv() error - " << strerror(errno) << "." << std::endl;
        return;
    }
    else if (!parse_ethernet(buffer, static_cast<std::size_t>(bytes_read), eth_header)) {
        return;
    } 
    if (ntohs(eth_header.h_proto) == ETH_P_ARP)
    {
        if (!parse_arp(buffer + sizeof(eth_header), 
            static_cast<std::size_t>(bytes_read) - sizeof(eth_header), arp_header)) {
            return;
        } 
        std::size_t reply_length;
        std::array<char, reply_size> reply_buf{};
        struct in_addr target;
        std::memcpy(&target.s_addr, arp_header.arp_tpa, sizeof(target.s_addr));
        if (tunnels_.find_ue_by_ip(target) == nullptr) {
            return;
        }
        if (!build_arp_reply(
                eth_header,
                arp_header,
                upf_mac_.data(),
                reply_buf.data(),
                reply_buf.size(),
                reply_length)) {
            return;
        }
        struct sockaddr_ll dn{}; 
        dn.sll_family = AF_PACKET; 
        dn.sll_ifindex = cn_idx_; 
        dn.sll_halen = ETH_ALEN; 
        dn.sll_protocol = htons(ETH_P_ARP);
        std::memcpy(dn.sll_addr, eth_header.h_source, ETH_ALEN);
        ssize_t sent = sendto( 
            cn_socket_, 
            reply_buf.data(), 
            reply_length, 
            0, 
            reinterpret_cast<const sockaddr*>(&dn), 
            sizeof(dn)); 
        if (sent < 0) 
        { 
            std::cerr << "Error: sendto() error - " << strerror(errno) << "." << std::endl; 
            return; 
        } 
        else 
        { 
            inet_ntop(AF_INET, arp_header.arp_tpa, ip_destination, sizeof(ip_destination));
            std::cout << "ARP reply: " << ip_destination << "." << std::endl;
            std::cout << "Send: " << sent << " bytes." << std::endl;
        }

    } else if (ntohs(eth_header.h_proto) == ETH_P_IP) {
        if (!parse_ipv4(buffer + sizeof(eth_header), 
            static_cast<std::size_t>(bytes_read) - sizeof(eth_header), ipv4_header)) {
            return;
        }
        inet_ntop(AF_INET, &ipv4_header.daddr, ip_destination, sizeof(ip_destination));
        struct in_addr destination{};
        destination.s_addr = ipv4_header.daddr;

        const Ue* ue = tunnels_.find_ue_by_ip(destination);
        if (ue == nullptr) {
            return;
        }
        Gtpu_view gtp{};
        gtp.teid = ue->downlink_teid;
        gtp.payload = buffer + sizeof(eth_header);
        gtp.payload_length = ntohs(ipv4_header.tot_len);
        std::size_t gtp_length;
        if (!build_gtpu(gtp, gtp_buf, sizeof(gtp_buf), gtp_length)) {
            return;
        }
        ssize_t sent = sendto( 
            an_socket_, 
            gtp_buf, 
            gtp_length, 
            0, 
            reinterpret_cast<const sockaddr*>(&gnb_address_), 
            sizeof(gnb_address_)); 
        if (sent < 0) 
        { 
            std::cerr << "Error: sendto() error - " << strerror(errno) << "." << std::endl; 
            return; 
        } 
        else 
        { 
            std::cout << "Downlink GTP-U: " << ip_destination << "." << std::endl; 
            std::cout << "TEID: " << gtp.teid << "." << std::endl; 
            std::cout << "Send: " << sent << " bytes." << std::endl; 
        }
    } else {
        return;
    }
}
void Upf::an_handler() {
    char uplink_buf[2048];
    char uplink_frame[2048];
    char ip_destination[INET_ADDRSTRLEN];
    struct sockaddr_in sender_addr{};
    socklen_t sender_length = sizeof(sender_addr);
    ssize_t bytes_read = recvfrom(an_socket_, uplink_buf, sizeof(uplink_buf), 0, 
                                    reinterpret_cast<sockaddr*>(&sender_addr), &sender_length);
    if (bytes_read < 0) 
    {
        std::cerr << "Error: recvfrom() error - " << strerror(errno) << "." << std::endl;
        return;
    }
    if (sender_addr.sin_addr.s_addr != gnb_address_.sin_addr.s_addr ||
        sender_addr.sin_port != gnb_address_.sin_port) {
        return;
    }
    Gtpu_view gtp{};
    if (!parse_gtpu(uplink_buf, static_cast<std::size_t>(bytes_read), gtp)) {
        return;
    }
    const Ue* ue = tunnels_.find_ue_by_ul_teid(gtp.teid);
    if (ue == nullptr) {
        return;
    }
    struct iphdr uplink_ip{};
    if (!parse_ipv4(gtp.payload, gtp.payload_length, uplink_ip)) {
        return;
    }
    if (uplink_ip.saddr != ue->ipv4_addr.s_addr || ntohs(uplink_ip.tot_len) != gtp.payload_length) {
        return;
    }
    struct ethhdr uplink_eth{};
    for (int i = 0; i < ETH_ALEN; i++) {
        uplink_eth.h_dest[i] = 0xff;
    }
    uplink_eth.h_proto = htons(ETH_P_IP);
    std::memcpy(uplink_eth.h_source, upf_mac_.data(), ETH_ALEN);
    if (sizeof(uplink_eth) + gtp.payload_length > sizeof(uplink_frame)) {
        return;
    }
    std::memcpy(uplink_frame, &uplink_eth, sizeof(uplink_eth));
    std::memcpy(uplink_frame + sizeof(uplink_eth), gtp.payload, gtp.payload_length);
    struct sockaddr_ll dn{}; 
    dn.sll_family = AF_PACKET; 
    dn.sll_ifindex = cn_idx_; 
    dn.sll_halen = ETH_ALEN; 
    dn.sll_protocol = htons(ETH_P_IP);
    std::memcpy(dn.sll_addr, uplink_eth.h_dest, ETH_ALEN); 
    ssize_t sent = sendto( 
        cn_socket_, 
        uplink_frame, 
        sizeof(uplink_eth) + gtp.payload_length, 
        0, 
        reinterpret_cast<const sockaddr*>(&dn), 
        sizeof(dn)); 
    if (sent < 0) 
    { 
        std::cerr << "Error: sendto() error - " << strerror(errno) << "." << std::endl; 
        return; 
    } 
    else 
    { 
        inet_ntop(AF_INET, &uplink_ip.saddr, ip_destination, sizeof(ip_destination));
        std::cout << "Uplink GTP-U: " << ip_destination << "." << std::endl; 
        std::cout << "TEID: " << gtp.teid << "." << std::endl; 
        std::cout << "Send: " << sent << " bytes." << std::endl; 
    }
}

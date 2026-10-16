#ifndef UPF_HPP_
#define UPF_HPP_

#include <array>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "tunnel.hpp"

class Upf {
public:
    Upf();
    ~Upf();

    bool upf_init();
    int upf_run();

private:
    int cn_socket_;
    int an_socket_;
    int epoll_fd_;
    unsigned int cn_idx_;
    std::array<unsigned char, ETH_ALEN> upf_mac_;
    sockaddr_in gnb_address_;
    TunnelTable tunnels_;

    bool setup_cn_socket();
    bool setup_an_socket();
    bool setup_epoll();
    void cn_handler();
    void an_handler();
};

#endif

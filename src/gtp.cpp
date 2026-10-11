#include <cstring>
#include <netinet/in.h>
#include "gtp.hpp"


bool parse_gtpu(const char* buffer, std::size_t length, Gtpu_view& gtp) {
    Gtpu_header header;
    if (buffer == nullptr || length < sizeof(Gtpu_header)) {
        return false;
    }
    std::memcpy(&header, buffer, sizeof(Gtpu_header));
    if (header.flags != 0x30 || header.message_type != 0xff || ntohs(header.length) != length - sizeof(Gtpu_header)) {
        return false;
    }
    gtp.teid = ntohl(header.teid);
    gtp.payload_length = length - sizeof(Gtpu_header);
    gtp.payload = &buffer[sizeof(Gtpu_header)];
    return true;
}

bool build_gtpu(const Gtpu_view& gtp, char* buffer, std::size_t buffer_capacity, std::size_t& length) {
    if ((gtp.payload_length > 0 && gtp.payload == nullptr) || buffer == nullptr || 
        buffer_capacity < sizeof(Gtpu_header) + gtp.payload_length || gtp.payload_length > 65535) {
        return false;
    }
    Gtpu_header header;
    header.teid = htonl(gtp.teid);
    header.length = htons(gtp.payload_length);
    header.flags = 0x30;
    header.message_type = 0xff;
    std::memcpy(buffer, &header, sizeof(header));
    if (gtp.payload_length > 0) {
        std::memcpy(buffer + sizeof(Gtpu_header), gtp.payload, gtp.payload_length);
    }
    length = sizeof(Gtpu_header) + gtp.payload_length;
    return true;
}

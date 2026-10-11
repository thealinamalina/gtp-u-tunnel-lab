#ifndef GTP_HPP_
#define GTP_HPP_

#include <cstdint>
#include <cstddef>

#pragma pack(push, 1)
struct Gtpu_header
{
    std::uint8_t flags;
    std::uint8_t message_type;
    std::uint16_t length;
    std::uint32_t teid;
};
#pragma pack(pop)

struct Gtpu_view
{
    std::uint32_t teid;
    const char* payload;
    std::size_t payload_length;
};

bool build_gtpu(const Gtpu_view& gtp, char* buffer, std::size_t buffer_capacity, std::size_t& length);
bool parse_gtpu(const char* buffer, std::size_t length, Gtpu_view& gtp);

#endif

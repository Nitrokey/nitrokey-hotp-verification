#include <cstdint>
#include <iostream>
#include "catch.hpp"

extern "C" {
    #include "../src/ccid.h"
    #include "../src/tlv.h"
}

TLV data[] = {
        {
                .tag = 0x71,
                .length = 6,
                .type = 'S',
                .v_str = "123456"
        },
        {
                .tag = 0x71,
                .length = 6,
                .type = 'S',
                .v_str = "789012"
        },
};

TEST_CASE("test tlv", "[Helper]") {
    uint8_t buf[1024] = {};
    process_all(buf, data, sizeof data / sizeof data[0]);
    print_buffer(buf, 64, "tlv res buffer");
    REQUIRE(buf[0] == data[0].tag);
    REQUIRE(buf[1] == data[0].length);
    REQUIRE(buf[2+data[0].length] == data[1].tag);
    REQUIRE(buf[2+data[0].length+1] == data[1].length);
    std::cout << buf;
}

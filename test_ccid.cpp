#include "catch.hpp"
#include <cstdint>
#include <iostream>

extern "C" {
#include "../src/ccid.h"
#include "../src/tlv.h"
#include "src/operations_ccid.h"
#include "src/return_codes.h"
}

TLV data[] = {
        {.tag = 0x71,
         .length = 6,
         .type = 'S',
         .v_str = "123456"},
        {.tag = 0x71,
         .length = 6,
         .type = 'S',
         .v_str = "789012"},
};


TEST_CASE("test ccid status", "[main]") {
    struct Device dev = {};
    bool res = device_connect(&dev);
    REQUIRE(res);
    int counter;
    uint16_t firmware_version;
    int res2 = status_ccid(dev.mp_devhandle_ccid, &counter, &firmware_version);
    if (res2 == RET_SUCCESS) {
        REQUIRE((0 <= counter && counter <= 8));
    } else if (res2 == RET_NO_PIN_ATTEMPTS) {
        REQUIRE(counter == -1);
    }
    //    CHECK(firmware_version == 0x040a);
    CHECK((firmware_version != 0 && firmware_version != 0xFFFF));
}

TEST_CASE("test tlv", "[Helper]") {
    uint8_t buf[1024] = {};
    process_all(buf, data, sizeof data / sizeof data[0]);
    print_buffer(buf, 64, "tlv res buffer");
    REQUIRE(buf[0] == data[0].tag);
    REQUIRE(buf[1] == data[0].length);
    REQUIRE(buf[2 + data[0].length] == data[1].tag);
    REQUIRE(buf[2 + data[0].length + 1] == data[1].length);
    std::cout << buf;
}

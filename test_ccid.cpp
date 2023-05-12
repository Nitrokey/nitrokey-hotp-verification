#include "catch.hpp"
#include <cstdint>
#include <iostream>

extern "C" {
#include "../src/ccid.h"
#include "../src/tlv.h"
#include "src/operations_ccid.h"
#include "src/return_codes.h"
}

// Multple TLV entities
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

// Encode tag length longer, than the actual data
TLV data_invalid[] = {
        {.tag = 0x71,
         .length = 80,
         .type = 'S',
         .v_str = "123456"},

};

// Single TLV entity
TLV data_valid[] = {
        {.tag = 0x71,
         .length = 6,
         .type = 'S',
         .v_str = "123456"},

};

TEST_CASE("test ccid status", "[main]") {
    struct Device dev = {};
    bool res = device_connect(&dev);
    REQUIRE(res);
    int counter;
    uint16_t firmware_version;
    uint32_t serial;
    int status_res = status_ccid(dev.mp_devhandle_ccid, &counter, &firmware_version, &serial);
    if (status_res == RET_SUCCESS) {
        REQUIRE((0 <= counter && counter <= 8));
    } else if (status_res == RET_NO_PIN_ATTEMPTS) {
        REQUIRE(counter == -1);
    }
    REQUIRE((firmware_version != 0 && firmware_version != 0xFFFF));
    INFO("Current serial number " << serial);
    // SN is unsupported currently by the Secrets App
    // CHECK((serial != 0 && serial != 0xFFFFFFFF));
    CHECK((serial == 0));
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

TEST_CASE("test tlv invalid", "[Helper]") {
    uint8_t buf[8] = {};
    process_all(buf, data_invalid, sizeof data_invalid / sizeof data_invalid[0]);
    TLV tlv = {};
    int r = get_tlv(buf, sizeof buf, 0x71, &tlv);
    REQUIRE(r == RET_COMM_ERROR);
}

TEST_CASE("test tlv valid", "[Helper]") {
    uint8_t buf[8] = {};
    process_all(buf, data_valid, sizeof data_valid / sizeof data_valid[0]);
    TLV tlv = {};
    int r = get_tlv(buf, sizeof buf, 0x71, &tlv);
    REQUIRE(r == RET_SUCCESS);
}

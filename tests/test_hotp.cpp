/*
 * Copyright (c) 2023 Nitrokey GmbH
 *
 * This file is part of Nitrokey HOTP verification project.
 *
 * Nitrokey HOTP verification is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * Nitrokey HOTP verification is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Nitrokey HOTP verification. If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0
 */

#include "catch.hpp"

extern "C" {
#include "../src/device.h"
#include "../src/operations.h"
#include "../src/operations_ccid.h"
#include "../src/settings.h"
}

const char *base32_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const char *admin_PIN = "12345678";
const char *RFC_HOTP_codes[] = {
        "755224",//0
        "287082",
        "359152",
        "969429",//3
        "338314",
        "254676",
        "287922",//6
        "162583",
        "399871",
        "520489",//9
        "403154",//10
        "481090",//11
};

struct Device dev;


TEST_CASE("Test correct codes", "[HOTP]") {
    int res;
    res = device_connect(&dev);
    REQUIRE(res == true);
    res = set_secret_on_device(&dev, base32_secret, admin_PIN, 0);
    REQUIRE(res == RET_NO_ERROR);
    for (auto c: RFC_HOTP_codes) {
        res = check_code_on_device(&dev, c);
        REQUIRE(res == RET_VALIDATION_PASSED);
    }
    device_disconnect(&dev);
}


TEST_CASE("Test correct codes set with initial counter value", "[HOTP]") {
    int res;
    res = device_connect(&dev);
    REQUIRE(res == true);
    int code = 0;
    for (auto c: RFC_HOTP_codes) {
        INFO("Setting slot with counter value " << code);
        res = set_secret_on_device(&dev, base32_secret, admin_PIN, code++);
        REQUIRE(res == RET_NO_ERROR);
        INFO("Expecting secret " << c << " for " << code);
        res = check_code_on_device(&dev, c);
        REQUIRE(res == RET_VALIDATION_PASSED);
    }
    device_disconnect(&dev);
}

TEST_CASE("Test incorrect codes", "[HOTP]") {
    int res;
    res = device_connect(&dev);
    REQUIRE(res == true);
    res = set_secret_on_device(&dev, base32_secret, admin_PIN, 0);
    REQUIRE(res == RET_NO_ERROR);

    for (int i = 0; i < 10; i++) {
        res = check_code_on_device(&dev, "123456");
        REQUIRE(res == RET_VALIDATION_FAILED);
    }

    device_disconnect(&dev);
}


TEST_CASE("Test codes with offset 2", "[HOTP]") {
    int res;
    res = device_connect(&dev);
    REQUIRE(res == true);
    res = set_secret_on_device(&dev, base32_secret, admin_PIN, 0);
    REQUIRE(res == RET_NO_ERROR);

    int i = 0;
    for (auto c: RFC_HOTP_codes) {
        if (i++ % 2 == 0) continue;
        res = check_code_on_device(&dev, c);
        REQUIRE(res == RET_VALIDATION_PASSED);
    }

    device_disconnect(&dev);
}

TEST_CASE("Test code with maximum offsets", "[HOTP]") {
    int res;
    res = device_connect(&dev);
    REQUIRE(res == true);
    res = set_secret_on_device(&dev, base32_secret, admin_PIN, 0);
    REQUIRE(res == RET_NO_ERROR);


    res = check_code_on_device(&dev, RFC_HOTP_codes[11]);
    REQUIRE(res == RET_VALIDATION_FAILED);
    res = check_code_on_device(&dev, RFC_HOTP_codes[10]);
    REQUIRE(res == RET_VALIDATION_FAILED);

    res = check_code_on_device(&dev, RFC_HOTP_codes[9]);
    REQUIRE(res == RET_VALIDATION_PASSED);
    res = check_code_on_device(&dev, RFC_HOTP_codes[11]);
    REQUIRE(res == RET_VALIDATION_PASSED);


    res = device_disconnect(&dev);
    REQUIRE(res == RET_NO_ERROR);
}


TEST_CASE("Try to set the HOTP secret with wrong PIN and test PIN counters", "[HOTP]") {
    int res;
    res = device_connect(&dev);
    REQUIRE(res == true);

#ifdef CCID_AUTHENTICATE
    SECTION("actual test") {
        const int MAX_PIN_ATTEMPT_COUNTER =
                (dev.connection_type == CONNECTION_HID)
                        ? MAX_PIN_ATTEMPT_COUNTER_HID
                        : MAX_PIN_ATTEMPT_COUNTER_CCID;

        struct ResponseStatus status = device_get_status(&dev);
        REQUIRE(status.retry_admin >= MAX_PIN_ATTEMPT_COUNTER - 1);

        res = set_secret_on_device(&dev, base32_secret, admin_PIN, 0);
        REQUIRE(res == RET_NO_ERROR);
        status = device_get_status(&dev);
        REQUIRE(status.retry_admin == MAX_PIN_ATTEMPT_COUNTER);
        REQUIRE(check_code_on_device(&dev, RFC_HOTP_codes[0]) == RET_VALIDATION_PASSED);

        // The slot should not be overwritten with the wrong_PIN, and it should not accept the previous HOTP code.
        // This test requires that the PIN is not needed for getting the OTP code accepted.
        // Fails otherwise.
        res = set_secret_on_device(&dev, base32_secret, "wrong_PIN", 0);
        REQUIRE(res == dev_wrong_password);
        status = device_get_status(&dev);
        REQUIRE(status.retry_admin == MAX_PIN_ATTEMPT_COUNTER - 1);
        REQUIRE(check_code_on_device(&dev, RFC_HOTP_codes[0]) == RET_VALIDATION_FAILED);

        res = set_secret_on_device(&dev, base32_secret, admin_PIN, 0);
        REQUIRE(res == RET_NO_ERROR);
        status = device_get_status(&dev);
        REQUIRE(status.retry_admin == MAX_PIN_ATTEMPT_COUNTER);

        for (auto c: RFC_HOTP_codes) {
            res = check_code_on_device(&dev, c);
            REQUIRE(res == RET_VALIDATION_PASSED);
        }
    }
#endif

    res = device_disconnect(&dev);
    REQUIRE(res == RET_NO_ERROR);
}

TEST_CASE("Try to set the HOTP secret without PIN", "[HOTP]") {
    int res;
    res = device_connect(&dev);
    REQUIRE(res == true);

    if (dev.connection_type != CONNECTION_CCID) {
        return;
    }

    SECTION("actual test") {
        struct ResponseStatus status = {};
        res = device_get_status(&dev, &status);
        REQUIRE(res == RET_NO_ERROR);
        const char *PIN_status_str = status.retry_admin == 0xFF ? "unset" : "set";
        INFO("Current PIN status: " << PIN_status_str);

        res = set_secret_on_device(&dev, base32_secret, "", 0);
        REQUIRE(res == RET_NO_ERROR);

        for (auto c: RFC_HOTP_codes) {
            res = check_code_on_device(&dev, c);
            REQUIRE(res == RET_VALIDATION_PASSED);
        }
    }

    res = device_disconnect(&dev);
    REQUIRE(res == RET_NO_ERROR);
}


TEST_CASE("Verify base32 string", "[Helper]") {
    std::string invalid_base32 = "111";
    std::string valid_base32 = "AAAAA";
    REQUIRE_FALSE(verify_base32(invalid_base32.c_str(), invalid_base32.length()));
    REQUIRE(verify_base32(valid_base32.c_str(), valid_base32.length()));
}

TEST_CASE("Verify base32 string with a padding character", "[Helper]") {
    std::string valid_base32 = "NZUXI4TPNNSXSCQ=";
    REQUIRE(verify_base32(valid_base32.c_str(), valid_base32.length()));
}

#include "../src/base32.h"
#include <cstring>
TEST_CASE("Verify base32 string of secret containing null byte", "[Helper]") {
    //  https://github.com/Nitrokey/nitrokey-hotp-verification/issues/6
    std::string secret_base32 = "JVOKTGWL6TWLRQBKUEEUYVGRJZQBM2EH";
    REQUIRE(verify_base32(secret_base32.c_str(), secret_base32.length()));
    const int secret_size_bytes = 20;
    const size_t base32_string_length_limit = BASE32_LEN(secret_size_bytes);
    const size_t OTP_secret_base32_length = strnlen(secret_base32.c_str(), base32_string_length_limit);
    const bool base32_valid = secret_base32.c_str() != nullptr && OTP_secret_base32_length > 0 && OTP_secret_base32_length <= base32_string_length_limit && verify_base32(secret_base32.c_str(), OTP_secret_base32_length);
    REQUIRE(base32_valid);
}

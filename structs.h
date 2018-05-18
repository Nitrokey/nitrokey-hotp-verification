/*
 * Copyright (c) 2018 Nitrokey UG
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
 * along with Nitrokey App. If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0
 */

#ifndef NITROKEY_HOTP_VERIFICATION_STRUCTS_H
#define NITROKEY_HOTP_VERIFICATION_STRUCTS_H

#ifndef _MSC_VER
#define __packed __attribute__((__packed__))
#else
#define __packed
#endif

#include <stdint.h>
#include <stdbool.h>

#define HID_REPORT_SIZE (65)
static const size_t HID_REPORT_SIZE_CONST = HID_REPORT_SIZE;

#pragma pack (push,1)

struct DeviceQuery {
  union {
    struct {
      uint8_t _zero;
      uint8_t command_id;
      uint8_t payload[HID_REPORT_SIZE - 6];
      uint32_t crc;
    };
    uint8_t as_data[HID_REPORT_SIZE];
  };
} __packed;


enum DeviceResponseConstants_e {
    //magic numbers from firmware
    storage_status_absolute_address = 21,
    storage_data_absolute_address = storage_status_absolute_address + 5,
    header_size = 8, //from _zero to last_command_status inclusive
    footer_size = 4, //crc
    wrapping_size = header_size + footer_size,
    storage_status_padding_size = storage_status_absolute_address - header_size
};

struct DeviceResponse_st {
  uint8_t _zero;
  uint8_t device_status;
  uint8_t command_id;  // originally last_command_type
  uint32_t last_command_crc;
  uint8_t last_command_status;

  union {
    uint8_t payload[HID_REPORT_SIZE - wrapping_size];
    struct {
      uint8_t _storage_status_padding[storage_status_padding_size];
      uint8_t command_counter;
      uint8_t command_id;
      uint8_t device_status; //@see stick20::device_status
      uint8_t progress_bar_value;
    } __packed storage_status;
  } __packed;
  uint32_t crc;
};

struct DeviceResponse {
  union{
    struct DeviceResponse_st response_st;
    uint8_t as_data[HID_REPORT_SIZE];
  };
};

//------------------------------------

struct ResponseStatus{
  union {
    uint16_t firmware_version;
    struct {
      uint8_t minor;
      uint8_t major;
    } firmware_version_st;
  };
  union{
    uint8_t card_serial[4];
    uint32_t card_serial_u32;
  } __packed;
  union {
    uint8_t general_config[5];
    struct{
      uint8_t numlock;     /** 0-1: HOTP slot number from which the code will be get on double press, other value - function disabled */
      uint8_t capslock;    /** same as numlock */
      uint8_t scrolllock;  /** same as numlock */
      uint8_t enable_user_password;
      uint8_t delete_user_password; /* unused */
    } __packed;
  } __packed;
  uint8_t retry_admin; /*not present in the firmware response for the Status command in v0.8 firmware*/
  uint8_t retry_user; /*not present in the firmware response for the Status command in v0.8 firmware*/
};


struct WriteToOTPSlot {
//admin auth
  uint8_t temporary_admin_password[25];
  uint8_t slot_number;
  union {
    uint64_t slot_counter_or_interval;
    uint8_t slot_counter_s[8];
  } __packed;
  union {
    uint8_t _slot_config;
    struct {
      bool use_8_digits   : 1;
      bool use_enter      : 1;
      bool use_tokenID    : 1;
    };
  };
  union {
    uint8_t slot_token_id[13]; /** OATH Token Identifier */
    struct { /** @see https://openauthentication.org/token-specs/ */
      uint8_t omp[2];
      uint8_t tt[2];
      uint8_t mui[8];
      uint8_t keyboard_layout; //disabled feature in nitroapp as of 20160805
    } slot_token_fields;
  };
};

struct FirstAuthenticate {
  uint8_t card_password[25];
  uint8_t temporary_password[25];
};

struct UserAuthenticate {
  uint8_t card_password[25];
  uint8_t temporary_password[25];
};

struct SendOTPData {
//admin auth
  uint8_t temporary_admin_password[25];
  uint8_t type; //S-secret, N-name
  uint8_t id; //multiple reports for values longer than 30 bytes
  uint8_t data[30]; //data, does not need null termination
};

struct GetHOTP {
  uint8_t slot_number;
  struct {
    uint64_t challenge; //@unused
    uint64_t last_totp_time; //@unused
    uint8_t last_interval; //@unused
  } __packed _unused;
  uint8_t temporary_user_password[25];
};

struct GetHOTP_response {
  union {
    uint8_t whole_response[18]; //14 bytes reserved for config, but used only 1
    struct {
      uint32_t code;
      union {
        uint8_t _slot_config;
        struct {
          bool use_8_digits   : 1;
          bool use_enter      : 1;
          bool use_tokenID    : 1;
        };
      };
    } __packed;
  } __packed;
};

typedef struct {
  uint32_t otp_code_to_verify;
} __packed cmd_query_verify_code;

#pragma pack (pop)
#endif //NITROKEY_HOTP_VERIFICATION_STRUCTS_H


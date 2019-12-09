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

#include <assert.h>
#include <string.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include "operations.h"
#include "device.h"
#include "base32.h"
#include "structs.h"
#include "command_id.h"
#include "random_data.h"
#include "dev_commands.h"
#include "min.h"
#include "settings.h"

static const int HOTP_SLOT_NUMBER = 3;

static char *const HOTP_SLOT_NAME = "Validation";

uint8_t get_internal_slot_number_for_hotp(uint8_t slot_number) { return (uint8_t) (0x10 + slot_number); }

bool verify_base32(const char* string, size_t len){
  for (size_t i=0; i<len; i++){
    const char c = string[i];
    const bool in_valid_range = (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7');
    if (!in_valid_range) return false;
  }
  return true;
}

int set_secret_on_device(struct Device *dev, const char *OTP_secret_base32, const char *admin_PIN, const uint64_t hotp_counter) {
  int res;
  //Make sure secret is parsable
#define secret_size_bytes (20)
  const size_t base32_string_length_limit = BASE32_LEN(secret_size_bytes);
  const size_t OTP_secret_base32_length = strnlen(OTP_secret_base32, base32_string_length_limit);
  if (!(OTP_secret_base32 != nullptr && OTP_secret_base32_length > 0
                                     && OTP_secret_base32_length <= base32_string_length_limit
                                     && verify_base32(OTP_secret_base32, OTP_secret_base32_length) )){
    printf("ERR: Too long or badly formatted base32 string. It should be not longer than %lu characters.\n", base32_string_length_limit);
    return RET_BADLY_FORMATTED_BASE32_STRING;
  }

  //Decode base32 to binary
  uint8_t binary_secret_buf[secret_size_bytes] = {0}; //handling 20 bytes -> 160 bits
  const size_t decoded_length = base32_decode((const unsigned char *) OTP_secret_base32, binary_secret_buf);
  assert(decoded_length <= secret_size_bytes);

  //Write binary secret to the Device's HOTP#3 slot
  //But authenticate first
  res = authenticate_admin(dev, admin_PIN, dev->admin_temporary_password);
  if (res != RET_NO_ERROR) {return res;}

  //going on with Pro v0.8 write protocol
  //send OTP data
  struct SendOTPData otpData = {0};
  memcpy(otpData.temporary_admin_password, dev->admin_temporary_password,
         min(sizeof(otpData.temporary_admin_password), sizeof(dev->admin_temporary_password)));
  otpData.type = 'S';
  otpData.id = 0;
  memcpy(otpData.data, binary_secret_buf, min(sizeof(otpData.data), min(sizeof(binary_secret_buf), min(20, decoded_length)) ));
  res = device_send(dev, (uint8_t *) &otpData, sizeof(otpData), SEND_OTP_DATA);
  if (res != RET_NO_ERROR) return res;
  res = device_receive_buf(dev);
  if (res != RET_NO_ERROR) return res;
  if ((res = dev->packet_response.response_st.last_command_status) != 0) {return res;}

  struct SendOTPData otpData_name = {0};
  memcpy(otpData_name.temporary_admin_password, dev->admin_temporary_password,
         min(sizeof(otpData_name.temporary_admin_password), sizeof(dev->admin_temporary_password)));
  otpData_name.type = 'N';
  otpData_name.id = 0;
  memcpy(otpData_name.data, HOTP_SLOT_NAME, strnlen(HOTP_SLOT_NAME, sizeof(otpData_name.data)));
  res = device_send(dev, (uint8_t *) &otpData_name, sizeof(otpData_name), SEND_OTP_DATA);
  if (res != RET_NO_ERROR) return res;
  res = device_receive_buf(dev);
  if (res != RET_NO_ERROR) return res;
  if ((res = dev->packet_response.response_st.last_command_status) != 0) {return res;}

  //execute write OTP on device
  struct WriteToOTPSlot writeToOTPSlot = {0};
  writeToOTPSlot.slot_number = get_internal_slot_number_for_hotp(HOTP_SLOT_NUMBER);
  writeToOTPSlot.slot_counter_or_interval = hotp_counter;
  writeToOTPSlot.use_8_digits = HOTP_CODE_USE_8_DIGITS;
  memcpy(writeToOTPSlot.temporary_admin_password, dev->admin_temporary_password,
         min(sizeof(writeToOTPSlot.temporary_admin_password), sizeof(dev->admin_temporary_password)));

  res = device_send(dev, (uint8_t *) &writeToOTPSlot, sizeof(writeToOTPSlot), WRITE_TO_SLOT);
  if (res != RET_NO_ERROR) return res;
  res = device_receive_buf(dev);
  if (res != RET_NO_ERROR) return res;

  if ((res = dev->packet_response.response_st.last_command_status) != 0) {return res;}

  return RET_NO_ERROR;
}

#define MAX_NUMBERS_DIGITS (30)
/**
 * Safe strtol - with copying and terminating string before conversion
 * @param string string to convert to number
 * @return converted number
 */
long strtol10_s(const char *string){
  char buf[MAX_NUMBERS_DIGITS+1] = {};
  strncpy(buf, string, sizeof(buf)-1);
  return strtol(buf, NULL, 10);
}

bool validate_number(const char* buf){
  const size_t len = strnlen(buf, MAX_NUMBERS_DIGITS);
  for(size_t i=0; i < len; i++){
    const bool in_range = '0' <= buf[i] && buf[i] <= '9';
    if (!in_range) return false;
  }
  return true;
}

int check_code_on_device(struct Device *dev, const char *HOTP_code_to_verify) {
  int res;
  cmd_query_verify_code verify_code = {};
  if (!validate_number(HOTP_code_to_verify)) return RET_BADLY_FORMATTED_HOTP_CODE;
  const long conversion_results = strtol10_s(HOTP_code_to_verify);
  if (conversion_results < HOTP_MIN_INT || conversion_results >= HOTP_MAX_INT) return RET_BADLY_FORMATTED_HOTP_CODE;
  verify_code.otp_code_to_verify = (uint32_t) conversion_results;

  res = device_send(dev, (uint8_t *) &verify_code, sizeof(verify_code), VERIFY_OTP_CODE);
  if (res != RET_NO_ERROR) return res;
  res = device_receive_buf(dev);
  if (res != RET_NO_ERROR) return res;
  if ((res = dev->packet_response.response_st.last_command_status) != 0) {return res;}

#ifdef _DEBUG
  printf("\nDevice responded: %s\n",
         dev->packet_response.response_st.payload[0] ? "HOTP code correct!" : "HOTP code incorrect!");
#endif

#ifdef _DEBUG
  const uint8_t HOTP_counters_difference = dev->packet_response.response_st.payload[1];
  if (HOTP_counters_difference != 0){
    printf("\nCounters differs by %d\n", HOTP_counters_difference);
  }
#endif
  
  return dev->packet_response.response_st.payload[0] ? RET_VALIDATION_PASSED : RET_VALIDATION_FAILED;
}

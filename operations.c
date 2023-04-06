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

#include "operations.h"
#include "base32.h"
#include "command_id.h"
#include "dev_commands.h"
#include "device.h"
#include "min.h"
#include "random_data.h"
#include "settings.h"
#include "structs.h"
#include "operations_ccid.h"
#include "utils.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>

static const int HOTP_SLOT_NUMBER = 3;

static char *const HOTP_SLOT_NAME = SLOT_NAME;

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
  const size_t base32_string_length_limit = BASE32_LEN(HOTP_SECRET_SIZE_BYTES);
  const size_t OTP_secret_base32_length = strnlen(OTP_secret_base32, base32_string_length_limit);
  if (!(OTP_secret_base32 != nullptr && OTP_secret_base32_length > 0
                                     && OTP_secret_base32_length <= base32_string_length_limit
                                     && verify_base32(OTP_secret_base32, OTP_secret_base32_length) )){
    printf("ERR: Too long or badly formatted base32 string. It should be not longer than %lu characters.\n", base32_string_length_limit);
    return RET_BADLY_FORMATTED_BASE32_STRING;
  }

    if (dev->connection_type == CONNECTION_CCID){
        set_pin_ccid(dev, admin_PIN);
        check_ret(authenticate_ccid(dev->mp_devhandle_ccid, admin_PIN), RET_WRONG_PIN);
        return set_secret_on_device_ccid(dev->mp_devhandle_ccid, OTP_secret_base32, hotp_counter);
    }


    //Decode base32 to binary
  uint8_t binary_secret_buf[HOTP_SECRET_SIZE_BYTES] = {0}; //handling 40 bytes -> 320 bits
  const size_t decoded_length = base32_decode((const unsigned char *) OTP_secret_base32, binary_secret_buf);
  assert(decoded_length <= HOTP_SECRET_SIZE_BYTES);

    assert(dev->connection_type == CONNECTION_HID);
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

int check_code_on_device_ccid(struct Device *dev, uint32_t HOTP_code_to_verify){
    assert(dev->connection_type == CONNECTION_CCID);
    int res = verify_code_ccid(dev->mp_devhandle_ccid, HOTP_code_to_verify);

#ifdef FEATURE_CCID_ASK_FOR_PIN_ON_ERROR
    if (res == RET_SLOT_NOT_CONFIGURED){
        // Slot is not configured or requires PIN to proceed.
        // Ask for PIN, authenticate and try again

        res = RET_WRONG_PIN;
        while (res == RET_WRONG_PIN){

            char input_admin_PIN[MAX_PIN_SIZE_CCID] = {};
            printf("Please provide PIN to continue: ");
            fflush(stdout);
            size_t r = read(0, input_admin_PIN, sizeof input_admin_PIN);
            input_admin_PIN[r-1] = 0; // remove the final \n character
            printf("\n");

            res = authenticate_ccid(dev->mp_devhandle_ccid, input_admin_PIN);
        }
        return verify_code_ccid(dev->mp_devhandle_ccid, HOTP_code_to_verify);
    }
#endif

    return res;
}

int check_code_on_device(struct Device *dev, const char *HOTP_code_to_verify) {
  int res;
  cmd_query_verify_code verify_code = {};
  if (!validate_number(HOTP_code_to_verify)) return RET_BADLY_FORMATTED_HOTP_CODE;
  const long conversion_results = strtol10_s(HOTP_code_to_verify);
  if (conversion_results < HOTP_MIN_INT || conversion_results >= HOTP_MAX_INT) return RET_BADLY_FORMATTED_HOTP_CODE;

    if (dev->connection_type == CONNECTION_CCID){
        return check_code_on_device_ccid(dev, conversion_results);
    }

    assert(dev->connection_type == CONNECTION_HID);
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

int regenerate_AES_key_Pro(struct Device *dev, char *const admin_password){
  if (dev->dev_info.name_short != 'P' && dev->dev_info.name_short != 'L') {
    return RET_UNKNOWN_DEVICE;
  }

  int res;
    //  Nitrokey Pro / Librem Key
    struct cmd_createNewKeys_Pro data_pro = {}  ;
    memmove(data_pro.admin_password, admin_password,
            strnlen(admin_password, sizeof(data_pro.admin_password)));
    res = device_send(dev, (uint8_t *)&data_pro, sizeof(data_pro), NEW_AES_KEY);

  if (res != RET_NO_ERROR)
    return res;
  res = device_receive_buf(dev);
  if (res != RET_NO_ERROR)
    return res;
  if ((res = dev->packet_response.response_st.last_command_status) != 0) {
    return res;
  }
  uint8_t status = dev->packet_response.response_st.device_status;
  usleep(1 * 1000 * 1000);
  uint16_t errors_cnt = 20;
  while (status == 1) {
    usleep(1 * 1000 * 1000);
    fprintf(stderr, "."); fflush(stderr);
    res = device_receive_buf(dev);
    if (res != RET_NO_ERROR) {
      errors_cnt--;
      printf("error: %d\n", errors_cnt);
    }
    if (errors_cnt==0){
      return res;
    }
    status = dev->packet_response.response_st.device_status;
  }
  res = status;
  if (res != 0) {
    return RET_COMM_ERROR;
  }
  printf("Please reconnect your device\n");
  return RET_NO_ERROR;
}

int regenerate_AES_key_Storage(struct Device *dev, char *const admin_password) {
  int res;

  //  Nitrokey Storage
  struct cmd_createNewKeys_Storage data = {};
  data.kind = 'A';
  memmove(data.admin_password, admin_password,
          strnlen(admin_password, sizeof(data.admin_password)));
  res = device_send(dev, (uint8_t *)&data, sizeof(data), GENERATE_NEW_KEYS);

  if (res != RET_NO_ERROR)
    return res;
  res = device_receive_buf(dev);
  if (res != RET_NO_ERROR)
    return res;
  if ((res = dev->packet_response.response_st.last_command_status) != 0) {
    return res;
  }
  uint8_t status = dev->packet_response.response_st.storage_status.device_status;
  while (status == NK_STORAGE_BUSY) {
    usleep(100 * 1000);
    fprintf(stderr, "."); fflush(stderr);
    res = device_receive_buf(dev);
    if (res != RET_NO_ERROR)
      return res;
    status = dev->packet_response.response_st.storage_status.device_status;
  }
  res = status;
  if (!(res == 0 || res == 1)) {
    return RET_COMM_ERROR;
  }
  return RET_NO_ERROR;
}

int regenerate_AES_key(struct Device *dev, char *const admin_password) {
  switch (dev->dev_info.name_short) {
  case 'S': {
    return regenerate_AES_key_Storage(dev, admin_password);
  } break;
  case 'L':
  case 'P': {
    return regenerate_AES_key_Pro(dev, admin_password);
  } break;
  default:
    return RET_UNKNOWN_DEVICE;
    break;
  }
}

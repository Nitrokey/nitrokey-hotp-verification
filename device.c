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
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "device.h"
#include "crc32.h"
#include "structs.h"
#include "command_id.h"
#include "min.h"
#include "return_codes.h"

const unsigned short m_vid = 0x20a0;
const unsigned short m_pid = 0x4108;

static const int CONNECTION_ATTEMPTS_COUNT = 80;

static const int CONNECTION_ATTEMPT_DELAY_MICRO_SECONDS = 1000*1000/2;

int device_receive(struct Device *dev, uint8_t *out_data, size_t out_buffer_size) {
  const int receive_attempts = 10;
  int i;
  int receive_status = 0;
  for (i = 0; i < receive_attempts; ++i) {
#ifdef _DEBUG
    fprintf(stderr, "."); fflush(stderr);
#endif
    usleep(100*1000);

    receive_status = (hid_get_feature_report(dev->mp_devhandle, dev->packet_response.as_data, HID_REPORT_SIZE_CONST));
    if (receive_status != (int)HID_REPORT_SIZE_CONST) continue;
    bool valid_response_crc = stm_crc32(dev->packet_response.as_data+1, HID_REPORT_SIZE_CONST - 5) == dev->packet_response.response_st.crc;
    bool valid_query_crc = dev->packet_query.crc == dev->packet_response.response_st.last_command_crc;
    if (valid_response_crc && valid_query_crc && dev->packet_response.response_st.device_status == 0){
      break;
    }
  }
  if (i >= receive_attempts-1){
    printf("WARN %s:%d: could not receive the data from the device.\n", __FILE__, __LINE__);
    return RET_CONNECTION_LOST;
  }

  if (out_data != nullptr){
    assert(out_buffer_size != 0);
    memcpy(out_data, dev->packet_query.as_data+1, min(out_buffer_size, HID_REPORT_SIZE_CONST-1));
    if (out_buffer_size > HID_REPORT_SIZE_CONST-1){
      printf("WARN %s:%d: incoming data bigger than provided output buffer.\n", __FILE__, __LINE__);
    }
  } else {
    //exit on wrong function parameters
    assert(out_buffer_size == 0);
  }

  return RET_NO_ERROR;
}

int device_send(struct Device *dev, uint8_t *in_data, size_t data_size, uint8_t command_ID) {
  _device_clear_buffers(dev);

  dev->packet_query.command_id = command_ID;

  if (in_data != nullptr){
    assert(data_size != 0);
    memcpy(dev->packet_query.payload, in_data, min(data_size, sizeof(dev->packet_query.payload)));
    if (data_size > HID_REPORT_SIZE_CONST-1){
      printf("WARN %s:%d: input data bigger than buffer.\n", __FILE__, __LINE__);
    }
  } else {
    //exit on wrong function parameters
    assert(data_size == 0);
  }

  dev->packet_query.crc = stm_crc32(dev->packet_query.as_data+1, HID_REPORT_SIZE_CONST - 5);
  int send_status = hid_send_feature_report(dev->mp_devhandle, dev->packet_query.as_data, HID_REPORT_SIZE_CONST);

  if (send_status != (int)HID_REPORT_SIZE_CONST){
    printf("WARN %s:%d: could not send the data to the device.\n", __FILE__, __LINE__);
    return RET_CONNECTION_LOST;
  }

  return RET_NO_ERROR;
}


int device_connect(struct Device *dev, char *key_brand) {
  bool res;

  if (dev->mp_devhandle != nullptr)
    return 1;

  dev->mp_devhandle = hid_open(m_vid, m_pid, nullptr);
  res = dev->mp_devhandle != nullptr;

  if (!res){
    fprintf(stderr, "Trying to connect to %s: ", key_brand);
    for (int i=0; i < CONNECTION_ATTEMPTS_COUNT; i++){
      dev->mp_devhandle = hid_open(m_vid, m_pid, nullptr);
      res = dev->mp_devhandle != nullptr;
      usleep(CONNECTION_ATTEMPT_DELAY_MICRO_SECONDS);
      if (res == true) break;
      fprintf(stderr, "."); fflush(stderr);
    }
    fprintf(stderr, "\n"); fflush(stderr);
  }

  return res;
}

int device_disconnect(struct Device *dev) {
  if (dev->mp_devhandle == nullptr) return 1;
  hid_close(dev->mp_devhandle);
  dev->mp_devhandle = nullptr;
  _device_clear_buffers(dev);
  hid_exit();
  return RET_NO_ERROR;
}

void _device_clear_buffers(struct Device *dev) {
  static_assert(sizeof(dev->packet_query.as_data) == HID_REPORT_SIZE, "Data size is not equal HID report size!");
  memset(dev->packet_query.as_data, 0, sizeof(dev->packet_query.as_data));
  memset(dev->packet_response.as_data, 0, sizeof(dev->packet_response.as_data));
  memset(dev->user_temporary_password, 0, sizeof(dev->user_temporary_password));
  memset(dev->admin_temporary_password, 0, sizeof(dev->admin_temporary_password));
}

int device_send_buf(struct Device *dev, uint8_t command_ID) {
  return device_send(dev, nullptr, 0, command_ID);
}

int device_receive_buf(struct Device *dev) {
  return device_receive(dev, nullptr, 0);
}

struct ResponseStatus device_get_status(struct Device *dev){
  //getting smartcards counters takes additional 100ms
  //could be skipped initially and shown only on failed attempt to make that faster
  device_send_buf(dev, GET_PASSWORD_RETRY_COUNT);
  device_receive_buf(dev);
  const uint8_t retry_admin = dev->packet_response.response_st.payload[0];
  device_send_buf(dev, GET_USER_PASSWORD_RETRY_COUNT);
  device_receive_buf(dev);
  const uint8_t retry_user = dev->packet_response.response_st.payload[0];

  device_send_buf(dev, GET_STATUS);
  device_receive_buf(dev);
  struct ResponseStatus* status = (struct ResponseStatus*) dev->packet_response.response_st.payload;
  status->retry_admin = retry_admin;
  status->retry_user = retry_user;
  return *status;
}


#include "command_id.h"
#define STR(x) case x: return (#x); break;
const char * command_status_to_string(uint8_t status_code){

  switch (status_code){
    STR(dev_ok)
    STR(wrong_CRC)
    STR(wrong_slot)
    STR(dev_slot_not_programmed)
    STR(dev_wrong_password)
    STR(not_authorized)
    STR(timestamp_warning)
    STR(no_name_error)
    STR(not_supported)
    STR(dev_unknown_command)
    STR(AES_dec_failed)
    default:break;
  }

  return "Unknown";
}
#undef STR

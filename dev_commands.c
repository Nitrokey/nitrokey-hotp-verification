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

#include "dev_commands.h"
#include <string.h>
#include "device.h"
#include "min.h"
#include "operations.h"
#include "command_id.h"
#include "random_data.h"
#include <stdint.h>
#include "return_codes.h"


int authenticate_admin(struct Device *dev, const char *admin_PIN, uint8_t *admin_temporary_password) {
  struct FirstAuthenticate auth_st = {0};
  if (strnlen(admin_PIN, MAX_STRING_LENGTH) > sizeof(auth_st.card_password)){
    return RET_TOO_LONG_PIN;
  }

  int res;
  read_random_bytes_to_buf(dev->admin_temporary_password, sizeof(dev->admin_temporary_password));

  memcpy(auth_st.card_password, admin_PIN, min(strnlen(admin_PIN, MAX_STRING_LENGTH), sizeof(auth_st.card_password)));
  memcpy(admin_temporary_password, auth_st.temporary_password,
         min(TEMPORARY_PASSWORD_LENGTH, sizeof(auth_st.temporary_password)));
  res = device_send(dev, (uint8_t *) &auth_st, sizeof(auth_st), FIRST_AUTHENTICATE);
  if (res != RET_NO_ERROR) return res;
  res = device_receive_buf(dev);
  if (res != RET_NO_ERROR) return res;
  res = dev->packet_response.response_st.last_command_status;
  return res == dev_ok ? RET_NO_ERROR : res;
}

int authenticate_user(struct Device *dev, const char *user_PIN, uint8_t *user_temporary_password) {
  struct UserAuthenticate auth_st = {0};
  if (strnlen(user_PIN, MAX_STRING_LENGTH) > sizeof(auth_st.card_password)){
    return RET_TOO_LONG_PIN;
  }

  int res;
  read_random_bytes_to_buf(dev->user_temporary_password, sizeof(dev->user_temporary_password));

  memcpy(auth_st.card_password, user_PIN, min(strnlen(user_PIN, MAX_STRING_LENGTH), sizeof(auth_st.card_password)));
  memcpy(user_temporary_password, auth_st.temporary_password,
         min(TEMPORARY_PASSWORD_LENGTH, sizeof(auth_st.temporary_password)));
  res = device_send(dev, (uint8_t *) &auth_st, sizeof(auth_st), USER_AUTHENTICATE);
  if (res != RET_NO_ERROR) return res;
  res = device_receive_buf(dev);
  if (res != RET_NO_ERROR) return res;
  res = dev->packet_response.response_st.last_command_status;
  return res == dev_ok ? RET_NO_ERROR : res;
}
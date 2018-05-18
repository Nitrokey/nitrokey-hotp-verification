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


#ifndef NITROKEY_HOTP_VERIFICATION_RETURN_CODES_H
#define NITROKEY_HOTP_VERIFICATION_RETURN_CODES_H

#include "command_id.h"
enum {
  RET_VALIDATION_FAILED = dev_command_status_range + 10,
  RET_VALIDATION_PASSED,
  RET_NO_ERROR,
  RET_BADLY_FORMATTED_BASE32_STRING,
  RET_BADLY_FORMATTED_HOTP_CODE,
  RET_TOO_LONG_PIN,
  RET_INVALID_PARAMS,
  RET_CONNECTION_LOST,
};

enum {
  EXIT_NO_ERROR = 0,
  EXIT_CONNECTION_ERROR = 1,
  EXIT_WRONG_PIN = 2,
  EXIT_OTHER_ERROR = 3,
  EXIT_INVALID_HOTP_CODE = 4,
  EXIT_UNKNOWN_COMMAND = 5,
  EXIT_SLOT_NOT_PROGRAMMED = 6,
  EXIT_BAD_FORMAT = 7,
  EXIT_CONNECTION_LOST = 8,
  EXIT_INVALID_PARAMS = 100,
};


const char* res_to_error_string(int res);
int res_to_exit_code(int res);


#endif //NITROKEY_HOTP_VERIFICATION_RETURN_CODES_H

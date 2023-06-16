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

#include "return_codes.h"

const char *res_to_error_string(int res) {
    if (res == dev_wrong_password) return "Wrong PIN";
    if (res == dev_slot_not_programmed) return "Slot not programmed";
    if (res == dev_unknown_command) return "Device is not supporting HOTP validation";
    if (res == RET_VALIDATION_PASSED) return "HOTP code is correct";
    if (res == RET_NO_ERROR) return "Operation success";
    if (res == RET_SUCCESS) return "Operation success";
    if (res == RET_VALIDATION_FAILED) return "HOTP code is incorrect";
    if (res == RET_INVALID_PARAMS) return "Invalid command, incorrect arguments count or format";
    if (res == RET_BADLY_FORMATTED_BASE32_STRING) return "Invalid base32 string";
    if (res == RET_BADLY_FORMATTED_HOTP_CODE) return "Invalid HOTP code given";
    if (res == RET_TOO_LONG_PIN) return "Too long PIN given";
    if (res == RET_CONNECTION_LOST) return "Connection to the device was lost during the process";
    if (res == RET_COMM_ERROR) return "Connection error occurred";
    if (res == RET_UNKNOWN_DEVICE) return "Current device is not supported or known";
    if (res == RET_NO_PIN_ATTEMPTS) return "Device does not show PIN attempts counter";
    if (res == RET_SLOT_NOT_CONFIGURED) return "HOTP slot is not configured";
    if (res == RET_SECURITY_STATUS_NOT_SATISFIED) return "Touch was not recognized, or there was other problem with the authentication";
    return "Unknown error";
}


int res_to_exit_code(int res) {
    if (res == dev_wrong_password) return EXIT_WRONG_PIN;
    if (res == dev_slot_not_programmed) return EXIT_SLOT_NOT_PROGRAMMED;
    if (res == dev_unknown_command) res = EXIT_UNKNOWN_COMMAND;
    if (res == RET_VALIDATION_PASSED) return EXIT_NO_ERROR;
    if (res == RET_NO_ERROR) return EXIT_NO_ERROR;
    if (res == RET_VALIDATION_FAILED) return EXIT_INVALID_HOTP_CODE;
    if (res == RET_INVALID_PARAMS) return EXIT_INVALID_PARAMS;
    if (res == RET_BADLY_FORMATTED_BASE32_STRING) return EXIT_BAD_FORMAT;
    if (res == RET_TOO_LONG_PIN) return EXIT_BAD_FORMAT;
    if (res == RET_BADLY_FORMATTED_HOTP_CODE) return EXIT_BAD_FORMAT;
    if (res == RET_CONNECTION_LOST) return EXIT_CONNECTION_LOST;
    return EXIT_OTHER_ERROR;
}
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

#ifndef NITROKEY_HOTP_VERIFICATION_OPERATIONS_H
#define NITROKEY_HOTP_VERIFICATION_OPERATIONS_H


static const int MAX_STRING_LENGTH = 50;

static const int HOTP_MAX_INT = 10000*10000;

static const int HOTP_MIN_INT = 0;

static const int NK_STORAGE_BUSY = 2;
#include "device.h"
#include "return_codes.h"

int set_secret_on_device(struct Device *dev, const char *OTP_secret_base32, const char *admin_PIN, const uint64_t hotp_counter);
int check_code_on_device(struct Device *dev, const char *HOTP_code_to_verify);
bool verify_base32(const char* string, size_t len);

long strtol10_s(const char *string);

int regenerate_AES_key(struct Device *dev, const char *const admin_password);


#endif //NITROKEY_HOTP_VERIFICATION_OPERATIONS_H

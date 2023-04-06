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

#ifndef NITROKEY_HOTP_VERIFICATION_SETTINGS_H
#define NITROKEY_HOTP_VERIFICATION_SETTINGS_H


/**
 * Generate and validate 8 digits codes on the device, instead of 6 digits
 */
#define HOTP_CODE_USE_8_DIGITS false

// handling 40 bytes -> 320 bits
#define HOTP_SECRET_SIZE_BYTES (40)

// This name will show up in the Secrets App listing. Nitrokey Pro and Storage won't mention it.
#define SLOT_NAME ("HEADS Validation")
#define SLOT_NAME_LEN ( sizeof(SLOT_NAME) - 1 )
#define MAX_PIN_ATTEMPT_COUNTER_CCID    8
#define MAX_PIN_ATTEMPT_COUNTER_HID     3
#define MAX_PIN_SIZE_CCID               128
#define MAX_CCID_BUFFER_SIZE            3072

// Ask for PIN, if the HOTP slot is PIN-encrypted
// #define FEATURE_CCID_ASK_FOR_PIN_ON_ERROR


#endif //NITROKEY_HOTP_VERIFICATION_SETTINGS_H

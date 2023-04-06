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

#ifndef NITROKEY_HOTP_VERIFICATION_TLV_H
#define NITROKEY_HOTP_VERIFICATION_TLV_H

#include "stdint.h"

typedef struct {
    uint8_t tag;
    uint8_t length;
    uint8_t type;

    union {
        uint32_t v_raw;
        uint8_t *v_data;
        const char *v_str;
    };

} TLV;

int process_all(uint8_t *buf, TLV data[], int count);
TLV get_tlv(uint8_t *buf, size_t size, int tag);

#endif// NITROKEY_HOTP_VERIFICATION_TLV_H
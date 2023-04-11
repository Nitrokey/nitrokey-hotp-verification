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

#include "tlv.h"
#include "ccid.h"
#include "utils.h"
#include <endian.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

int process_TLV(uint8_t *buf, const TLV *t) {
    int i = 0;
    switch (t->type) {
        case 'R':
        case 'S':
            // encode string or data
            buf[i++] = t->tag;
            buf[i++] = t->length;
            memmove(buf + i, t->v_str, t->length);
            i += t->length;
            break;
        case 'I':
            // encode int BE u32
            buf[i++] = t->tag;
            buf[i++] = t->length;
            rassert(t->length == 4);
            uint32_t be = htobe32(t->v_raw);
            memmove(buf + i, &be, t->length);
            i += t->length;
            break;
        case 'B':
            // raw bytes - copy buffer directly, without adding TL pair
            memmove(buf + i, t->v_data, t->length);
            i += t->length;
            break;
        default:
            printf("invalid op %d \n", t->type);// FIXME debug
            rassert(false);
            exit(1);
            break;
    }

    return i;
}


int process_all(uint8_t *buf, TLV *data, int count) {
    int idx = 0;
    int idx_old = 0;
    for (int i = 0; i < count; ++i) {
        TLV *t = &data[i];
        idx += process_TLV(buf + idx, t);
        print_buffer(buf + idx_old, idx - idx_old, " ");
        idx_old = idx;
    }
    return idx;
}

TLV get_tlv(uint8_t *buf, size_t size, int tag) {
    TLV result = {};
    size_t i = 0;

    while (i < size) {
        if (buf[i] == tag) {
            result.tag = buf[i++];
            result.length = buf[i++];
            result.v_data = &buf[i];
            return result;
        } else {
            i++;            // skip T
            i += 1 + buf[i];// skip L and V
        }
    }
    return result;
}

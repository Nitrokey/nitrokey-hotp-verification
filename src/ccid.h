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

#ifndef NITROKEY_HOTP_VERIFICATION_CCID_H
#define NITROKEY_HOTP_VERIFICATION_CCID_H

#include <stdint.h>
#include <libusb.h>
#include "stdbool.h"
#include "tlv.h"
#include "device.h"

uint32_t
icc_compose(uint8_t *buf, uint32_t buffer_length, uint8_t msg_type, int32_t data_len, uint8_t slot, uint8_t seq,
            uint16_t param, uint8_t *data);

uint32_t
iso7816_compose(uint8_t *buf, uint32_t buffer_length, uint8_t ins, uint8_t p1, uint8_t p2, uint8_t cls, uint8_t le,
                uint8_t *data, uint8_t data_len);

typedef struct {
    uint8_t status;
    uint8_t chain;
    uint8_t *data;
    uint32_t data_len;
    uint16_t data_status_code;
//    const uint8_t *buffer;
//    const uint32_t buffer_len;
} IccResult;

IccResult parse_icc_result(uint8_t *buf, size_t buf_len);

int ccid_test();

void print_buffer(const unsigned char *buffer, const uint32_t length, const char *message);

int ccid_send(libusb_device_handle *device, int *actual_length, const unsigned char *data, const size_t length);

int ccid_receive(libusb_device_handle *device, int *actual_length, unsigned char *returned_data, int buffer_length);


int ccid_process(libusb_device_handle *handle, uint8_t *buf, uint32_t buf_length, const uint8_t *data_to_send[],
                 int data_to_send_count, const uint32_t data_to_send_sizes[], bool continue_on_errors,
                 IccResult *result);

int ccid_process_single(libusb_device_handle *handle, uint8_t *buf, uint32_t buf_length, const uint8_t *d,
                        const uint32_t length, IccResult *result);

char *ccid_error_message(uint16_t status_code);

int icc_pack_tlvs_for_sending(uint8_t *buf, size_t buflen, TLV tlvs[], int tlvs_count, int ins);
libusb_device_handle *get_device(libusb_context *ctx, const struct VidPid pPid[], int devices_count);
int ccid_init( libusb_device_handle* handle);
int send_select_ccid(libusb_device_handle* handle, uint8_t buf[], size_t buf_size, IccResult *iccResult);


enum {
    Tag_CredentialId = 0x71,
    Tag_NameList = 0x72,
    Tag_Key = 0x73,
    Tag_Challenge = 0x74,
    Tag_Response = 0x75,
    Tag_Properties = 0x78,
    Tag_InitialCounter = 0x7A,
    Tag_Version = 0x79,
    Tag_Algorithm = 0x7B,
    Tag_Password = 0x80,
    Tag_NewPassword = 0x81,
    Tag_PINCounter = 0x82
};


enum {
    Kind_Hotp = 0x10,
    Kind_Totp = 0x20,
    Kind_HotpReverse = 0x30
};

enum {
    Algo_Sha1 = 0x01,
    Algo_Sha256 = 0x02,
    Algo_Sha512 = 0x03
};

enum {
    Ins_Put = 0x1,
    Ins_Delete = 0x2,
    Ins_SetCode = 0x3,
    Ins_Reset = 0x4,
    Ins_List = 0xA1,
    Ins_Calculate = 0xA2,
    Ins_Validate = 0xA3,
    Ins_CalculateAll = 0xA4,
    Ins_SendRemaining = 0xA5,
    Ins_VerifyCode = 0xB1,
    Ins_VerifyPIN = 0xB2,
    Ins_ChangePIN = 0xB3,
    Ins_SetPIN = 0xB4,

    Ins_Select = 0xA4,
    Ins_GetResponse = 0xc0,
};

#define ARR_LEN(x) (sizeof((x)) / sizeof ((x)[0]) )

#endif //NITROKEY_HOTP_VERIFICATION_CCID_H

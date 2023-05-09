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

#ifndef NITROKEY_HOTP_VERIFICATION_DEVICE_H
#define NITROKEY_HOTP_VERIFICATION_DEVICE_H

#include "settings.h"
#include "structs.h"
#include <hidapi/hidapi.h>
#include <libusb.h>
#include <stddef.h>
#include <stdint.h>

#define nullptr (NULL)
#define TEMPORARY_PASSWORD_LENGTH (25)
#define NITROKEY_USB_VID 0x20a0
#define NITROKEY_PRO_USB_PID 0x4108
#define NITROKEY_STORAGE_USB_PID 0x4109
#define NITROKEY_3_USB_PID 0x42b2
#define LIBREM_KEY_USB_VID 0x316d
#define LIBREM_KEY_USB_PID 0x4c4b

typedef enum {
    CONNECTION_UNKNOWN,
    CONNECTION_HID,
    CONNECTION_CCID,
    CONNECTION_LENGTH
} ConnectionType;

typedef struct VidPid {
    uint16_t vid;
    uint16_t pid;
    const char *name;
    char name_short;
} VidPid;

struct Device {
    hid_device *mp_devhandle;
    libusb_device_handle *mp_devhandle_ccid;
    libusb_context *ctx_ccid;
    ConnectionType connection_type;
    VidPid dev_info;
    union {
        struct DeviceQuery packet_query;
        uint8_t ccid_buffer_out[MAX_CCID_BUFFER_SIZE];
    };
    union {
        struct DeviceResponse packet_response;
        uint8_t ccid_buffer_in[MAX_CCID_BUFFER_SIZE];
    };
    uint8_t user_temporary_password[TEMPORARY_PASSWORD_LENGTH];
    uint8_t admin_temporary_password[TEMPORARY_PASSWORD_LENGTH];
};

int device_connect(struct Device *dev);
int device_disconnect(struct Device *dev);
int device_get_status(struct Device *dev, struct ResponseStatus *out_status);
int device_send(struct Device *dev, uint8_t *in_data, size_t data_size, uint8_t command_ID);
int device_receive(struct Device *dev, uint8_t *out_data, size_t out_buffer_size);
int device_send_buf(struct Device *dev, uint8_t command_ID);
int device_receive_buf(struct Device *dev);
const char *command_status_to_string(uint8_t status_code);


void clean_buffers(struct Device *dev);

#endif//NITROKEY_HOTP_VERIFICATION_DEVICE_H

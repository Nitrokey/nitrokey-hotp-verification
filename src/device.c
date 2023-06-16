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

#include "device.h"
#include "ccid.h"
#include "command_id.h"
#include "crc32.h"
#include "min.h"
#include "return_codes.h"
#include "settings.h"
#include "structs.h"
#include "utils.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NITROKEY_USB_VID 0x20a0
#define NITROKEY_PRO_USB_PID 0x4108
#define NITROKEY_STORAGE_USB_PID 0x4109
#define NITROKEY_3_USB_PID 0x42b2
#define LIBREM_KEY_USB_VID 0x316d
#define LIBREM_KEY_USB_PID 0x4c4b

static void device_clear_buffers(struct Device *dev);

void _dump(uint8_t *data, size_t datalen) {
    if (datalen == 0) {
        printf("empty\n");
        return;
    }
    for (size_t i = 0; i < datalen; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}
#ifdef _DEBUG
#define dump(x, len)                           \
    printf("Dump of %s[%d]: ", #x, (int) len); \
    _dump(x, len);
#else
#define dump(x, len) ;
#endif

const VidPid devices[] = {
        {NITROKEY_USB_VID, NITROKEY_PRO_USB_PID, "Nitrokey Pro", 'P'},
        {LIBREM_KEY_USB_VID, LIBREM_KEY_USB_PID, "Librem Key", 'L'},
        {NITROKEY_USB_VID, NITROKEY_STORAGE_USB_PID, "Nitrokey Storage", 'S'},
};

const VidPid devices_ccid[] = {
        {NITROKEY_USB_VID, NITROKEY_3_USB_PID, "Nitrokey 3", '3'},
};

const size_t devices_size = sizeof(devices) / sizeof(devices[0]);

static const int CONNECTION_ATTEMPTS_COUNT = 2;

static const int CONNECTION_ATTEMPT_DELAY_MICRO_SECONDS = 1000 * 1000 / 2;

int device_receive(struct Device *dev, uint8_t *out_data, size_t out_buffer_size) {
    const int receive_attempts = 10;
    int i;
    int receive_status = 0;
    for (i = 0; i < receive_attempts; ++i) {
#ifdef _DEBUG
        fprintf(stderr, ".");
        fflush(stderr);
#endif
        usleep(500 * 1000);

        receive_status = (hid_get_feature_report(dev->mp_devhandle, dev->packet_response.as_data, HID_REPORT_SIZE_CONST));
        if (receive_status != (int) HID_REPORT_SIZE_CONST) continue;
        dump(dev->packet_response.as_data, receive_status);
        bool valid_response_crc = stm_crc32(dev->packet_response.as_data + 1, HID_REPORT_SIZE_CONST - 5) == dev->packet_response.response_st.crc;
        bool valid_query_crc = dev->packet_query.crc == dev->packet_response.response_st.last_command_crc;
        if (valid_response_crc && valid_query_crc && dev->packet_response.response_st.device_status == 0) {
            break;
        }
    }
    if (i >= receive_attempts - 1) {
        printf("WARN %s:%d: could not receive the data from the device.\n", "device.c", __LINE__);
        return RET_CONNECTION_LOST;
    }

    if (out_data != nullptr) {
        rassert(out_buffer_size != 0);
        memcpy(out_data, dev->packet_query.as_data + 1, min(out_buffer_size, HID_REPORT_SIZE_CONST - 1));
        if (out_buffer_size > HID_REPORT_SIZE_CONST - 1) {
            printf("WARN %s:%d: incoming data bigger than provided output buffer.\n", "device.c", __LINE__);
        }
    } else {
        //exit on wrong function parameters
        rassert(out_buffer_size == 0);
    }

    return RET_NO_ERROR;
}

int device_send(struct Device *dev, uint8_t *in_data, size_t data_size, uint8_t command_ID) {
    device_clear_buffers(dev);

    dev->packet_query.command_id = command_ID;

    if (in_data != nullptr) {
        rassert(data_size != 0);
        memcpy(dev->packet_query.payload, in_data, min(data_size, sizeof(dev->packet_query.payload)));
        if (data_size > HID_REPORT_SIZE_CONST - 1) {
            printf("WARN %s:%d: input data bigger than buffer.\n", "device.c", __LINE__);
        }
    } else {
        //exit on wrong function parameters
        rassert(data_size == 0);
    }

    dev->packet_query.crc = stm_crc32(dev->packet_query.as_data + 1, HID_REPORT_SIZE_CONST - 5);
    dump(dev->packet_query.as_data, HID_REPORT_SIZE_CONST);
    int send_status = hid_send_feature_report(dev->mp_devhandle, dev->packet_query.as_data, HID_REPORT_SIZE_CONST);

    if (send_status != (int) HID_REPORT_SIZE_CONST) {
        printf("WARN %s:%d: could not send the data to the device.\n", "device.c", __LINE__);
        return RET_CONNECTION_LOST;
    }

    return RET_NO_ERROR;
}

int device_connect_hid(struct Device *dev);

int device_connect_ccid(struct Device *dev) {
    dev->ctx_ccid = NULL;
    int r = libusb_init(&dev->ctx_ccid);
    if (r < 0) {
        printf("Error initializing libusb: %s\n", libusb_strerror(r));
        return false;
    }
    dev->mp_devhandle_ccid = get_device(dev->ctx_ccid, devices_ccid, 1);
    if (dev->mp_devhandle_ccid == NULL) {
        return false;
    }
    ccid_init(dev->mp_devhandle_ccid);

    return true;
}
int device_connect(struct Device *dev) {
    int r = device_connect_hid(dev);
    if (r) {
        dev->connection_type = CONNECTION_HID;
        fprintf(stderr, "\n");
        fflush(stderr);
        return r;
    }

#ifdef FEATURE_USE_CCID
    fflush(stderr);
    fprintf(stderr, ".");
    r = device_connect_ccid(dev);
    if (r) {
        dev->connection_type = CONNECTION_CCID;
        fprintf(stderr, "\n");
        fflush(stderr);
        return r;
    }
#endif

    fprintf(stderr, "\n");
    return false;
}

int device_connect_hid(struct Device *dev) {
    int count = CONNECTION_ATTEMPTS_COUNT;

    if (dev->mp_devhandle != nullptr)
        return 1;

    while (count-- > 0) {
        for (size_t dev_id = 0; dev_id < devices_size; ++dev_id) {
            const VidPid vidPid = devices[dev_id];
            dev->mp_devhandle = hid_open(vidPid.vid, vidPid.pid, nullptr);
            if (dev->mp_devhandle != nullptr) {
                dev->dev_info = vidPid;
                return true;
            }
            usleep(CONNECTION_ATTEMPT_DELAY_MICRO_SECONDS);
        }
        if (count == CONNECTION_ATTEMPTS_COUNT)
            fprintf(stderr, "Trying to connect to device: ");
        else
            fprintf(stderr, ".");
        fflush(stderr);
    }

    return false;
}

int device_disconnect(struct Device *dev) {
    if (dev->connection_type == CONNECTION_CCID) {
        if (dev->mp_devhandle_ccid == nullptr) return 1;//TODO name error value
        libusb_release_interface(dev->mp_devhandle_ccid, 0);
        libusb_close(dev->mp_devhandle_ccid);
        libusb_exit(dev->ctx_ccid);
        device_clear_buffers(dev);
        return RET_NO_ERROR;
    } else if (dev->connection_type == CONNECTION_HID) {
        if (dev->mp_devhandle == nullptr) return 1;//TODO name error value
        hid_close(dev->mp_devhandle);
        dev->mp_devhandle = nullptr;
        device_clear_buffers(dev);
        hid_exit();
        return RET_NO_ERROR;
    }
    return RET_UNKNOWN_DEVICE;
}

static void device_clear_buffers(struct Device *dev) {
    static_assert(sizeof(dev->packet_query.as_data) == HID_REPORT_SIZE, "Data size is not equal HID report size!");
    memset(dev->packet_query.as_data, 0, sizeof(dev->packet_query.as_data));
    memset(dev->packet_response.as_data, 0, sizeof(dev->packet_response.as_data));
    memset(dev->user_temporary_password, 0, sizeof(dev->user_temporary_password));
    memset(dev->admin_temporary_password, 0, sizeof(dev->admin_temporary_password));
    clean_buffers(dev);
}

int device_send_buf(struct Device *dev, uint8_t command_ID) {
    return device_send(dev, nullptr, 0, command_ID);
}

int device_receive_buf(struct Device *dev) {
    return device_receive(dev, nullptr, 0);
}

#include "operations_ccid.h"

int device_get_status(struct Device *dev, struct ResponseStatus *out_status) {
    if (dev->connection_type == CONNECTION_CCID) {
        int counter = 0;
        uint32_t serial = 0;
        uint16_t version = 0;
        int res = status_ccid(dev->mp_devhandle_ccid,
                              &counter,
                              &version,
                              &serial);
        out_status->retry_admin = counter;
        out_status->retry_user = counter;
        out_status->card_serial_u32 = serial;
        out_status->firmware_version = version;
        return res;
    }

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
    struct ResponseStatus *status = (struct ResponseStatus *) dev->packet_response.response_st.payload;
    status->retry_admin = retry_admin;
    status->retry_user = retry_user;
    return RET_NO_ERROR;
}


#include "command_id.h"
#define STR(x)       \
    case x:          \
        return (#x); \
        break;
const char *command_status_to_string(uint8_t status_code) {

    switch (status_code) {
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
        default:
            break;
    }

    return "Unknown";
}
#undef STR

void clean_buffers(struct Device *dev) {
    memset(dev->ccid_buffer_in, 0, sizeof dev->ccid_buffer_in);
    memset(dev->ccid_buffer_out, 0, sizeof dev->ccid_buffer_out);
}
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

#include "ccid.h"
#include "min.h"
#include "operations_ccid.h"
#include "return_codes.h"
#include "settings.h"
#include "tlv.h"
#include "utils.h"
#include <libusb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

static const int READ_ENDPOINT = 0x81;

static const int WRITE_ENDPOINT = 0x01;

static const int TIMEOUT = 1000;


uint32_t icc_compose(uint8_t *buf, uint32_t buffer_length, uint8_t msg_type, size_t data_len, uint8_t slot, uint8_t seq, uint16_t param, uint8_t *data) {
    static int _seq = 0;
    if (seq == 0) {
        seq = _seq++;
    }

    size_t i = 0;
    buf[i++] = msg_type;

    rassert(data_len < INT32_MAX);
    int32_t _data_len = (int32_t) data_len;
    buf[i++] = _data_len << 0;
    buf[i++] = _data_len << 8;
    buf[i++] = _data_len << 16;
    buf[i++] = _data_len << 24;

    buf[i++] = slot;
    buf[i++] = seq;
    buf[i++] = 0;
    buf[i++] = param << 0;
    buf[i++] = param << 8;
    const size_t final_data_length = min(data_len, buffer_length - i);
    memmove(buf + i, data, final_data_length);
    i += final_data_length;
    return i;
}


uint32_t iso7816_compose(uint8_t *buf, uint32_t buffer_length, uint8_t ins, uint8_t p1, uint8_t p2, uint8_t cls, uint8_t le, uint8_t *data, uint8_t data_len) {
    size_t i = 0;
    buf[i++] = cls;
    buf[i++] = ins;
    buf[i++] = p1;
    buf[i++] = p2;
    if (data != NULL && data_len != 0) {
        buf[i++] = data_len;
        const size_t data_length = min(data_len, buffer_length - i - 1);
        memmove(buf + i, data, data_length);
        i += data_length;
    }
    if (le != 0) {
        buf[i++] = le;
    }
    return i;
}


IccResult parse_icc_result(uint8_t *buf, size_t buf_len) {
    rassert(buf_len >= 10);
    unused(buf_len);
    const uint8_t data_len = buf[1] | (buf[2] << 8) | (buf[3] << 16) | (buf[4] << 24);
    // take last 2 bytes as the status code, if there is any data returned
    const uint16_t data_status_code = (data_len >= 2) ? be16toh(*(uint16_t *) &buf[10 + data_len - 2]) : 0;
    const IccResult i = {
            .status = buf[7],
            .chain = buf[9],
            .data = &buf[10],
            .data_len = data_len,
            .data_status_code = data_status_code,
            //            .buffer = buf,
            //            .buffer_len = buf_len
    };
    // Make sure the response do not contain overread attempts
    rassert(i.data_len < buf_len - 10);
    return i;
}

libusb_device_handle *get_device(libusb_context *ctx, const struct VidPid pPid[], int devices_count) {
    int r;
    libusb_device **devs;
    size_t count = libusb_get_device_list(ctx, &devs);
    if (count == 0) {
        printf("Error getting device list\n");
        return NULL;
    }

    rassert(devices_count == 1);
    libusb_device_handle *handle = NULL;
    for (size_t i = 0; i < count; i++) {
        libusb_device *dev = devs[i];
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(devs[i], &desc) >= 0) {
            LOG("%x ", desc.idVendor);
            if (!(desc.idVendor == pPid->vid && desc.idProduct == pPid->pid)) {
                continue;
            }
        }

        r = libusb_open(dev, &handle);
        if (r == LIBUSB_SUCCESS) {
            LOG("open\n");
            break;
        } else {
            printf("Error opening device: %s\n", libusb_strerror(r));
        }
    }
    libusb_free_device_list(devs, 1);
    if (handle == NULL) {
        printf("No working device found\n");
        return NULL;
    }

    r = libusb_claim_interface(handle, 0);
    if (r < 0) {
        printf("Error claiming interface: %s\n", libusb_strerror(r));
        return NULL;
    }

    LOG("set alt interface\n");
    r = libusb_set_interface_alt_setting(handle, 0, 0);
    if (r < 0) {
        printf("Error set alt interface: %s\n", libusb_strerror(r));
        return NULL;
    }

    return handle;
}


int ccid_process_single(libusb_device_handle *handle, uint8_t *receiving_buffer, uint32_t receiving_buffer_length, const uint8_t *sending_buffer,
                        const uint32_t sending_buffer_length, IccResult *result) {
    int actual_length = 0, r;

    r = ccid_send(handle, &actual_length, sending_buffer, sending_buffer_length);
    if (r != 0) {
        return r;
    }

    int prev_status = 0;
    while (true) {
        r = ccid_receive(handle, &actual_length, receiving_buffer, receiving_buffer_length);
        if (r != 0) {
            return r;
        }

        IccResult iccResult = parse_icc_result(receiving_buffer, receiving_buffer_length);
        LOG("status %d, chain %d\n", iccResult.status, iccResult.chain);
        if (iccResult.data_len > 0) {
            print_buffer(iccResult.data, iccResult.data_len, "    returned data");
            LOG("Status code: %s\n", ccid_error_message(iccResult.data_status_code));
        }
        if (iccResult.data[0] == DATA_REMAINING_STATUS_CODE) {
            // 0x61 status code means data remaining, make another receive call

            uint8_t buf_sr[SMALL_CCID_BUFFER_SIZE] = {};
            uint32_t send_rem_length = iso7816_compose(buf_sr, sizeof buf_sr,
                                                       Ins_GetResponse, 0, 0, 0, 0xFF, NULL, 0);
            uint8_t buf_sr_2[SMALL_CCID_BUFFER_SIZE] = {};
            uint32_t send_rem_icc_len = icc_compose(buf_sr_2, sizeof buf_sr_2,
                                                    0x6F, send_rem_length,
                                                    0, 0, 0, buf_sr);
            int actual_length_sr = 0;
            r = ccid_send(handle, &actual_length_sr, buf_sr_2, send_rem_icc_len);
            if (r != 0) {
                return r;
            }

            memset(receiving_buffer, 0, receiving_buffer_length);
            r = ccid_receive(handle, &actual_length_sr, receiving_buffer, receiving_buffer_length);
            if (r != 0) {
                return r;
            }

            iccResult = parse_icc_result(receiving_buffer, receiving_buffer_length);
            LOG("status %d, chain %d\n", iccResult.status, iccResult.chain);
            if (iccResult.data_len > 0) {
                print_buffer(iccResult.data, iccResult.data_len, "    returned data");
                LOG("Status code: %s\n", ccid_error_message(iccResult.data_status_code));
            }
        }
        if (iccResult.status == AWAITING_FOR_TOUCH_STATUS_CODE) {
            if (prev_status != iccResult.status) {
                printf("Please touch the USB security key if it blinks ");
                fflush(stdout);
                prev_status = iccResult.status;
            } else {
                printf(".");
                fflush(stdout);
            }
            continue;
        } else {
            if (prev_status == AWAITING_FOR_TOUCH_STATUS_CODE) {
                printf(". touch received\n");
                fflush(stdout);
            }
        }
        prev_status = iccResult.status;
        if (iccResult.chain == 0 || iccResult.chain == 2) {
            if (result != NULL) {
                memmove(result, &iccResult, sizeof iccResult);
            }
            break;
        }
        switch (iccResult.chain) {
            case 1:
            case 3:
                continue;
            default:
                printf("Invalid value for chain: %d\n", iccResult.chain);
                return RET_COMM_ERROR;
        }
    }
    return 0;
}

int ccid_process(libusb_device_handle *handle, uint8_t *buf, uint32_t buf_length, const uint8_t **data_to_send,
                 int data_to_send_count, const uint32_t *data_to_send_sizes, bool continue_on_errors,
                 IccResult *result) {
    int r;
    rassert(buf != NULL);
    rassert(buf_length >= 270);

    for (int i = 0; i < data_to_send_count; ++i) {
        const unsigned char *d = data_to_send[i];
        const int length = (int) data_to_send_sizes[i];

        r = ccid_process_single(handle, buf, buf_length, d, length, result);
        if (r != 0) {
            if (continue_on_errors) {
                // ignore error, continue with sending the next record
                continue;
            } else {
                return r;
            }
        }

    }// end for
    return 0;
}

int send_select_ccid(libusb_device_handle *handle, uint8_t buf[], size_t buf_size, IccResult *iccResult) {
    unsigned char cmd_select[] = {
            0x6f,
            0x0c,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xa4,
            0x04,
            0x00,
            0x07,
            0xa0,
            0x00,
            0x00,
            0x05,
            0x27,
            0x21,
            0x01,
    };

    check_ret(
            ccid_process_single(handle, buf, buf_size, cmd_select, sizeof cmd_select, iccResult),
            RET_COMM_ERROR);


    return RET_NO_ERROR;
}


int ccid_init(libusb_device_handle *handle) {

    unsigned char cmd_select[] = {
            0x6f,
            0x0c,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xa4,
            0x04,
            0x00,
            0x07,
            0xa0,
            0x00,
            0x00,
            0x05,
            0x27,
            0x21,
            0x01,
    };

    unsigned char cmd_poweron[] = {
            0x62,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
    };

    unsigned char cmd_poweroff[] = {
            0x63,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
    };

    unsigned char cmd_info[] = {
            0x61,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
    };

    const unsigned char *data_to_send[] = {
            cmd_select,
            //            cmd_poweron,
            //            cmd_poweroff,
            //            cmd_info,
    };

    const unsigned int data_to_send_size[] = {
            sizeof(cmd_select),
            //            sizeof(cmd_poweron),
            //            sizeof(cmd_poweroff),
            //            sizeof(cmd_info),
    };

    unsigned char buf[MAX_CCID_BUFFER_SIZE] = {};
    ccid_process(handle, buf, sizeof buf, data_to_send, LEN_ARR(data_to_send), data_to_send_size, true, NULL);
    return 0;
}

uint32_t icc_pack_tlvs_for_sending(uint8_t *buf, size_t buflen, TLV *tlvs, int tlvs_count, int ins) {
    uint8_t data_tlvs[MAX_CCID_BUFFER_SIZE] = {};
    int tlvs_actual_length = process_all(data_tlvs, tlvs, tlvs_count);

    // encode instruction
    uint8_t data_iso[MAX_CCID_BUFFER_SIZE] = {};
    uint32_t iso_actual_length = iso7816_compose(
            data_iso, sizeof data_iso,
            ins, 0, 0, 0, 0, data_tlvs, tlvs_actual_length);

    // encode ccid wrapper
    uint32_t icc_actual_length = icc_compose(buf, buflen,
                                             0x6F, iso_actual_length,
                                             0, 0, 0, data_iso);


    return icc_actual_length;
}

int ccid_receive(libusb_device_handle *device, int *actual_length, unsigned char *returned_data, size_t buffer_length) {
    int32_t _buffer_length = MIN(buffer_length, INT32_MAX);
    int r = libusb_bulk_transfer(device, READ_ENDPOINT, returned_data, _buffer_length, actual_length, TIMEOUT);
    if (r < 0) {
        LOG("Error reading data: %s\n", libusb_strerror(r));
        return RET_COMM_ERROR;
    }
    print_buffer(returned_data, (*actual_length), "recv");
    return 0;
}

int ccid_send(libusb_device_handle *device, int *actual_length, const unsigned char *data, const size_t length) {
    print_buffer(data, length, "sending");
    int r = libusb_bulk_transfer(device, WRITE_ENDPOINT, (uint8_t *) data, (int) length, actual_length, TIMEOUT);
    if (r < 0) {
        LOG("Error sending data: %s\n", libusb_strerror(r));
        return RET_COMM_ERROR;
    }
    return 0;
}

void print_buffer(const unsigned char *buffer, const uint32_t length, const char *message) {
#ifdef NDEBUG
    unused(message);
    unused(length);
    unused(buffer);
#endif
    LOG("%s ", message);
    for (uint32_t j = 0; j < length; ++j) {
        LOG("%02x", buffer[j]);
    }
    LOG("\n");
}


char *ccid_error_message(uint16_t status_code) {
    if ((status_code & 0xFF00) == 0x6100) {
        return "MoreDataAvailable";
    }
    switch (status_code) {
        case 0x61FF:
            return "MoreDataAvailable";
        case 0x6300:
            return "VerificationFailed";
        case 0x6400:
            return "UnspecifiedNonpersistentExecutionError";
        case 0x6500:
            return "UnspecifiedPersistentExecutionError";
        case 0x6700:
            return "WrongLength";
        case 0x6881:
            return "LogicalChannelNotSupported";
        case 0x6882:
            return "SecureMessagingNotSupported";
        case 0x6884:
            return "CommandChainingNotSupported";
        case 0x6982:
            return "SecurityStatusNotSatisfied";
        case 0x6985:
            return "ConditionsOfUseNotSatisfied";
        case 0x6983:
            return "OperationBlocked";
        case 0x6a80:
            return "IncorrectDataParameter";
        case 0x6a81:
            return "FunctionNotSupported";
        case 0x6a82:
            return "NotFound";
        case 0x6a84:
            return "NotEnoughMemory";
        case 0x6a86:
            return "IncorrectP1OrP2Parameter";
        case 0x6a88:
            return "KeyReferenceNotFound";
        case 0x6d00:
            return "InstructionNotSupportedOrInvalid";
        case 0x6e00:
            return "ClassNotSupported";
        case 0x6f00:
            return "UnspecifiedCheckingError";
        case 0x9000:
            return "Success";
        default:
            return "Unknown error code";
    }
    return "Unreachable";
}

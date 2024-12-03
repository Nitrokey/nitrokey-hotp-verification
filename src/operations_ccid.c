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

#include "operations_ccid.h"
#include "base32.h"
#include "ccid.h"
#include "device.h"
#include "return_codes.h"
#include "settings.h"
#include "tlv.h"
#include "utils.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>


int set_pin_ccid(struct Device *dev, const char *admin_PIN) {
    TLV tlvs[] = {
            {
                    .tag = Tag_Password,
                    .length = strnlen(admin_PIN, MAX_PIN_SIZE_CCID),
                    .type = 'S',
                    .v_str = admin_PIN,
            },
    };

    clean_buffers(dev);
    // encode
    uint32_t icc_actual_length = icc_pack_tlvs_for_sending(dev->ccid_buffer_out, sizeof dev->ccid_buffer_out,
                                                           tlvs, ARR_LEN(tlvs), Ins_SetPIN);

    // send
    IccResult iccResult;
    int r = ccid_process_single(dev->mp_devhandle_ccid, dev->ccid_buffer_in, sizeof dev->ccid_buffer_in,
                                dev->ccid_buffer_out, icc_actual_length, &iccResult);

    if (r != 0) {
        return r;
    }
    // check status code
    if (iccResult.data_status_code != 0x9000) {
        return 1;
    }

    return 0;
}

int nk3_change_pin(struct Device *dev, const char *old_pin, const char*new_pin) {
    libusb_device *usb_dev;
    struct libusb_device_descriptor usb_desc;

    if (!dev->mp_devhandle_ccid) {
        return RET_NO_ERROR;    
    }

    usb_dev = libusb_get_device(dev->mp_devhandle_ccid);

    int r = libusb_get_device_descriptor(usb_dev, &usb_desc);

    if (r < 0) {
        return r;
    }


    if (usb_desc.idVendor != NITROKEY_USB_VID || usb_desc.idProduct != NITROKEY_3_USB_PID) {
        return RET_NO_ERROR;    
    }

    TLV tlvs[] = {
        {
            .tag = Tag_Password,
            .length = strnlen(old_pin, MAX_PIN_SIZE_CCID),
            .type = 'S',
            .v_str = old_pin,
        },
        {
            .tag = Tag_NewPassword,
            .length = strnlen(new_pin, MAX_PIN_SIZE_CCID),
            .type = 'S',
            .v_str = new_pin,
        },
    };
    // encode
    uint32_t icc_actual_length = icc_pack_tlvs_for_sending(dev->ccid_buffer_out, sizeof dev->ccid_buffer_out,
                                                           tlvs, ARR_LEN(tlvs), Ins_ChangePIN);
    // send
    IccResult iccResult;
    r = ccid_process_single(dev->mp_devhandle_ccid, dev->ccid_buffer_in, sizeof dev->ccid_buffer_in,
                                dev->ccid_buffer_out, icc_actual_length, &iccResult);
    if (r != 0) {
        return r;
    }
    // check status code
    if (iccResult.data_status_code != 0x9000) {
        return 1;
    }

    return RET_NO_ERROR;
}


int authenticate_ccid(struct Device *dev, const char *admin_PIN) {
    TLV tlvs[] = {
            {
                    .tag = Tag_Password,
                    .length = strnlen(admin_PIN, 30),
                    .type = 'S',
                    .v_str = admin_PIN,
            },
    };

    clean_buffers(dev);
    // encode
    uint32_t icc_actual_length = icc_pack_tlvs_for_sending(dev->ccid_buffer_out, sizeof dev->ccid_buffer_out,
                                                           tlvs, ARR_LEN(tlvs), Ins_VerifyPIN);
    // send
    IccResult iccResult;
    int r = ccid_process_single(dev->mp_devhandle_ccid, dev->ccid_buffer_in, sizeof dev->ccid_buffer_in,
                                dev->ccid_buffer_out, icc_actual_length, &iccResult);
    if (r != 0) {
        return r;
    }

    // check status code
    if (iccResult.data_status_code == 0x6300) {
        // Invalid PIN or PIN attempt counter is used up
        return RET_WRONG_PIN;
    }
    if (iccResult.data_status_code == 0x6982) {
        return RET_SECURITY_STATUS_NOT_SATISFIED;
    }
    if (iccResult.data_status_code != 0x9000) {
        // TODO print the error code
        return 1;
    }

    return RET_NO_ERROR;
}

// Attempt to authenticate with admin_PIN. If the PIN is not set (status code 0x6982), create the PIN
// with the given value
int authenticate_or_set_ccid(struct Device *dev, const char *admin_PIN) {
    int r = authenticate_ccid(dev, admin_PIN);
    if (r == RET_SECURITY_STATUS_NOT_SATISFIED) {
        check_ret(set_pin_ccid(dev, admin_PIN), RET_SECURITY_STATUS_NOT_SATISFIED);
        return authenticate_ccid(dev, admin_PIN);
    }

    return RET_NO_ERROR;
}


int delete_secret_on_device_ccid(struct Device *dev) {    
    TLV tlvs[] = {
        {
            .tag = Tag_CredentialId,
            .length = SLOT_NAME_LEN,
            .type = 'S',
            .v_str = SLOT_NAME,
        }
    };

    clean_buffers(dev);
    // encode
    uint32_t icc_actual_length = icc_pack_tlvs_for_sending(dev->ccid_buffer_out, sizeof dev->ccid_buffer_out,
                                                           tlvs, ARR_LEN(tlvs), Ins_Delete);
    // send
    IccResult iccResult;
    int r = ccid_process_single(dev->mp_devhandle_ccid, dev->ccid_buffer_in, sizeof dev->ccid_buffer_in,
                                dev->ccid_buffer_out, icc_actual_length, &iccResult);
    if (r != 0) {
        return r;
    }

    // check status code
    if (iccResult.data_status_code == 0x6a82 || iccResult.data_status_code == 0x9000) {
        return 0;
    } else {
        return RET_VALIDATION_FAILED;
    }
    return r;
}

int set_secret_on_device_ccid(struct Device *dev, const char *admin_PIN, const char *OTP_secret_base32, const uint64_t hotp_counter) {
    // Decode base32 secret
    uint8_t binary_secret_buf[HOTP_SECRET_SIZE_BYTES + 2] = {0};
    const size_t decoded_length = base32_decode((const unsigned char *) OTP_secret_base32, binary_secret_buf + 2) + 2;
    rassert(decoded_length <= HOTP_SECRET_SIZE_BYTES);

    binary_secret_buf[0] = Kind_HotpReverse | Algo_Sha1;
    binary_secret_buf[1] = (HOTP_CODE_USE_8_DIGITS) ? 8 : 6;

    // 0x02 if touch_button_required else 0x00
    uint8_t properties[2] = {Tag_Properties, 0x00};

    rassert(hotp_counter < 0xFFFFFFFF);
    uint32_t initial_counter_value = hotp_counter;

    int r = delete_secret_on_device_ccid(dev);
    if (r != 0) {
        return r;
    }

#ifdef CCID_SECRETS_AUTHENTICATE_OR_CREATE_PIN
        if (strnlen(admin_PIN, 30) > 0) {
            if (authenticate_or_set_ccid(dev, admin_PIN) != RET_NO_ERROR) {
                return RET_SECURITY_STATUS_NOT_SATISFIED;
            }
        }
#endif
    TLV tlvs[] = {
            {
                    .tag = Tag_CredentialId,
                    .length = SLOT_NAME_LEN,
                    .type = 'S',
                    .v_str = SLOT_NAME,
            },
            {
                    .tag = Tag_Key,
                    .length = decoded_length,
                    .type = 'R',
                    .v_data = binary_secret_buf,
            },
            {
                    .tag = Tag_Properties,
                    .length = 2,
                    .type = 'B',
                    .v_data = properties,
            },
            {
                    .tag = Tag_InitialCounter,
                    .length = 4,
                    .type = 'I',
                    .v_raw = initial_counter_value,
            },
    };


    clean_buffers(dev);
    // encode
    uint32_t icc_actual_length = icc_pack_tlvs_for_sending(dev->ccid_buffer_out, sizeof dev->ccid_buffer_out,
                                                           tlvs, ARR_LEN(tlvs), Ins_Put);

    // send
    IccResult iccResult;
    r = ccid_process_single(dev->mp_devhandle_ccid, dev->ccid_buffer_in, sizeof dev->ccid_buffer_in,
                                dev->ccid_buffer_out, icc_actual_length, &iccResult);


    if (r != 0) {
        return r;
    }
    // check status code
    if (iccResult.data_status_code == 0x6a82) {
        return RET_NO_PIN_ATTEMPTS;
    }
    if (iccResult.data_status_code == 0x6982) {
        return RET_SECURITY_STATUS_NOT_SATISFIED;
    }
    if (iccResult.data_status_code != 0x9000) {
        return RET_VALIDATION_FAILED;
    }

    return RET_NO_ERROR;
}

int verify_code_ccid(struct Device *dev, const uint32_t code_to_verify) {
    int r;

    TLV tlvs[] = {
            {
                    .tag = Tag_CredentialId,
                    .length = SLOT_NAME_LEN,
                    .type = 'S',
                    .v_str = SLOT_NAME,
            },
            {
                    .tag = Tag_Response,
                    .length = 4,
                    .type = 'I',
                    .v_raw = code_to_verify,
            },
    };


    clean_buffers(dev);
    // encode
    uint32_t icc_actual_length = icc_pack_tlvs_for_sending(dev->ccid_buffer_out, sizeof dev->ccid_buffer_out,
                                                           tlvs, ARR_LEN(tlvs), Ins_VerifyCode);

    // send
    IccResult iccResult;
    r = ccid_process_single(dev->mp_devhandle_ccid, dev->ccid_buffer_in, sizeof dev->ccid_buffer_in,
                            dev->ccid_buffer_out, icc_actual_length, &iccResult);
    if (r != 0) {
        return r;
    }
    // check status code
    if (iccResult.data_status_code == 0x6A82) {
        // Slot is not configured or requires PIN to proceed. Ask User for the latter.
        return RET_SLOT_NOT_CONFIGURED;
    }

    if (iccResult.data_status_code != 0x9000) {
        return RET_VALIDATION_FAILED;
    }

    return RET_VALIDATION_PASSED;
}

int status_ccid(libusb_device_handle *handle, struct FullResponseStatus *full_response) {
    rassert(full_response != NULL);
    struct ResponseStatus *response = &full_response->response_status;
    rassert(handle != NULL);
    uint8_t buf[1024] = {};
    IccResult iccResult = {};
    bool pin_counter_is_error = false;
    int r;
    libusb_device *usb_dev;
    struct libusb_device_descriptor usb_desc;

    usb_dev = libusb_get_device(handle);

    r = libusb_get_device_descriptor(usb_dev, &usb_desc);

    if (r < 0) {
        return r;
    }


    if (usb_desc.idVendor == NITROKEY_USB_VID || usb_desc.idProduct == NITROKEY_3_USB_PID) {
        full_response->device_type = Nk3;
    } else if (usb_desc.idVendor == NITROKEY_USB_VID || usb_desc.idProduct == NITROKEY_PRO_USB_PID) {
        full_response->device_type = NkPro2;
    } else if (usb_desc.idVendor == NITROKEY_USB_VID || usb_desc.idProduct == NITROKEY_STORAGE_USB_PID) {
        full_response->device_type = NkStorage;
    } else if (usb_desc.idVendor == LIBREM_KEY_USB_VID || usb_desc.idProduct == LIBREM_KEY_USB_PID) {
        full_response->device_type = LibremKey;
    }

    if (full_response->device_type == Nk3) {
        r = send_select_nk3_admin_ccid(handle, buf, sizeof buf, &iccResult);
        if (r != RET_NO_ERROR) {
            return r;
        }

        uint8_t data_iso[MAX_CCID_BUFFER_SIZE] = {};
        uint32_t iso_actual_length = iso7816_compose(
                data_iso, sizeof data_iso,
                0x61, 0, 0, 0, 4, NULL, 0);

        // encode ccid wrapper
        uint32_t icc_actual_length = icc_compose(buf, sizeof buf,
                                                 0x6F, iso_actual_length,
                                                 0, 0, 0, data_iso);
        int transferred;
        r = ccid_send(handle, &transferred, buf, icc_actual_length);
        if (r != 0) {
            return r;
        }

        r = ccid_receive(handle, &transferred, buf, sizeof buf);
        if (r != 0) {
            return r;
        }

        IccResult iccResult = parse_icc_result(buf, transferred);
        rassert(iccResult.data_status_code == 0x9000);
        rassert(iccResult.data_len == 6);
        full_response->nk3_extra_info.firmware_version = be32toh(*(uint32_t *) iccResult.data);
    }

    if (full_response->device_type == Nk3) {
        r = send_select_nk3_pgp_ccid(handle, buf, sizeof buf, &iccResult);
        if (r != RET_NO_ERROR) {
            return r;
        }

        uint8_t data_iso[MAX_CCID_BUFFER_SIZE] = {};
        uint32_t iso_actual_length = iso7816_compose(
                data_iso, sizeof data_iso,
                0xCA, 0, 0xC4, 0, 0xFF, NULL, 0);

        // encode ccid wrapper
        uint32_t icc_actual_length = icc_compose(buf, sizeof buf,
                                                 0x6F, iso_actual_length,
                                                 0, 0, 0, data_iso);
        int transferred;
        r = ccid_send(handle, &transferred, buf, icc_actual_length);
        if (r != 0) {
            return r;
        }

        r = ccid_receive(handle, &transferred, buf, sizeof buf);
        if (r != 0) {
            return r;
        }

        IccResult iccResult = parse_icc_result(buf, transferred);
        rassert(iccResult.data_status_code == 0x9000);
        rassert(iccResult.data_len == 9);
        full_response->nk3_extra_info.pgp_user_pin_retries = iccResult.data[4];
        full_response->nk3_extra_info.pgp_admin_pin_retries = iccResult.data[6];
    }

    r = send_select_ccid(handle, buf, sizeof buf, &iccResult);
    if (r != RET_NO_ERROR) {
        return r;
    }
    if (iccResult.data_len == 0 || iccResult.data_status_code != 0x9000) {
        return RET_COMM_ERROR;
    }

    TLV counter_tlv = {};
    r = get_tlv(iccResult.data, iccResult.data_len, Tag_PINCounter, &counter_tlv);
    if (!(r == RET_NO_ERROR && counter_tlv.tag == Tag_PINCounter)) {
        // PIN counter not found - comm error (ignore) or PIN not set
        pin_counter_is_error = true;
    } else {
        response->retry_admin = counter_tlv.v_data[0];
        response->retry_user = counter_tlv.v_data[0];
    }

    TLV serial_tlv = {};
    r = get_tlv(iccResult.data, iccResult.data_len, Tag_SerialNumber, &serial_tlv);
    if (r == RET_NO_ERROR && serial_tlv.tag == Tag_SerialNumber) {
        response->card_serial_u32 = be32toh(*(uint32_t *) serial_tlv.v_data);
    } else {
        // ignore errors - unsupported or hidden serial_tlv number
        response->card_serial_u32 = 0;
    }

    TLV version_tlv = {};
    r = get_tlv(iccResult.data, iccResult.data_len, Tag_Version, &version_tlv);
    if (!(r == RET_NO_ERROR && version_tlv.tag == Tag_Version)) {
        response->firmware_version = 0;
        return RET_COMM_ERROR;
    }
    response->firmware_version = be16toh(*(uint16_t *) version_tlv.v_data);

    if (pin_counter_is_error == true) {
        return RET_NO_PIN_ATTEMPTS;
    }
    return RET_NO_ERROR;
}

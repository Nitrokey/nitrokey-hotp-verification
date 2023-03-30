
#include "utils.h"
#include "min.h"
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <libusb.h>
#include <string.h>
#include <assert.h>
#include "operations_ccid.h"
#include "ccid.h"
#include "tlv.h"
#include "settings.h"
#include "base32.h"


int set_pin_ccid(libusb_device_handle *handle, const char *admin_PIN) {

    /**
     *         structure = [
            tlv8.Entry(Tag.Password.value, password),
        ]
        self._send_receive(Instruction.SetPIN, structure=structure)

     */

    TLV tlvs[] = {
            {
                    .tag = Tag_Password,
                    .length = strnlen(admin_PIN, 30),
                    .type = 'S',
                    .v_str = admin_PIN,
            },
    };

    int r;
    uint8_t data[1024] = {};
    uint32_t icc_actual_length = icc_pack_tlvs_for_sending(data, sizeof data, tlvs, ARR_LEN(tlvs), Ins_SetPIN);

    // send
    unsigned char recv_buf[1024] = {};
    IccResult iccResult;
    r = ccid_process_single(handle, recv_buf, sizeof recv_buf,
                            data, icc_actual_length, &iccResult);

    if (r != 0){
        return r;
    }
    // check status code
    if (iccResult.data_status_code != 0x9000){
        return 1;
    }

    return 0;
}


int authenticate_ccid(libusb_device_handle *handle, const char *admin_PIN) {

    /**
     *         structure = [
            tlv8.Entry(Tag.Password.value, password),
        ]
        self._send_receive(Instruction.VerifyPIN, structure=structure)
     */
    int r;
    TLV tlvs[] = {
            {
                    .tag = Tag_Password,
                    .length = strnlen(admin_PIN, 30),
                    .type = 'S',
                    .v_str = admin_PIN,
            },
    };

    uint8_t data[1024] = {};
    uint32_t icc_actual_length = icc_pack_tlvs_for_sending(data, sizeof data, tlvs, ARR_LEN(tlvs), Ins_VerifyPIN);

    // send
    unsigned char recv_buf[1024] = {};
    IccResult iccResult;
    r = ccid_process_single(handle, recv_buf, sizeof recv_buf,
                            data, icc_actual_length, &iccResult);
    if (r != 0){
        return r;
    }

    // check status code
    if (iccResult.data_status_code != 0x9000){
        return 1;
    }

    return 0;
}


int
set_secret_on_device_ccid(libusb_device_handle *handle, const char *OTP_secret_base32, const uint64_t hotp_counter) {
    uint8_t binary_secret_buf[secret_size_bytes+2] = {0}; //handling 40 bytes -> 320 bits
    const size_t decoded_length = base32_decode((const unsigned char *) OTP_secret_base32, binary_secret_buf+2)+2;
    assert(decoded_length <= secret_size_bytes);

    binary_secret_buf[0] = Kind_HotpReverse | Algo_Sha1;
    binary_secret_buf[1] = (HOTP_CODE_USE_8_DIGITS)? 8 : 6;

    /**
     *         structure = [
            tlv8.Entry(Tag.CredentialId.value, credid),
            # header (2) + secret (N)
            tlv8.Entry(
                Tag.Key.value, bytes([kind.value | algo.value, digits]) + secret
            ),
            RawBytes([Tag.Properties.value, 0x02 if touch_button_required else 0x00]),
            tlv8.Entry(
                Tag.InitialCounter.value, initial_counter_value.to_bytes(4, "big")
            ),
        ]
        self._send_receive(Instruction.Put, structure)

     */
    // 0x02 if touch_button_required else 0x00
    uint8_t properties[2] = { Tag_Properties, 0x00 };

    // FIXME check for overflow ?
    uint32_t initial_counter_value = hotp_counter;

    TLV tlvs[] = {
            {
                    .tag = Tag_CredentialId,
                    .length = slot_name_len,
                    .type = 'S',
                    .v_str = slot_name,
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


    int r;
    // FIXME check if pin is set, set PIN if none
//    r = set_pin_ccid(handle, admin_PIN);

//    r = authenticate_ccid(handle, admin_PIN);
//    if (!r) {
//        printf("Authentication failed!\n");
//    }

    uint8_t data[1024] = {};
    uint32_t icc_actual_length = icc_pack_tlvs_for_sending(data, sizeof data, tlvs, ARR_LEN(tlvs), Ins_Put);

    // send
    unsigned char recv_buf[1024] = {};
    IccResult iccResult;
    r = ccid_process_single(handle, recv_buf, sizeof recv_buf,
                            data, icc_actual_length, &iccResult);
    if (r != 0){
        return r;
    }
    // check status code
    if (iccResult.data_status_code != 0x9000){
        return 1;
    }

    return 0;
}

int verify_code_ccid(libusb_device_handle *handle, const uint32_t code_to_verify) {
    int r;

    TLV tlvs[] = {
            {
                    .tag = Tag_CredentialId,
                    .length = slot_name_len,
                    .type = 'S',
                    .v_str = slot_name,
            },
            {
                    .tag = Tag_Response,
                    .length = 4,
                    .type = 'I',
                    .v_raw = code_to_verify,
            },
    };
    uint8_t data[1024] = {};
    uint32_t icc_actual_length = icc_pack_tlvs_for_sending(data, sizeof data,
                                                           tlvs, ARR_LEN(tlvs), Ins_VerifyCode);
    // send
    unsigned char recv_buf[1024] = {};
    IccResult iccResult;
    r = ccid_process_single(handle, recv_buf, sizeof recv_buf,
                            data, icc_actual_length, &iccResult);
    if (r != 0){
        return r;
    }
    // check status code
    if (iccResult.data_status_code != 0x9000){
        return 1;
    }

    return 0;
}
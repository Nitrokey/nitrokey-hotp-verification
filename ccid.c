
#include <libusb.h>
#include "ccid.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "operations_ccid.h"

static const int READ_ENDPOINT = 0x81;

static const int WRITE_ENDPOINT = 0x01;

static const int TIMEOUT = 1000;


#include "min.h"
#include "tlv.h"
#include "base32.h"
#include "settings.h"
#include "utils.h"

uint32_t icc_compose(uint8_t *buf, uint32_t buffer_length, uint8_t msg_type, int32_t data_len, uint8_t slot, uint8_t seq, uint16_t param, uint8_t *data){
    static int _seq = 0;
    if (seq == 0){
        seq = _seq++;
    }

    size_t i = 0;
    buf[i++] = msg_type;

    buf[i++] = data_len << 0;
    buf[i++] = data_len << 8;
    buf[i++] = data_len << 16;
    buf[i++] = data_len << 24;

    buf[i++] = slot;
    buf[i++] = seq;
    buf[i++] = 0;
    buf[i++] = param << 0;
    buf[i++] = param << 8;
    const size_t final_data_length = min(data_len, buffer_length-i);
    memmove(buf + i, data, final_data_length);
    i += final_data_length;
    return i;
}


uint32_t iso7816_compose(uint8_t *buf, uint32_t buffer_length, uint8_t ins, uint8_t p1, uint8_t p2, uint8_t cls, uint8_t le,  uint8_t *data, uint8_t data_len){
    size_t i = 0;
    buf[i++] = cls;
    buf[i++] = ins;
    buf[i++] = p1;
    buf[i++] = p2;
    if (data != NULL && data_len != 0){
        buf[i++] = data_len;
        const size_t data_length = min(data_len, buffer_length-i-1);
        memmove(buf + i, data, data_length);
        i += data_length;
    }
    // TODO: check should "le" be included even if it is equal to 0
    if (le != 0){
        buf[i++] = le;
    }
    return i;
}


#define unused(x) ((void)(x))

IccResult parse_icc_result(uint8_t *buf, size_t buf_len) {
    assert (buf_len >= 10);
    unused(buf_len);
    const uint8_t data_len = buf[1] | (buf[2] << 8) | (buf[3] << 16) | (buf[4] << 24);
    // take last 2 bytes as the status code, if there is any data returned
    const uint16_t data_status_code = (data_len >= 2) ?
                                      be16toh(*(uint16_t *) &buf[10 + data_len - 2]) : 0;
    const IccResult i = {
            .status = buf[7],
            .chain = buf[9],
            .data = &buf[10],
            .data_len = data_len,
            .data_status_code = data_status_code,
//            .buffer = buf,
//            .buffer_len = buf_len
    };
    return i;
}

libusb_device_handle *get_device(libusb_context *ctx) {
    int r;
    libusb_device **devs;
    size_t count = libusb_get_device_list(ctx, &devs);
    if (count == 0) {
        printf("Error getting device list\n");
        return NULL;
    }


    libusb_device_handle *handle = NULL;
    for (size_t i = 0; i < count; i++) {
        libusb_device *dev = devs[i];
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(devs[i], &desc) >= 0) {
            printf("%x ", desc.idVendor);
            if (!(desc.idVendor == 0x20a0 && desc.idProduct == 0x42b2)) {
                continue;
            }
        }

        r = libusb_open(dev, &handle);
        if (r == LIBUSB_SUCCESS) {
            printf("open\n");
            break;
        } else {
            printf("Error opening device: %s\n", libusb_strerror(r));
        }
    }
    if (handle == NULL) {
        printf("No working device found");
        return NULL;
    }

    libusb_free_device_list(devs, 1);

    r = libusb_claim_interface(handle, 0);
    if (r < 0) {
        printf("Error claiming interface: %s\n", libusb_strerror(r));
        return NULL;
    }

    printf("set alt interface\n");
    r = libusb_set_interface_alt_setting(handle, 0, 0);
    if (r < 0) {
        printf("Error set alt interface: %s\n", libusb_strerror(r));
        return NULL;
    }

    return handle;
}


int ccid_process_single(libusb_device_handle *handle, uint8_t *buf, uint32_t buf_length, const uint8_t *d,
                        const uint32_t length, IccResult *result) {
    int actual_length = 0, r;

    r = ccid_send(handle, &actual_length, d, length);
    if (r != 0) {
        return r;
    }

    while (true) {
        r = ccid_receive(handle, &actual_length, buf, buf_length);
        if (r != 0) {
            return r;
        }

        IccResult iccResult = parse_icc_result(buf, buf_length);
        printf("status %d, chain %d\n", iccResult.status, iccResult.chain);
        if (iccResult.data_len > 0) {
            print_buffer(iccResult.data, iccResult.data_len, "    returned data");
            printf("Status code: %s\n", ccid_error_message(iccResult.data_status_code));
        }
        if (iccResult.data[0] == 0x61) { // 0x61 status code means data remaining, make another receive

            uint8_t buf_sr[512];
            uint32_t send_rem_length = iso7816_compose(buf_sr, sizeof buf_sr,
                                                  Ins_GetResponse, 0, 0, 0, 0xFF, NULL, 0);
            uint8_t buf_sr_2[512];
            uint32_t send_rem_icc_len = icc_compose(buf_sr_2, sizeof buf_sr_2,
                                               0x6F, send_rem_length,
                                               0, 0, 0, buf_sr);
            int actual_length_sr = 0;
            uint8_t buf_sr_recv[512];
            r = ccid_send(handle, &actual_length_sr, buf_sr_2, send_rem_icc_len);
            r = ccid_receive(handle, &actual_length_sr, buf_sr_recv, sizeof buf_sr_recv);
            iccResult = parse_icc_result(buf_sr_recv, sizeof buf_sr_recv);
            printf("status %d, chain %d\n", iccResult.status, iccResult.chain);
            if (iccResult.data_len > 0) {
                print_buffer(iccResult.data, iccResult.data_len, "    returned data");
                printf("Status code: %s\n", ccid_error_message(iccResult.data_status_code));
            }
        }
        if (iccResult.status == 0x80) continue;
        if (iccResult.chain == 0 || iccResult.chain == 2) {
            if (result != NULL) {
                memmove(result, &iccResult, sizeof iccResult);
            }
            break;
        }
        switch (iccResult.chain) {
            case 1:
            case 3:
                printf("Touch device if it blinks\n");
                continue;
            default:
                printf("Invalid value for chain: %d\n", iccResult.chain);
                return 1;
        }
    }
    return 0;
}

int ccid_process(libusb_device_handle *handle, uint8_t *buf, uint32_t buf_length, const uint8_t **data_to_send,
                 int data_to_send_count, const uint32_t *data_to_send_sizes, bool continue_on_errors,
                 IccResult *result) {
    int r;
    assert(buf != NULL);
    assert(buf_length >= 270);

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

    } // end for
    return 0;
}

int ccid_test() {
    libusb_context *ctx = NULL;
    int r = libusb_init(&ctx);
    if (r < 0) {
        printf("Error initializing libusb: %s\n", libusb_strerror(r));
        return 1;
    }

    libusb_device_handle *handle = get_device(ctx);
    if (handle == NULL){
        return 1;
    }

    unsigned char cmd_select[] = {
            0x6f, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00,
            0x05, 0x27, 0x21, 0x01,
    };

    unsigned char cmd_poweron[] = {
            0x62,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };

    unsigned char cmd_poweroff[] = {
            0x63,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };

    unsigned char cmd_info[] = {
            0x61,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };

    unsigned char cmd_reset[] = {
            0x6f,0x04,0x00,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x04,0xde,0xad,
    };

    const unsigned char *data_to_send[] = {
            cmd_select, cmd_poweron, cmd_poweroff, cmd_info, cmd_reset
    };

    const unsigned int data_to_send_size[] = {
            sizeof(cmd_select),
            sizeof(cmd_poweron),
            sizeof(cmd_poweroff),
            sizeof(cmd_info),
            sizeof(cmd_reset)
    };

    // FIXME set the proper CCID buffer length (270 was not enough)
    unsigned char buf[1024] = {};
    ccid_process(handle, buf, sizeof buf, data_to_send, 4, data_to_send_size, true, NULL);

    // always set the PIN; inform user beforehand that provided PIN will be used as the new one if not set
    // this will fail on the already set PIN
    r = set_pin_ccid(handle, "123123");
    check_r(
        authenticate_ccid(handle, "123123")
    );
//    r = set_secret_on_device_ccid(handle,
//                                  "ORSXG5AK" /*test*/, "123123", 0);

    r = set_secret_on_device_ccid(handle,
                                  "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" /*12345678901234567890*/, 0);



    printf("--------------------verify code\n");
    r = authenticate_ccid(handle, "123123"); // no need for auth by design for the revhotp check? WRONG!
    r = verify_code_ccid(handle, 755224);

    r = authenticate_ccid(handle, "123123");
    r = verify_code_ccid(handle, 287082);

    r = authenticate_ccid(handle, "123123");
    r = verify_code_ccid(handle, 520489);

    
    libusb_release_interface(handle, 0);
    libusb_close(handle);
    libusb_exit(ctx);

    return 0;
}

int icc_pack_tlvs_for_sending(uint8_t *buf, size_t buflen, TLV *tlvs, int tlvs_count, int ins) {
    uint8_t data_tlvs[1024] = {};
    int tlvs_actual_length = process_all(data_tlvs, tlvs, tlvs_count);

    // encode instruction
    uint8_t data_iso[1024] = {};
    uint32_t iso_actual_length = iso7816_compose(
            data_iso, sizeof data_iso,
            ins, 0, 0, 0, 0, data_tlvs, tlvs_actual_length);

    // encode ccid wrapper
    uint32_t icc_actual_length = icc_compose(buf, buflen,
                                             0x6F, iso_actual_length,
                                             0, 0, 0, data_iso);


    return icc_actual_length;
}

int ccid_receive(libusb_device_handle *device, int *actual_length, unsigned char *returned_data, int buffer_length) {
    int r = libusb_bulk_transfer(device, READ_ENDPOINT, returned_data, buffer_length, actual_length, TIMEOUT);
    if (r < 0) {
        printf("Error reading data: %s\n", libusb_strerror(r));
            return 1;
    }
    print_buffer(returned_data, (*actual_length), "recv");
    return 0;
}

int ccid_send(libusb_device_handle *device, int *actual_length, const unsigned char *data, const size_t length) {
    print_buffer(data, length, "sending");
    int r = libusb_bulk_transfer(device, WRITE_ENDPOINT, (uint8_t *) data, (int) length, actual_length, TIMEOUT);
    if (r < 0) {
        printf("Error sending data: %s\n", libusb_strerror(r));
        return 1;
    }
    return 0;
}

void print_buffer(const unsigned char *buffer, const uint32_t length, const char *message) {
    printf("%s ", message);
    for (uint32_t j = 0; j < length; ++j) {
        printf("%02x", buffer[j]);
    }
    printf("\n");
}



char *ccid_error_message(uint16_t status_code) {
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

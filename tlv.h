#ifndef NITROKEY_HOTP_VERIFICATION_TLV_H
#define NITROKEY_HOTP_VERIFICATION_TLV_H


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

#endif // NITROKEY_HOTP_VERIFICATION_TLV_H
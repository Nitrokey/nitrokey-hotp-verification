
#ifndef NITROKEY_HOTP_VERIFICATION_OPERATIONS_CCID_H
#define NITROKEY_HOTP_VERIFICATION_OPERATIONS_CCID_H

#include "device.h"
#include <libusb.h>

int set_pin_ccid(struct Device *dev, const char *admin_PIN);
int authenticate_ccid(struct Device *dev, const char *admin_PIN);
int authenticate_or_set_ccid(struct Device *dev, const char *admin_PIN);
int set_secret_on_device_ccid(struct Device *dev, const char *admin_PIN, const char *OTP_secret_base32, const uint64_t hotp_counter);
int verify_code_ccid(struct Device *dev, const uint32_t code_to_verify);
int status_ccid(libusb_device_handle *handle, struct FullResponseStatus *full_response);
int nk3_change_pin(struct Device *dev, const char *old_pin, const char *new_pin);
// new_pin can be `null`
//
// If it is, no new pin will be set
int nk3_reset(struct Device *dev, const char *new_pin);


#endif//NITROKEY_HOTP_VERIFICATION_OPERATIONS_CCID_H

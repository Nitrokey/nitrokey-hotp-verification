
#ifndef NITROKEY_HOTP_VERIFICATION_OPERATIONS_CCID_H
#define NITROKEY_HOTP_VERIFICATION_OPERATIONS_CCID_H

#include <libusb.h>

int set_pin_ccid(libusb_device_handle *handle, const char *admin_PIN);
int authenticate_ccid(libusb_device_handle *handle, const char *admin_PIN);
int set_secret_on_device_ccid(libusb_device_handle *handle, const char *OTP_secret_base32, const uint64_t hotp_counter);
int verify_code_ccid(libusb_device_handle *handle, const uint32_t code_to_verify);


#endif //NITROKEY_HOTP_VERIFICATION_OPERATIONS_CCID_H

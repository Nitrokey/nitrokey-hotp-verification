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
#include "operations.h"
#include "return_codes.h"
#include "utils.h"
#include "operations_ccid.h"
#include "version.h"
#include <stdio.h>
#include <string.h>

static struct Device dev = {};

int parse_cmd_and_run(int argc, char *const *argv);

void print_help(char *app_name) {
    printf("Available commands: \n"
           "\t%s id\n"
           "\t%s info\n"
           "\t%s version\n"
           "\t%s check <HOTP CODE>\n"
           "\t%s regenerate <ADMIN PIN>\n"
           "\t%s set <BASE32 HOTP SECRET> <ADMIN PIN> [COUNTER]\n"
           "\t%s nk3-change-pin <old-pin> <new-pin>\n",
           app_name, app_name, app_name, app_name, app_name, app_name, app_name);
}


int main(int argc, char *argv[]) {
    printf("HOTP code verification application, version %s\n", VERSION);

    int res;

    if (argc != 1 && argv[1][0] != 'v') {
        res = device_connect(&dev);
        if (res != RET_NO_ERROR) {
            printf("Could not connect to the device\n");
            return EXIT_CONNECTION_ERROR;
        }
    }

    res = parse_cmd_and_run(argc, argv);
    if (res != dev_ok && res != RET_NO_ERROR && res != RET_VALIDATION_PASSED && res != RET_VALIDATION_FAILED) {
        printf("Error occurred, status code %d: %s\n", res, res_to_error_string(res));
    } else {
        printf("%s\n", res_to_error_string(res));
    }

#ifdef _DEBUG
    if (res < dev_command_status_range && res != dev_ok) {
        printf("Device error: %s\n", command_status_to_string((uint8_t) res));
    }
#endif

    device_disconnect(&dev);

    res = res_to_exit_code(res);
    return res;
}

void print_card_serial(struct ResponseStatus *status) {
    if ((*status).card_serial_u32 != 0) {
        printf("0x%X\n", (*status).card_serial_u32);
    } else {
        printf("N/A\n");
    }
}

int parse_cmd_and_run(int argc, char *const *argv) {
    int res = RET_INVALID_PARAMS;
    if (argc > 1) {
        switch (argv[1][0]) {
            case 'v':
                printf("%s\n", VERSION);
                printf("%s\n", VERSION_GIT);
                res = RET_NO_ERROR;
                break;
            case 'i': {// id | info
                struct FullResponseStatus status;
                memset(&status, 0, sizeof (struct FullResponseStatus));

                res = device_get_status(&dev, &status);
                check_ret((res != RET_NO_ERROR) && (res != RET_NO_PIN_ATTEMPTS), res);
                if (strnlen(argv[1], 10) == 2 && argv[1][1] == 'd') {
                    // id command - print ID only
                    print_card_serial(&status.response_status);
                } else {
                    // info command - print status
                    printf("Connected device status:\n");
                    printf("\tCard serial: ");
                    print_card_serial(&status.response_status);
                    if (status.device_type == Nk3) {
                         printf("\tFirmware Nitrokey 3: v%d.%d.%d\n",
                               (status.nk3_extra_info.firmware_version >> 22) & 0b1111111111,
                               (status.nk3_extra_info.firmware_version >> 6) & 0xFFFF,
                               status.nk3_extra_info.firmware_version & 0b111111);
                        printf("\tFirmware Secrets App: v%d.%d\n",
                               status.response_status.firmware_version_st.major,
                               status.response_status.firmware_version_st.minor);
                        if (res != RET_NO_PIN_ATTEMPTS) {
                            printf("\tSecrets app PIN counter: %d\n",
                                   status.response_status.retry_user);
                        } else {
                            printf("\tSecrets app PIN counter: PIN is not set - set PIN before the first use\n");
                        }
                        printf("\tGPG Card counters: Admin %d, User %d\n",
                               status.nk3_extra_info.pgp_admin_pin_retries,
                               status.nk3_extra_info.pgp_user_pin_retries);
                    } else {
                        printf("\tFirmware: v%d.%d\n",
                               status.response_status.firmware_version_st.major,
                               status.response_status.firmware_version_st.minor);
                        if (res != RET_NO_PIN_ATTEMPTS) {
                            printf("\tCard counters: Admin %d, User %d\n",
                                   status.response_status.retry_admin, status.response_status.retry_user);
                        } else {
                            printf("\tCard counters: PIN is not set - set PIN before the first use\n");
                        }
                    }
                }
                if (res == RET_NO_PIN_ATTEMPTS) {
                    // Ignore if PIN is not set here
                    res = RET_NO_ERROR;
                }
            } break;
            case 'c':
                if (argc != 3) break;
                res = check_code_on_device(&dev, argv[2]);
                break;
            case 'n':
                if (strcmp(argv[1], "nk3-change-pin") != 0 || argc != 4) break;
                res = nk3_change_pin(&dev, argv[2], argv[3]);
                break;
            case 's':
                if (argc != 4 && argc != 5) break;
                {
                    uint64_t counter = 0;
                    if (argc == 5) {
                        counter = strtol10_s(argv[4]);
                    }
                    res = set_secret_on_device(&dev, argv[2], argv[3], counter);
                }
                break;
            case 'r':
                if (argc != 3) break;
                res = regenerate_AES_key(&dev, argv[2]);
                break;
            default:
                break;
        }
    }
    if (argc == 1) {
        print_help(argv[0]);
        res = RET_NO_ERROR;
    } else if (res == RET_INVALID_PARAMS) {
        print_help(argv[0]);
    }
    return res;
}

/*
 * Copyright (c) 2018 Nitrokey UG
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
 * along with Nitrokey App. If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "operations.h"
#include "version.h"
#include "command_id.h"
#include "return_codes.h"

struct Device dev;

int parse_cmd_and_run(int argc, char *const *argv);

void print_welcome(char* key_brand){
  printf("HOTP code verification application via %s, version %s\n", key_brand, VERSION);
}

void print_help(char* app_name) {
  printf("Available commands: \n"
         "\t%s id\n"
         "\t%s info\n"
         "\t%s version\n"
         "\t%s check <HOTP CODE>\n"
         "\t%s regenerate <ADMIN PIN>\n"
         "\t%s set <BASE32 HOTP SECRET> <ADMIN PIN> [COUNTER]\n",
         app_name, app_name, app_name, app_name, app_name, app_name);
}


int main(int argc, char* argv[]) {
  char *librem_exec = "libremkey";
  char *key_brand;
  if(strstr(argv[0], librem_exec) != NULL) {
    key_brand = "Librem Key";
  } else {
    key_brand = "Nitrokey";
  }
  print_welcome(key_brand);

  int res;

  if(argc != 1){
    res = device_connect(&dev, key_brand);
    if (res != true){
      printf("Could not connect with the %s device\n", key_brand);
      return EXIT_CONNECTION_ERROR;
    }
  }

  res = parse_cmd_and_run(argc, argv);
  if (res != dev_ok && res != RET_NO_ERROR && res != RET_VALIDATION_PASSED && res != RET_VALIDATION_FAILED){
    printf("Error occurred, status code %d: %s\n", res, res_to_error_string(res));
  } else {
    printf("%s\n", res_to_error_string(res));
  }

#ifdef _DEBUG
  if (res<dev_command_status_range && res!=dev_ok){
    printf("Device error: %s\n", command_status_to_string((uint8_t) res));
  }
#endif

  device_disconnect(&dev);

  res = res_to_exit_code(res);
  return res;
}

int parse_cmd_and_run(int argc, char *const *argv) {
  int res = RET_INVALID_PARAMS;
  if (argc > 1){
    switch (argv[1][0]) {
      case 'v':
        printf("%s\n", VERSION);
        printf("%s\n", VERSION_GIT);
        res = RET_NO_ERROR;
        break;
      case 'i': {
          struct ResponseStatus status = device_get_status(&dev);
          if (strnlen(argv[1], 10) == 2 && argv[1][1] == 'd'){
            printf("0x%X\n", status.card_serial_u32);
          } else {
            printf("Connected device status:\n \tCard serial: 0x%X\n\tFirmware: v%d.%d\n\tCard counters: Admin %d, User %d\n",
                   status.card_serial_u32, status.firmware_version_st.major, status.firmware_version_st.minor,
                   status.retry_admin, status.retry_user);
          }
          res = RET_NO_ERROR;
        }
        break;
      case 'c':
        if (argc != 3) break;
        res = check_code_on_device(&dev, argv[2]);
        break;
      case 's':
        if (argc != 4 && argc !=5 ) break;
        {
          uint64_t counter = 0;
          if (argc==5){
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
  if (argc == 1){
    print_help(argv[0]);
    res = RET_NO_ERROR;
  } else if (res == RET_INVALID_PARAMS){
    print_help(argv[0]);
  }
  return res;
}

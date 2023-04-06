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

#ifndef NITROKEY_HOTP_VERIFICATION_UTILS_H
#define NITROKEY_HOTP_VERIFICATION_UTILS_H

#include <stdio.h> // for printf for rassert
#include <stdlib.h> // for exit for rassert

#define STRINGIFY_HELPER(X) #X
#define STRINGIFY(X) STRINGIFY_HELPER(X)
#define rassert(x) if( !(x) ){ printf("Critical assertion failed: " STRINGIFY(x) "\n"); exit(1); }
#define check_ret(x, ret) if((x) != 0){ printf("Call failed: " STRINGIFY(x) "\n"); return (ret); }
#define LEN_ARR(x)  (sizeof(x) / sizeof (x[0]) )
#define unused(x) ((void)(x))

#ifndef NDEBUG
#define LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define LOG(...) do {} while (0)
#endif


#endif //NITROKEY_HOTP_VERIFICATION_UTILS_H

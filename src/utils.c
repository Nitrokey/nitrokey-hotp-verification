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

#include <inttypes.h>
#include <time.h>

int64_t millis() {
    struct timespec now;
    timespec_get(&now, TIME_UTC);
    return ((int64_t) now.tv_sec) * 1000 + ((int64_t) now.tv_nsec) / 1000000;
}

static int64_t g_milis = 0;
void stopwatch_start() {
    g_milis = millis();
}

int64_t stopwatch_stop() {
    return millis() - g_milis;
}

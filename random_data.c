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

#include "random_data.h"
#include <stdio.h>

size_t read_random_bytes_to_buf(uint8_t *out_buffer, size_t size) {
  FILE* random_source = fopen("/dev/urandom", "r");
  const size_t read = fread(out_buffer, sizeof(uint8_t), size, random_source);
  fclose(random_source);
  return read;
}
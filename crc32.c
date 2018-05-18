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

#include <stdint.h>
#include <stddef.h>
#include "crc32.h"

//taken from libnitrokey

uint32_t _crc32(uint32_t crc, uint32_t data) {
  int i;
  crc = crc ^ data;

  for (i = 0; i < 32; i++) {
    if (crc & 0x80000000)
      crc = (crc << 1) ^ 0x04C11DB7;  // polynomial used in STM32
    else
      crc = (crc << 1);
  }

  return crc;
}

uint32_t stm_crc32(const uint8_t *data, size_t size) {
  uint32_t crc = 0xffffffff;
  const uint32_t *pend = (const uint32_t *)(data + size);
  for (const uint32_t *p = (const uint32_t *)(data); p < pend; p++)
    crc = _crc32(crc, *p);
  return crc;
}
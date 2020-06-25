/*
 * Copyright (c) 2020 Nitrokey Gmbh
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

#include "catch.hpp"

extern "C" {
#include "../operations.h"
}


struct Device dev;


TEST_CASE("Test correct codes", "[HOTP]") {
  int res;
  res = device_connect(&dev);
  REQUIRE(res == true);
  res = regenerate_AES_key(&dev, "12345678");
  REQUIRE(res == RET_NO_ERROR);
  device_disconnect(&dev);
  REQUIRE(res == RET_NO_ERROR);
}

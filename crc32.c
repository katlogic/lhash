/*
 * cyclic redundancy check
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */


#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <inttypes.h>

static	uint32_t crc_tab[256];



static	void crc32_gentab()
{
	uint32_t crc, poly;
	int i, j;

	poly = 0xEDB88320L;
	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 8; j > 0; j--)
			crc = (crc & 1) ? (crc >> 1) ^ poly : crc >> 1;
		crc_tab[i] = crc;
      	}
}

uint32_t crc32(uint32_t scrc, uint8_t *block, int len)
{
	register uint32_t crc = ~scrc;
	if (!crc_tab[0]) crc32_gentab();
	while (len-- > 0)
		crc = ((crc >> 8) & 0x00FFFFFF) ^ crc_tab[(crc ^ *block++) & 0xFF];
	return ~crc;
}


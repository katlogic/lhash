/*
 * space-optimized md5 implementation
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

#include <string.h>
#include "lhash.h"

#define r1(x, y, z)	(z ^ (x & (y ^ z)))
#define r2(x, y, z)	r1(z, x, y)
#define r3(x, y, z)	(x ^ y ^ z)
#define r4(x, y, z)	(y ^ (x | ~z))

/* wouldn't approximating these save some space? .. 256 bytes */
u32	sinus[] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
	0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,
	0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9,
	0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
	0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/* offsets, round 1 excluded */
u8	offs[] = {
	1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,

	5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,

	0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
};

u8	shifts[] = {
	7, 12, 17, 22,

	5, 9, 14, 20,

	4, 11, 16, 23,

	6, 10, 15, 21
};

#define md5round(R, in, s) { \
	T = a + R(b, c, d) + (in); \
	a = d; \
	d = c; \
	c = b; \
	b = rol32(T, (s)) + b; \
}

static void md5_transform(u32 *hash, const u8 *data)
{
	int i;
	register u32 a, b, c, d, T;
#ifndef LITTLE_ENDIAN
	u32 in[MD5_BLOCK_WORDS];
	for (i = 0; i < MD5_BLOCK_WORDS; i++)
		in[i] = le2host(((u32 *)data)[i]);
#else
#define in ((u32 *)data)
#endif

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];

	for (i = 0; i < 16; i++)
		md5round(r1, in[i] + sinus[i], shifts[i&3]);
	for (i = 0; i < 16; i++)
		md5round(r2, in[offs[i]] + sinus[16+i], shifts[4+(i&3)]);
	for (i = 0; i < 16; i++)
		md5round(r3, in[offs[16+i]] + sinus[32+i], shifts[8+(i&3)]);
	for (i = 0; i < 16; i++)
		md5round(r4, in[offs[32+i]] + sinus[48+i], shifts[12+(i&3)]);
#undef in
	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
}

void md5_init(MD5 *mctx)
{
	u32 inits[] = {0x67452301,0xefcdab89,0x98badcfe,0x10325476};
	memcpy(mctx->hash, inits, sizeof(mctx->hash));
	mctx->count = 0;
}

void md5_update(MD5 *ctx, const void *data, unsigned int len)
{
	unsigned int inbuf = 0;

	inbuf = ctx->count & 63;
	ctx->count += len;

	if (inbuf+len >= 64) {
		if (inbuf) {
			int tocp = 64-inbuf;
			memcpy(ctx->buffer + inbuf, data, tocp);
			len -= tocp;
			data = ((u8 *)data) + tocp;
			md5_transform(ctx->hash, ctx->buffer);
			inbuf = 0;
		}
		for (;len >= 64; len -= 64, data = ((u8 *)data) + 64)
			md5_transform(ctx->hash, data);
	}
	memcpy(ctx->buffer + inbuf, data, len);
}

void md5_final(MD5 *ctx, u8 *out)
{
	static u8 padding[64];
	u32 bits[2];
	int pad;
#ifndef LITTLE_ENDIAN
	int i;
#endif

	padding[0] = 0x80;
	pad = (64-(ctx->count&63))-8;
	if (pad < 0)
		pad += 64;

	bits[0] = (ctx->count) << 3;
	bits[1] = (ctx->count) >> 29;
	md5_update(ctx, padding, pad);

	md5_update(ctx, (const u8 *) bits, 8);
#ifdef LITTLE_ENDIAN
	memcpy(out, ctx->hash, sizeof(ctx->hash));
#else
	for (i = 0; i < MD5_HASH_WORDS; i++) {
		((u32 *) out)[i] = host2le(ctx->hash[i]);
	}
#endif
}


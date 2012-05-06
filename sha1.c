/*
 * space-optimised sha1 implementation
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

#include "lhash.h"

#define sharound(trans) \
	{ t = (trans) + rol32(a, 5) + e + pre[i]; e = d; d = c; c = rol32(b, 30); b = a; a = t; }

static void sha_transform(u32 *digest, const u8 *in)
{
	u32 a, b, c, d, e, t, i;
	u32 pre[80];

	for (i = 0; i < 16; i++)
		pre[i] = host2be(((const u32 *)in)[i]);
	for (i = 0; i < 64; i++)
		pre[i+16] = rol32(pre[i+13] ^ pre[i+8] ^ pre[i+2] ^ pre[i], 1);
	

	a = digest[0];
	b = digest[1];
	c = digest[2];
	d = digest[3];
	e = digest[4];

	for (i = 0; i < 20; i++) sharound((d ^ (b & (c ^ d))) + 0x5A827999);
	for (; i < 40; i++) sharound((b ^ c ^ d) + 0x6ED9EBA1);
	for (; i < 60; i++) sharound(((b & c) + (d & (b ^ c))) + 0x8F1BBCDC);
	for (; i < 80; i++) sharound((b ^ c ^ d) + 0xCA62C1D6);

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
}

void sha1_init(SHA1 *ctx)
{
	static const u32 inits[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->state, inits, sizeof(inits));
}

void sha1_update(SHA1 *ctx, const void *data, unsigned int len)
{
	unsigned int inbuf;

	inbuf = ctx->count & 63;
	ctx->count += len;

	if (inbuf+len >= 64) {
		if (inbuf) {
			int tocp = 64-inbuf;
			memcpy(ctx->buffer + inbuf, data, tocp);
			len -= tocp;
			data = ((u8 *)data) + tocp;
			sha_transform(ctx->state, ctx->buffer);
			inbuf = 0;
		}
		for (;len >= 64; len -= 64, data = ((u8 *)data) + 64)
			sha_transform(ctx->state, data);
	}
	memcpy(ctx->buffer + inbuf, data, len);
}


void sha1_final(SHA1 *ctx, u8 *out)
{
	static u8 padding[64];
	u32 bits[2];
	int pad, i;

	padding[0] = 0x80;
	pad = (64-(ctx->count&63))-8;
	if (pad <= 0)
		pad += 64;


	bits[0] = host2be(ctx->count >> 29);
	bits[1] = host2be(ctx->count << 3);

	sha1_update(ctx, padding, pad);
	sha1_update(ctx, (const u8 *) bits, 8);
	for (i = 0; i < 5; i++)
		((u32 *) out)[i] = host2be(ctx->state[i]);
}


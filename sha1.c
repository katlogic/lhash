#define HASH_BITS 160
#define HASH_NAME sha1
#define HASH_FLAGS HASH_MD|HASH_PBKDF2|HASH_HMAC|HASH_INIT

#include "common.h"

static const uint32_t init[5] = {
	0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 
};

#define SHA1ROUND(trans) \
	{ t = (trans) + ROL32(a, 5) + e + tmp[i]; \
		e = d; d = c; c = ROL32(b, 30); b = a; a = t; }

static void transform(uint32_t *state, const uint8_t *in)
{
	uint32_t a, b, c, d, e, t, i;
	uint32_t tmp[80];

	/* expand */
	for (i = 0; i < 16; i++)
		tmp[i] = HOST2BE(((const uint32_t *)in)[i]);
	for (i = 0; i < 64; i++)
		tmp[i+16] = ROL32(tmp[i+13] ^ tmp[i+8] ^ tmp[i+2] ^ tmp[i], 1);

	/* compress */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	for (i = 0; i < 20; i++) SHA1ROUND((d ^ (b & (c ^ d))) + 0x5A827999);
	for (; i < 40; i++) SHA1ROUND((b ^ c ^ d) + 0x6ED9EBA1);
	for (; i < 60; i++) SHA1ROUND(((b & c) + (d & (b ^ c))) + 0x8F1BBCDC);
	for (; i < 80; i++) SHA1ROUND((b ^ c ^ d) + 0xCA62C1D6);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}

#define lua_binding luaopen_sha1
#define hash_name "sha1"
#include "common.c"


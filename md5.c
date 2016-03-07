#define HASH_BITS 128
#define HASH_NAME md5
#define HASH_FLAGS HASH_MD|HASH_HMAC|HASH_LE

#include "common.h"

static const uint32_t init[4] = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 
};

#define R1(x, y, z)	(z ^ (x & (y ^ z)))
#define R2(x, y, z)	R1(z, x, y)
#define R3(x, y, z)	(x ^ y ^ z)
#define R4(x, y, z)	(y ^ (x | ~z))

#define MD5ROUND(R, in, s) { \
	t = a + R(b, c, d) + (in); \
	a = d; \
	d = c; \
	c = b; \
	b = ROL32(t, (s)) + b; \
}

static void transform(uint32_t *state, const uint8_t *data)
{
	static const uint32_t	K[] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};

	static const uint8_t	offs[] = {
		1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
		5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
		0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
	};

	static const uint8_t	shifts[] = {
		7, 12, 17, 22,
		5, 9, 14, 20,
		4, 11, 16, 23,
		6, 10, 15, 21
	};


	int i;
	register uint32_t a, b, c, d, t;
	uint32_t in[16];

	for (i = 0; i < 16; i++)
		in[i] = LE2HOST(((uint32_t *)data)[i]);

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	for (i = 0; i < 16; i++)
		MD5ROUND(R1, in[i] + K[i], shifts[i&3]);
	for (i = 0; i < 16; i++)
		MD5ROUND(R2, in[offs[i]] + K[16+i], shifts[4+(i&3)]);
	for (i = 0; i < 16; i++)
		MD5ROUND(R3, in[offs[16+i]] + K[32+i], shifts[8+(i&3)]);
	for (i = 0; i < 16; i++)
		MD5ROUND(R4, in[offs[32+i]] + K[48+i], shifts[12+(i&3)]);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

#define lua_binding luaopen_md5
#define hash_name "md5"
#include "common.c"


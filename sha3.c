#define HASH_BITS 256 /* 224-512 */
#define HASH_NAME sha3
#define HASH_WORDS 25
#define HASH_UPDATE (200 - 2 * (HASH_BITS / 8))
#define HASH_FLAGS HASH_HMAC|HASH_LE|HASH_64

#include "common.h"

static void transform(uint64_t st[25], const uint8_t *in)
{
	static const uint8_t rho[24] = {
		1,  3,   6, 10, 15, 21,
		28, 36, 45, 55,  2, 14,
		27, 41, 56,  8, 25, 43,
		62, 18, 39, 61, 20, 44
	};

	static const uint8_t pi[24] = {
		10,  7, 11, 17, 18, 3,
		 5, 16,  8, 21, 24, 4,
		15, 23, 19, 13, 12, 2,
		20, 14, 22,  9, 6,  1
	};

	static const uint64_t rc[24] = {
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
		0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008
	};

	int i, j, round;
	uint64_t t, bc[5];

	for (i = 0; i < HASH_UPDATE/8; i++)
		st[i] ^= HOST2LE64(in[i]);

	for (round = 0; round < 24; round++) {
		for (i = 0; i < 5; i++)	 
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^
				st[i + 15] ^ st[i + 20];

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ ROL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				st[j + i] ^= t;
		}

		t = st[1];
		for (i = 0; i < 24; i++) {
			j = pi[i];
			bc[0] = st[j];
			st[j] = ROL64(t, rho[i]);
			t = bc[0];
		}

		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = st[j + i];
			for (i = 0; i < 5; i++)
				st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}

		st[0] ^= rc[round];
	}
}

static void final(struct sha3 *ctx, uint8_t *out)

{
	uint64_t tst[25];
	uint8_t tmp[HASH_UPDATE];
	size_t nrem = ctx->used;
	int i;

	memcpy(tst, ctx->state, sizeof tst);
	memcpy(tmp, ctx->buf, nrem);
	tmp[nrem++] = 1;
	memset(tmp + nrem, 0, HASH_UPDATE - nrem);
	tmp[HASH_UPDATE-1] ^= 0x80;
	transform(tst, tmp);
	for (i = 0; i < HASH_BITS/64; i++)
		((uint64_t*)out)[i] = HOST2LE64(tst[i]);
}

#define lua_binding luaopen_sha3
#define hash_name "sha3"
#include "common.c"


#define HASH_BITS 256
#define HASH_NAME sha256
#define HASH_FLAGS HASH_MD|HASH_PBKDF2|HASH_HMAC

#include "common.h"

static const uint32_t init[8] = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

#define R0(x)	(ROR((x),2) ^ ROR((x),13) ^ ROR((x),22))
#define R1(x)	(ROR((x),6) ^ ROR((x),11) ^ ROR((x),25))
#define R2(x)	(ROR((x),7) ^ ROR((x),18) ^ ((x)>>3))
#define R3(x)	(ROR((x),17) ^ ROR((x),19) ^ ((x)>>10))
#define R4(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
#define R5(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define ADVANCE { h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }

static void transform(uint32_t *state, const uint8_t *in)
{
	static const uint32_t K[] = {
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
		0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
		0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
		0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
		0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
		0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
		0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
		0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
		0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
	};


	uint32_t a,b,c,d,e,f,g,h,s0,s1,t1,t2;
	uint32_t tmp[16];
	int j;

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	/* expand */
	for (j = 0; j < 16; j++) {
		t1 = h + R1(e) + R4(e, f, g) + K[j] +
			(tmp[j] = HOST2BE(((const uint32_t*)(in))[j]));
		t2 = R0(a) + R5(a, b, c);
		ADVANCE;
	}

	/* compress */
	for (; j < 64; j++) {
		s0 = tmp[(j+1)&15];
		s0 = R2(s0);
		s1 = tmp[(j+14)&15];	
		s1 = R3(s1);
		t1 = h + R1(e) + R4(e, f, g) + K[j] + 
		     (tmp[j&15] += s1 + tmp[(j+9)&15] + s0);
		t2 = R0(a) + R5(a, b, c);
		ADVANCE;
	}
	state[0] = a;
	state[1] = b;
	state[2] = c;
	state[3] = d;
	state[4] = e;
	state[5] = f;
	state[6] = g;
	state[7] = h;
}

#define lua_binding luaopen_sha2
#define hash_name "sha2"
#include "common.c"


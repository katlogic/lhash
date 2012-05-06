#ifndef __LHASH_H_
#define __LHASH_H_

#include <stdint.h>
#include <sys/types.h>
#include <endian.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/time.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#define u8 uint8_t
#define u32 uint32_t
#define u64 uint64_t

#ifndef LITTLE_ENDIAN
#warning "untested endian"
#endif

/* SHA defs */
#define SHA1_DIGEST_SIZE	20
#define SHA1_HMAC_BLOCK_SIZE	64
typedef struct {
        u64 count;
        u32 state[5];
        u8 buffer[64];
} SHA1;
void sha1_init(SHA1 *ctx);
void sha1_update(SHA1 *ctx, const void *data, unsigned int len);
void sha1_final(SHA1 *ctx, u8 *out);


/* MD5 defs */
#define MD5_DIGEST_SIZE		16
#define MD5_BLOCK_WORDS		16
#define MD5_HASH_WORDS		4
typedef struct {
	u64 count;
	u32 hash[MD5_HASH_WORDS];
	u8 buffer[64];
} MD5;
void md5_init(MD5 *mctx);
void md5_update(MD5 *mctx, const void *data, unsigned int len);
void md5_final(MD5 *mctx, u8 *out);

/* RC4 defs */
typedef struct {
	int x, y;
	int m[256];
} RC4;
void rc4_setup(RC4 *ctx, const uint8_t *key, int len);
void rc4_crypt(RC4 * ctx, u8 *out, const u8 *buf, int len);

#define SHA256_BLOCK_LENGTH		64
#define SHA256_DIGEST_LENGTH		32
#define SHA256_DIGEST_STRING_LENGTH	(SHA256_DIGEST_LENGTH * 2 + 1)
#define SHA384_BLOCK_LENGTH		128
#define SHA384_DIGEST_LENGTH		48
#define SHA384_DIGEST_STRING_LENGTH	(SHA384_DIGEST_LENGTH * 2 + 1)
#define SHA512_BLOCK_LENGTH		128
#define SHA512_DIGEST_LENGTH		64
#define SHA512_DIGEST_STRING_LENGTH	(SHA512_DIGEST_LENGTH * 2 + 1)

#define SHA384_CTX SHA512_CTX

typedef struct _SHA256_CTX {
	uint32_t	state[8];
	uint64_t	bitcount;
	uint8_t	buffer[SHA256_BLOCK_LENGTH];
} SHA256_CTX;
typedef struct _SHA512_CTX {
	uint64_t	state[8];
	uint64_t	bitcount[2];
	uint8_t	buffer[SHA512_BLOCK_LENGTH];
} SHA512_CTX;

void SHA256_Init(SHA256_CTX *);
void SHA256_Update(SHA256_CTX*, const uint8_t*, size_t);
void SHA256_Final(uint8_t[SHA256_DIGEST_LENGTH], SHA256_CTX*);
char* SHA256_End(SHA256_CTX*, char[SHA256_DIGEST_STRING_LENGTH]);
char* SHA256_Data(const uint8_t*, size_t, char[SHA256_DIGEST_STRING_LENGTH]);

void SHA384_Init(SHA384_CTX*);
void SHA384_Update(SHA384_CTX*, const uint8_t*, size_t);
void SHA384_Final(uint8_t[SHA384_DIGEST_LENGTH], SHA384_CTX*);
char* SHA384_End(SHA384_CTX*, char[SHA384_DIGEST_STRING_LENGTH]);
char* SHA384_Data(const uint8_t*, size_t, char[SHA384_DIGEST_STRING_LENGTH]);

void SHA512_Init(SHA512_CTX*);
void SHA512_Update(SHA512_CTX*, const uint8_t*, size_t);
void SHA512_Final(uint8_t[SHA512_DIGEST_LENGTH], SHA512_CTX*);
char* SHA512_End(SHA512_CTX*, char[SHA512_DIGEST_STRING_LENGTH]);
char* SHA512_Data(const uint8_t*, size_t, char[SHA512_DIGEST_STRING_LENGTH]);

uint32_t crc32(uint32_t scrc, uint8_t *block, int len);
void	rand_bytes(u8 *buf, int count);

#define swap_endian(x) (((x<<24)&0xff000000)|((x<<8)&0x00ff0000)| \
			((x>>24)&0x000000ff)|((x>>8)&0x0000ff00))
#ifdef LITTLE_ENDIAN
#define host2le(x) (x)
#define host2be(x) swap_endian((x))
#define le2host(x) (x)
#define be2host(x) swap_endian((x))
#else
#define host2be(x) (x)
#define host2le(x) swap_endian((x))
#define be2host(x) (x)
#define le2host(x) swap_endian((x))
#endif

#define rol32(w, s) (((w) << (s)) | ((w) >> (32 - (s))))
#define ror32(w, s) (((w) >> (s)) | ((w) << ((s))))

#endif



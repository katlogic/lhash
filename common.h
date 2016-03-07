#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdint.h>
#include <string.h>

#define HASH_HMAC 	1
#define HASH_MD 	2
#define HASH_LE	 	4
#define HASH_PBKDF2	8
#define HASH_64 	16
#define HASH_INIT 	32

#if (HASH_FLAGS) & HASH_64
#define HASH_WORD 	uint64_t
#define HASH_WORDBITS 	64
#else
#define HASH_WORD 	uint32_t
#define HASH_WORDBITS 	32
#endif

#ifndef HASH_WORDS
#define HASH_WORDS 	(HASH_BITS / HASH_WORDBITS)
#endif

#define HASH_BYTES 	(HASH_BITS / 8)

#if (HASH_FLAGS) & HASH_MD
#define HASH_UPDATE 	64
#endif

struct HASH_NAME {
	HASH_WORD 	state[HASH_WORDS];
	uint64_t 	total;
	uint32_t 	used;
	uint8_t 	buf[HASH_UPDATE];
};


#define ROL32(w, s) (((w) << (s)) | ((w) >> (32 - (s))))
#define ROL64(w, s) (((w) << (s)) | ((w) >> (64 - (s))))
#define ROR32(w, s) (((w) >> (s)) | ((w) << (32 - (s))))

#if defined(__GNUC__) || defined(__clang__)
#define SWAP_ENDIAN(x) __builtin_bswap32(x)
#define SWAP_ENDIAN64(x) __builtin_bswap64(x);
#else
#define SWAP_ENDIAN(x) (((x<<24)&0xff000000)|((x<<8)&0x00ff0000)| \
			((x>>24)&0x000000ff)|((x>>8)&0x0000ff00))
#define SWAP_ENDIAN64(x) \
	(x >> 56) | \
	((x >> 40) & 0x000000000000FF00ULL) | \
	((x >> 24) & 0x0000000000FF0000ULL) | \
	((x >>  8) & 0x00000000FF000000ULL) | \
	((x <<  8) & 0x000000FF00000000ULL) | \
	((x << 24) & 0x0000FF0000000000ULL) | \
	((x << 40) & 0x00FF000000000000ULL) | \
	(x << 56)
#endif
#ifdef LITTLE_ENDIAN
#define HOST2LE(x) (x)
#define HOST2LE64(x) (x)
#define HOST2BE(x) SWAP_ENDIAN((x))
#define HOST2BE64(x) SWAP_ENDIAN64((x))
#define LE2HOST(x) (x)
#define LE2HOST64(x) (x)
#define BE2HOST(x) SWAP_ENDIAN((x))
#define BE2HOST64(x) SWAP_ENDIAN64((x))
#else
#define HOST2BE(x) (x)
#define HOST2BE64(x) (x)
#define HOST2LE(x) SWAP_ENDIAN((x))
#define HOST2LE64(x) SWAP_ENDIAN64((x))
#define BE2HOST(x) (x)
#define BE2HOST64(x) (x)
#define LE2HOST(x) SWAP_ENDIAN((x))
#define LE2HOST64(x) SWAP_ENDIAN((x))
#endif

#if (HASH_FLAGS) & HASH_LE
#define HOST2HASH(x) HOST2LE(x)
#define HOST2HASH64(x) HOST2LE64(x)
#else
#define HOST2HASH(x) HOST2BE(x)
#define HOST2HASH64(x) HOST2BE64(x)
#endif

#if LUA_VERSION_NUM < 502
#define luaL_setfuncs(L, reg, nup) luaL_openlib(L, NULL, reg, nup)
#endif

#define LUA_EXPORT(n) \
	int luaopen_##n(lua_State *L) { return lua_binding(L); } \
	int luaopen_lhash_##n(lua_State *L) { return lua_binding(L); };


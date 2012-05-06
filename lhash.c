#include "lhash.h"

#define METHOD(m) static int m(lua_State *L)
#define checkudata(name) luaL_checkudata(L, 1, name)

#define	SHA1STATE	"lhash.sha1*"
#define	SHA256STATE	"lhash.sha256*"
#define	SHA384STATE	"lhash.sha384*"
#define	SHA512STATE	"lhash.sha512*"
#define	MD5STATE	"lhash.md5*"

static	inline	void *lnewdata(lua_State *L, const char *name, int size)
{
	void *p = lua_newuserdata(L, size);
	luaL_getmetatable(L, name);
	lua_setmetatable(L, -2);
	return p;
}

static	inline void * lznewdata(lua_State *L, const char *name, int size)
{
	void *p = lnewdata(L, name, size);
	memset(p, 0, size);
	return p;
}
#define newdata(name,size) lnewdata(L,name,size)
#define newzdata(name,size) lznewdata(L,name,size)


/*************************************************************************
 * hmac api implementations
 **************************************************************************/
METHOD(hmac64_api)
{
	char ipad[64], opad[64];
	int i;
	size_t keyl;
	const char *key = luaL_checklstring(L, 1, &keyl);
	if (keyl > 64)
		luaL_argerror(L, 2, "key may be no longer than 64");
	for (i = 0; i < keyl; i++) {
		ipad[i] = key[i] ^ 0x36;
		opad[i] = key[i] ^ 0x5c;
	}
	memset(ipad + i, 0x36, 64 - i);
	memset(opad + i, 0x5c, 64 - i);
	lua_pushlstring(L, ipad, 64);
	lua_pushlstring(L, opad, 64);
	return 2;
}
METHOD(hmac128_api)
{
	char ipad[128], opad[128];
	int i;
	size_t keyl;
	const char *key = luaL_checklstring(L, 1, &keyl);
	if (keyl > 128)
		luaL_argerror(L, 2, "key may be no longer than 128");
	for (i = 0; i < keyl; i++) {
		ipad[i] = key[i] ^ 0x36;
		opad[i] = key[i] ^ 0x5c;
	}
	memset(ipad + i, 0x36, 128 - i);
	memset(opad + i, 0x5c, 128 - i);
	lua_pushlstring(L, ipad, 128);
	lua_pushlstring(L, opad, 128);
	return 2;
}

/*************************************************************************
 * sha1 api implementations
 **************************************************************************/
METHOD(sha1_api)
{
	size_t l;
	const char *s = lua_tolstring(L, 1, &l);
	SHA1 *c;
	if (s) {
		SHA1 ctx;
		u8 digest[SHA1_DIGEST_SIZE];
		sha1_init(&ctx);
		sha1_update(&ctx, s, l);
		sha1_final(&ctx, digest);
		lua_pushlstring(L, (char*) digest, SHA1_DIGEST_SIZE);
		return 1;
	}
	c = newzdata(SHA1STATE, sizeof(SHA1));
	sha1_init(c);
	return 1;
}

METHOD(clone_sha1)
{
	SHA1 *ctx = checkudata(SHA1STATE);
	memcpy(newdata(SHA1STATE, sizeof(*ctx)), ctx, sizeof(*ctx));
	return 1;
}


METHOD(update_sha1)
{
	SHA1 *ctx = checkudata(SHA1STATE);
	size_t l;
	const char *buf = luaL_checklstring(L, 2, &l);
	unsigned start = luaL_optint(L, 3, 0);
	unsigned len = luaL_optint(L, 4, l);
	if (start > l)
		start = l;
	if (start + len > l)
		len = l - start;
	sha1_update(ctx, buf + start, len);
	lua_settop(L, 1);
	return 1;
}

METHOD(final_sha1)
{
	SHA1 *ctx = checkudata(SHA1STATE);
	u8 buf[SHA1_DIGEST_SIZE];
	size_t fsl;
	const char *fs = lua_tolstring(L, 2, &fsl);
	if (fs) sha1_update(ctx, fs, fsl);
	sha1_final(ctx, buf);
	sha1_init(ctx);
	lua_pushlstring(L, (char*)buf, SHA1_DIGEST_SIZE);
	return 1;
}
METHOD(reset_sha1)
{
	SHA1 *ctx = checkudata(SHA1STATE);
	sha1_init(ctx);
	lua_settop(L, 1);
	return 1;
}


/*************************************************************************
 * sha256 api implementations
 **************************************************************************/
METHOD(sha256_api)
{
	size_t l;
	const char *s = lua_tolstring(L, 1, &l);
	SHA256_CTX *c;
	if (s) {
		SHA256_CTX ctx;
		u8 digest[SHA256_DIGEST_LENGTH];
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, (u8*)s, l);
		SHA256_Final(digest, &ctx);
		lua_pushlstring(L, (char*) digest, SHA256_DIGEST_LENGTH);
		return 1;
	}
	c = newzdata(SHA256STATE, sizeof(SHA256_CTX));
	SHA256_Init(c);
	return 1;
}

METHOD(clone_sha256)
{
	SHA256_CTX *ctx = checkudata(SHA256STATE);
	memcpy(newdata(SHA256STATE, sizeof(SHA256_CTX)), ctx, sizeof(*ctx));
	return 1;
}

METHOD(update_sha256)
{
	SHA256_CTX *ctx = checkudata(SHA256STATE);
	size_t l;
	const char *buf = luaL_checklstring(L, 2, &l);
	unsigned start = luaL_optint(L, 3, 0);
	unsigned len = luaL_optint(L, 4, l);
	if (start > l)
		start = l;
	if (start + len > l)
		len = l - start;
	SHA256_Update(ctx, (u8*)(buf + start), len);
	lua_settop(L, 1);
	return 1;
}

METHOD(final_sha256)
{
	SHA256_CTX *ctx = checkudata(SHA256STATE);
	u8 buf[SHA256_DIGEST_LENGTH];
	size_t fsl;
	const char *fs = lua_tolstring(L, 2, &fsl);
	if (fs) SHA256_Update(ctx, (u8*)fs, fsl);
	SHA256_Final(buf, ctx);
	SHA256_Init(ctx);
	lua_pushlstring(L, (char*)buf, SHA256_DIGEST_LENGTH);
	return 1;
}

METHOD(reset_sha256)
{
	SHA256_CTX *ctx = checkudata(SHA256STATE);
	SHA256_Init(ctx);
	lua_settop(L, 1);
	return 1;
}

/*************************************************************************
 * sha384 api implementations
 **************************************************************************/
METHOD(sha384_api)
{
	size_t l;
	const char *s = lua_tolstring(L, 1, &l);
	SHA384_CTX *c;
	if (s) {
		SHA384_CTX ctx;
		u8 digest[SHA384_DIGEST_LENGTH];
		SHA384_Init(&ctx);
		SHA384_Update(&ctx, (u8*)s, l);
		SHA384_Final(digest, &ctx);
		lua_pushlstring(L, (char*) digest, SHA384_DIGEST_LENGTH);
		return 1;
	}
	c = newzdata(SHA384STATE, sizeof(SHA384_CTX));
	SHA384_Init(c);
	return 1;
}

METHOD(clone_sha384)
{
	SHA384_CTX *ctx = checkudata(SHA384STATE);
	memcpy(newdata(SHA384STATE, sizeof(SHA384_CTX)), ctx, sizeof(*ctx));
	return 1;
}

METHOD(update_sha384)
{
	SHA384_CTX *ctx = checkudata(SHA384STATE);
	size_t l;
	const char *buf = luaL_checklstring(L, 2, &l);
	unsigned start = luaL_optint(L, 3, 0);
	unsigned len = luaL_optint(L, 4, l);
	if (start > l)
		start = l;
	if (start + len > l)
		len = l - start;
	SHA384_Update(ctx, (u8*)(buf + start), len);
	lua_settop(L, 1);
	return 1;
}

METHOD(final_sha384)
{
	SHA384_CTX *ctx = checkudata(SHA384STATE);
	u8 buf[SHA384_DIGEST_LENGTH];
	size_t fsl;
	const char *fs = lua_tolstring(L, 2, &fsl);
	if (fs) SHA384_Update(ctx, (u8*)fs, fsl);
	SHA384_Final(buf, ctx);
	SHA384_Init(ctx);
	lua_pushlstring(L, (char*)buf, SHA384_DIGEST_LENGTH);
	return 1;
}

METHOD(reset_sha384)
{
	SHA384_CTX *ctx = checkudata(SHA384STATE);
	SHA384_Init(ctx);
	lua_settop(L, 1);
	return 1;
}

/*************************************************************************
 * sha512 api implementations
 **************************************************************************/
METHOD(sha512_api)
{
	size_t l;
	const char *s = lua_tolstring(L, 1, &l);
	SHA512_CTX *c;
	if (s) {
		SHA512_CTX ctx;
		u8 digest[SHA512_DIGEST_LENGTH];
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, (u8*)s, l);
		SHA512_Final(digest, &ctx);
		lua_pushlstring(L, (char*) digest, SHA512_DIGEST_LENGTH);
		return 1;
	}
	c = newzdata(SHA512STATE, sizeof(SHA512_CTX));
	SHA512_Init(c);
	return 1;
}

METHOD(clone_sha512)
{
	SHA512_CTX *ctx = checkudata(SHA512STATE);
	memcpy(newdata(SHA512STATE, sizeof(SHA512_CTX)), ctx, sizeof(*ctx));
	return 1;
}

METHOD(update_sha512)
{
	SHA512_CTX *ctx = checkudata(SHA512STATE);
	size_t l;
	const char *buf = luaL_checklstring(L, 2, &l);
	unsigned start = luaL_optint(L, 3, 0);
	unsigned len = luaL_optint(L, 4, l);
	if (start > l)
		start = l;
	if (start + len > l)
		len = l - start;
	SHA512_Update(ctx, (u8*)(buf + start), len);
	lua_settop(L, 1);
	return 1;
}

METHOD(final_sha512)
{
	SHA512_CTX *ctx = checkudata(SHA512STATE);
	u8 buf[SHA512_DIGEST_LENGTH];
	size_t fsl;
	const char *fs = lua_tolstring(L, 2, &fsl);
	if (fs) SHA512_Update(ctx, (u8*)fs, fsl);
	SHA512_Final(buf, ctx);
	SHA512_Init(ctx);
	lua_pushlstring(L, (char*)buf, SHA512_DIGEST_LENGTH);
	return 1;
}

METHOD(reset_sha512)
{
	SHA512_CTX *ctx = checkudata(SHA512STATE);
	SHA512_Init(ctx);
	lua_settop(L, 1);
	return 1;
}



/*************************************************************************
 * md5 api implementations
 **************************************************************************/
METHOD(md5_api)
{
	size_t l;
	const char *s = lua_tolstring(L, 1, &l);
	MD5 *c;
	if (s) {
		MD5 ctx;
		u8 digest[MD5_DIGEST_SIZE];
		md5_init(&ctx);
		md5_update(&ctx, s, l);
		md5_final(&ctx, digest);
		lua_pushlstring(L, (char*) digest, MD5_DIGEST_SIZE);
		return 1;
	}
	c = newzdata(MD5STATE, sizeof(MD5));
	md5_init(c);
	return 1;
}

METHOD(clone_md5)
{
	MD5 *ctx = checkudata(MD5STATE);
	memcpy(newdata(MD5STATE, sizeof(*ctx)), ctx, sizeof(*ctx));
	return 1;
}


METHOD(update_md5)
{
	MD5 *ctx = checkudata(MD5STATE);
	size_t l;
	const char *buf = luaL_checklstring(L, 2, &l);
	unsigned start = luaL_optint(L, 3, 0);
	unsigned len = luaL_optint(L, 4, l);
	if (start > l)
		start = l;
	if (start + len > l)
		len = l - start;
	md5_update(ctx, buf + start, len);
	lua_settop(L, 1);
	return 1;
}

METHOD(final_md5)
{
	MD5 *ctx = checkudata(MD5STATE);
	u8 buf[MD5_DIGEST_SIZE];
	size_t fsl;
	const char *fs = lua_tolstring(L, 2, &fsl);
	if (fs) md5_update(ctx, fs, fsl);
	md5_final(ctx, buf);
	md5_init(ctx);
	lua_pushlstring(L, (char*)buf, MD5_DIGEST_SIZE);
	return 1;
}

METHOD(reset_md5)
{
	MD5 *ctx = checkudata(MD5STATE);
	md5_init(ctx);
	lua_settop(L, 1);
	return 1;
}


/*************************************************************************
 * crc32/random api implementations
 **************************************************************************/
METHOD(crc_api)
{
	size_t l;
	u32 i = lua_tointeger(L, 1);
	const char *msg = luaL_checklstring(L, 2, &l);
	int off = luaL_optint(L, 3, 0);
	size_t len = luaL_optint(L, 4, l);
	if (off + len > l)
		len = l - off;
	lua_pushinteger(L, crc32(i, (u8*) msg + off, len));
	return 1;
}

METHOD(random_api)
{
	u32 u;
	if (lua_isnumber(L, 1)) {
		int	n = lua_tonumber(L, 1);
		u8	buf[n];
		rand_bytes(buf, n);
		lua_pushlstring(L, (char*) buf, n);
		return 1;
	}
	rand_bytes((void*)&u, sizeof(u));
	lua_pushinteger(L, u);
	return 1;
}


static luaL_reg sha1_meth[] = {
	{ "update", update_sha1 },
	{ "clone", clone_sha1 },
	{ "final", final_sha1 },
	{ "reset", reset_sha1 },
	{ NULL, NULL }
};
static luaL_reg sha256_meth[] = {
	{ "update", update_sha256 },
	{ "clone", clone_sha256 },
	{ "final", final_sha256 },
	{ "reset", reset_sha256 },
	{ NULL, NULL }
};
static luaL_reg sha384_meth[] = {
	{ "update", update_sha384 },
	{ "clone", clone_sha384 },
	{ "final", final_sha384 },
	{ "reset", reset_sha384 },
	{ NULL, NULL }
};
static luaL_reg sha512_meth[] = {
	{ "update", update_sha512 },
	{ "clone", clone_sha512 },
	{ "final", final_sha512 },
	{ "reset", reset_sha512 },
	{ NULL, NULL }
};

static luaL_reg md5_meth[] = {
	{ "update", update_md5 },
	{ "clone", clone_md5 },
	{ "final", final_md5 },
	{ "reset", reset_md5 },
	{ NULL, NULL }
};


static luaL_reg lhash_api[] = {
	{ "sha1", sha1_api },
	{ "sha256", sha256_api },
	{ "sha384", sha384_api },
	{ "sha512", sha512_api },
	{ "hmac64", hmac64_api },
	{ "hmac128", hmac128_api },
	{ "md5", md5_api },
	{ "crc32", crc_api },
	{ "random", random_api },
	{ NULL, NULL }
};

static	void register_meth(lua_State *L, const char *mn, luaL_reg *tab)
{
	luaL_newmetatable(L, mn);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_register(L, NULL, tab);
}

int luaopen_lhash(lua_State *L)
{
	register_meth(L, SHA1STATE, sha1_meth);
	register_meth(L, SHA256STATE, sha256_meth);
	register_meth(L, SHA384STATE, sha384_meth);
	register_meth(L, SHA512STATE, sha512_meth);
	register_meth(L, MD5STATE, md5_meth);

	luaL_register(L, "lhash", lhash_api);
	return 0;
}



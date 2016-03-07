static void update(struct HASH_NAME *ctx, const uint8_t *in, size_t len)
{
	while (len) {
		int room = HASH_UPDATE - ctx->used;
		if (room > 0) {
			if (room > len)
				room = len;
			memcpy(ctx->buf + ctx->used, in, room);
			in += room;
			ctx->used += room;
			ctx->total += room;
			len -= room;
		}
		if (ctx->used == HASH_UPDATE) {
			transform(ctx->state, ctx->buf);
			ctx->used = 0;
		}
	}
}

static void reset(struct HASH_NAME *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
#if (HASH_FLAGS) & HASH_INIT
	{
	int i;
	for (i = 0; i < HASH_WORDS; i++)
		ctx->state[i] = init[i];
	}
#endif
}

#if (HASH_FLAGS) & HASH_MD
static void final(struct HASH_NAME *ctx, uint8_t *out)
{
	uint8_t buf[HASH_UPDATE];
	uint32_t i, used = ctx->used;
	HASH_WORD state[HASH_WORDS];
	memcpy(buf, ctx->buf, HASH_UPDATE);
	memcpy(state, ctx->state, sizeof(state));
	buf[used++] = 0x80;
	if (used <= (HASH_UPDATE-8)) {
		memset(buf + used, 0, (HASH_UPDATE-8)-used);
	} else {
		memset(buf + used, 0, HASH_UPDATE-used);
		transform(state, buf);
		memset(buf, 0, HASH_UPDATE-8);

	}
	*((uint64_t*)(buf+HASH_UPDATE-8)) = HOST2HASH64(ctx->total<<3);
	transform(state, buf);
	for (i = 0; i < HASH_WORDS; i++)
		((HASH_WORD*)(out))[i] = HOST2HASH(state[i]);
}
#endif

static struct HASH_NAME *toctx(lua_State *L, int idx)
{
	void *d = lua_touserdata(L, idx);
	if (d) {
		if (lua_getmetatable(L, idx)) {
			if (!lua_rawequal(L, -1, lua_upvalueindex(1)))
				d = NULL;
			lua_pop(L, 1);
		} else d = NULL;
	}
	if (!d)
		luaL_argerror(L, idx, "expected " hash_name " object");
	return d;
}

static void do_updates(lua_State *L, struct HASH_NAME *ctx, int from, int to)
{
	int i;
	for (i = from; i <= to; i++) {
		size_t l;
		const char *s = luaL_checklstring(L, i, &l);
		update(ctx, (const uint8_t*)s, l);
	}
}

static void do_hmac(struct HASH_NAME *ctx, const uint8_t *key, size_t keysz,
		const uint8_t *data, size_t datasz)
{
	int i;
	uint8_t ikey[HASH_UPDATE], okey[HASH_UPDATE];
	uint8_t buf[HASH_UPDATE] = {0};
	reset(ctx);
	if (keysz > HASH_UPDATE) {
		update(ctx, (const uint8_t*)key, keysz);
		final(ctx, buf);
		reset(ctx);
	} else {
		memcpy(buf, key, keysz);
	}
	for (i = 0; i < HASH_UPDATE; i++) {
		okey[i] = buf[i] ^ 0x5c;
		ikey[i] = buf[i] ^ 0x36;
	}
	update(ctx, ikey, HASH_UPDATE);
	update(ctx, (const uint8_t*)data, datasz);
	final(ctx, buf);
	reset(ctx);
	update(ctx, okey, HASH_UPDATE);
	update(ctx, buf, HASH_BYTES);
}

#if (HASH_FLAGS) & HASH_HMAC
static int m_hmac(lua_State *L)
{
	struct HASH_NAME *ctx = toctx(L, 1);
	size_t keysz, datasz;
	const char *key = luaL_checklstring(L, 2, &keysz);
	const char *data = luaL_checklstring(L, 3, &datasz);
	do_hmac(ctx, (const uint8_t*)key, keysz, (const uint8_t*)data, datasz);
	lua_settop(L, 1);
	return 1;
}
#endif


static int m_create(lua_State *L)
{
	struct HASH_NAME *ctx = lua_newuserdata(L, sizeof(struct HASH_NAME));
	reset(ctx);
	lua_pushvalue(L, lua_upvalueindex(1));
	lua_setmetatable(L, -2);
	do_updates(L, ctx, 1, lua_gettop(L)-1);
	return 1;
}

static int m_clone(lua_State *L)
{
	struct HASH_NAME *nctx, *ctx = toctx(L, 1);
	nctx = lua_newuserdata(L, sizeof(struct HASH_NAME));
	*nctx = *ctx;
	lua_pushvalue(L, lua_upvalueindex(1));
	lua_setmetatable(L, -2);
	do_updates(L, nctx, 2, lua_gettop(L)-1);
	return 1;
}

static int m_reset(lua_State *L)
{
	struct HASH_NAME *ctx = toctx(L, 1);
	reset(ctx);
	do_updates(L, ctx, 2, lua_gettop(L));
	lua_settop(L, 1);
	return 1;
}

static int m_update(lua_State *L)
{
	struct HASH_NAME *ctx = toctx(L, 1);
	do_updates(L, ctx, 2, lua_gettop(L));
	lua_settop(L, 1);
	return 1;
}

static int m_digest(lua_State *L)
{
	struct HASH_NAME *ctx = toctx(L, 1);
	uint8_t buf[HASH_BYTES];
	do_updates(L, ctx, 2, lua_gettop(L));
	final(ctx, buf);
	lua_pushlstring(L, (const char*)buf, sizeof buf);
	return 1;
}

static int m_hexdigest(lua_State *L)
{
	static const char tab[16] = "0123456789abcdef";
	struct HASH_NAME *ctx = toctx(L, 1);
	uint8_t buf[HASH_BYTES];
	char buf2[HASH_BYTES*2+1];
	int i;
	do_updates(L, ctx, 2, lua_gettop(L));
	final(ctx, buf);
	for (i = 0; i < HASH_BYTES; i++) {
		buf2[i*2] = tab[buf[i]/16];
		buf2[i*2+1] = tab[buf[i]%16];
	}
	buf2[HASH_BYTES*2] = 0;
	lua_pushlstring(L, buf2, HASH_BYTES*2);
	return 1;
}

static const luaL_Reg 	methods[] = {
	{"clone", 	m_clone},
	{"reset", 	m_reset},
	{"update", 	m_update},
	{"digest", 	m_digest},
	{"hexdigest", 	m_hexdigest},
	{"hex", 	m_hexdigest},
#if (HASH_FLAGS) & HASH_HMAC
	{"hmac", 	m_hmac},
#endif
	{NULL, 		NULL}
};


static int lua_binding(lua_State *L)
{
	lua_newtable(L);
	lua_pushvalue(L, -1);
	luaL_setfuncs(L, methods, 1);

	lua_pushvalue(L, -1);
	lua_setmetatable(L, -2);

	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");

	lua_pushcclosure(L, m_create, 1);
	return 1;
}

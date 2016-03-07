static void update(struct HASH_NAME *ctx, const uint8_t *in, size_t len)
{
	while (len) {
		int room = HASH_UPDATE - ctx->used;
		if (room > 0) {
			if (room > len)
				room = len;
			memcpy(ctx->buf + ctx->used, in, room);
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

#if (HASH_FLAGS) & HASH_MD
static void final(struct sha3 *ctx, uint8_t *out)
{
	uint32_t bits[2];
	static uint8_t padding[HASH_UPDATE] = {0x80};
	struct HASH_NAME tmp = *ctx;
	int pad = (HASH_UPDATE-ctx->used)-8;
	if (pad <= 0)
		pad += HASH_UPDATE;
	bits[0] = HOST2HASH(ctx->total>>29);
	bits[1] = HOST2HASH(ctx->total<<3);
	update(&tmp, padding, pad);
	update(&tmp, bits, 8);
	for (i = 0; i < HASH_WORDS; i++)
		((HASH_WORD*)(out))[i] = HOST2HASH(tmp.state[i]);
}
#endif

static struct HASH_NAME *toctx(lua_State *L, int idx)
{
	void *d = lua_touserdata(L, idx);
	if (d) {
		if (lua_getmetatable(L, idx)) {
			if (!lua_rawequal(L, lua_upvalueindex(1)))
				d = NULL;
			lua_pop(L, 1);
		} else d = NULL;
	}
	if (!d)
		luaL_argerror(L, idx, "expected " hash_name " object");
	return d;
}

static void do_updates(lua_State *L, int from, int to)
{
	int i;
	for (i = from; i <= to; i++) {
		size_t l;
		const char *s = luaL_checklstring(L, i, &l);
		update(ctx, (const uint8_t*)s, l);
	}
}

#if (HASH_FLAGS) & HASH_HMAC
static int m_hmac(lua_State *L)
{
	struct HASH_NAME *nctx, *ctx = toctx(L, 1);
	uint8_t buf[HASH_UPDATE] = {0};
	uint8_t ikey[HASH_UPDATE], okey[HASH_UPDATE];
	size_t keysz, datasz;
	const char *key = luaL_checklstring(L, 2, &sz);
	const char *data = luaL_checklstring(L, 3, &datasz);
	reset(ctx);
	if (keysz > HASH_UPDATE) {
		update(ctx, key, keysz);
		final(ctx, buf);
		reset(ctx);
	} else {
		memcpy(buf, key, sz);
	}
	for (i = 0; i < HASH_UPDATE; i++) {
		okey[i] = buf[i] ^ 0x5c;
		ikey[i] = buf[i] ^ 0x36;
	}
	update(ctx, ikey, HASH_UPDATE);
	update(ctx, data, datasz);
	final(ctx, buf);
	reset(ctx);
	update(ctx, okey, HASH_UPDATE);
	update(ctx, buf, HASH_UPDATE);
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
	do_updates(L, 2, lua_gettop(L)-1);
	return 1;
}

static int m_clone(lua_State *L)
{
	struct HASH_NAME *nctx, *ctx = toctx(L, 1);
	nctx = lua_newuserdata(L, sizeof(struct HASH_NAME));
	*nctx = *ctx;
	lua_pushvalue(L, lua_upvalueindex(1));
	lua_setmetatable(L, -2);
	do_updates(L, 2, lua_gettop(L)-1);
	return 1;
}

static int m_reset(lua_State *L)
{
	struct HASH_NAME *ctx = toctx(L, 1);
	reset(ctx);
	do_updates(L, 2, lua_gettop(L));
	lua_settop(L, 1);
	return 1;
}

static int m_update(lua_State *L)
{
	struct HASH_NAME *ctx = toctx(L, 1);
	do_updates(L, 2, lua_gettop(L));
	lua_settop(L, 1);
	return 1;
}

static int m_digest(lua_State *L)
{
	struct HASH_NAME *ctx = toctx(L, 1);
	uint8_t buf[HASH_BYTES];
	do_updates(L, 2, lua_gettop(L));
	final(ctx, buf);
	lua_pushlstring(L, buf, sizeof buf);
	return 1;
}

static luaL_Reg 	methods = {
	{"clone", 	m_clone},
	{"reset", 	m_reset},
	{"update", 	m_update},
	{"digest", 	m_digest},
	{"hexdigest", 	m_hexdigest},
	{"hex", 		m_hexdigest},
#if (HASH_FLAGS) & HASH_HMAC
	{"hmac", 	m_hmac},
#endif
	{NULL, 		NULL}
};


int lua_binding(lua_State *L)
{
	lua_newtable(L);
	luaL_setfuncs(L, methods, 0);
	lua_pushvalue(L, -1);
	lua_setmetatable(L, -2);
	lua_pushvalue(L, -1);
	lua_setfield(L, "__index", -2);
	lua_pushcclosure(L, m_create, 1);
	return 1;
}

require "lhash"
require "lhash.hmac"

function phex(s)
	return(string.gsub(s, ".", function(c) return string.format("%02x", string.byte(c)) end))
end

function test1(s)
	local a = "The quick brown fox"
	local b = " jumps over the lazy cog"
	local c = lhash[s]()
	c:update(a)
	c:update(b)
	local f = c:final()
	assert(f == lhash[s](a..b))
	return phex(f)
end

function test2(s)
	return phex(lhash[s](string.rep("\0", 1000)))
end

assert(test1("sha1") == "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3")
assert(test2("sha1") == "c577f7a37657053275f3e3ecc06ec22e6b909366")
assert(test1("sha256") == "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be")
assert(test2("sha256") == "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53")
assert(test1("sha384") == "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b")
assert(test2("sha384") == "aae017d4ae5b6346dd60a19d52130fb55194b6327dd40b89c11efc8222292de81e1a23c9b59f9f58b7f6ad463fa108ca")
assert(test1("sha512") == "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045")
assert(test2("sha512") == "ca3dff61bb23477aa6087b27508264a6f9126ee3a004f53cb8db942ed345f2f2d229b4b59c859220a1cf1913f34248e3803bab650e849a3d9a709edc09ae4a76")
assert(test1("md5") == "1055d3e698d289f2af8663725127bd4b")
assert(test2("md5") == "ede3d3b685b4e137ba4cb2521329a75e")

------------------------
-- hmac
------------------------
function hmac(macfunc, func, str, key)
	local hmaci, hmaco = lhash[macfunc](key)
	local a = lhash[func]():update(hmaco):update(lhash[func]():update(hmaci):update(str):final()):final()
	local b = lhash.hmac[func](key, str)
	assert(a==b)
	assert(lhash.hmac[func](key):final(str) == a)
	return phex(a)
end

-- RFC2202
assert(hmac("hmac64","md5", "what do ya want for nothing?", "Jefe") == "750c783e6ab0b503eaa86e310a5db738")
assert(hmac("hmac64","sha1", "what do ya want for nothing?", "Jefe") == "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")

-- RFC4231
assert(hmac("hmac64","sha256", "what do ya want for nothing?", "Jefe") == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
assert(hmac("hmac128","sha384", "what do ya want for nothing?", "Jefe") == "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")
assert(hmac("hmac128","sha512", "what do ya want for nothing?", "Jefe") == "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")

print("All tests passed.")


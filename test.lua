local hashes = {
	md5 = require 'md5',
	sha1 = require 'sha1',
	sha2 = require 'sha2',
	sha3 = require 'sha3',
}

local hmac = {
	{
		key = ("\x0b"):rep(20),
		data = "Hi There",
		sha1 = "b617318655057264e28bc0b6fb378c8ef146be00",
		sha2 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		sha3 = "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb",
	},
	{
		key = "Jefe",
		data = "what do ya want for nothing?",

		md5 = "750c783e6ab0b503eaa86e310a5db738",
		sha1 = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
		sha2 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		sha3 = "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5"
	},
	{
		key = ("\xaa"):rep(16),
		data = ("\xdd"):rep(50),

		md5 = "56be34521d144c88dbb8c733f0e8b3f6",
	},

	{
		key = ("\xaa"):rep(20),
		data = ("\xdd"):rep(50),
		sha1 = "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
	},

	{
		key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
		data = ("\xcd"):rep(50),

		md5 = "697eaf0aca3a3aea3a75164746ffaa79",
		sha1 = "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
	},

	{
		key = ("\x0c"):rep(16),
		data = "Test With Truncation",
		md5 = "56461ef2342edc00f9bab995690efd4c",
	},

	{
		key = ("\x0c"):rep(20),
		data = "Test With Truncation",

		sha1 = "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
	},
	{
		key = ("\xaa"):rep(80),
		data = "Test Using Larger Than Block-Size Key - Hash Key First",


		md5 = "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
		sha1 = "aa4ae5e15272d00e95705637ce8a3b55ed402112",
	},
	{
		key = ("\xaa"):rep(80),
		data = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",

		md5 = "6f630fad67cda0ee1fb1f562db3aa53e",
		sha1 = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
	},
}

for _,v in ipairs(hmac) do
	local key = v.key
	local data = v.data
	for f,h in pairs(v) do
		if hashes[f] then
			--print(#key,#data,f,h,hashes[f]():hmac(key,data):hex())
			assert(hashes[f]():hmac(key,data):hex() == h)
		end
	end
end


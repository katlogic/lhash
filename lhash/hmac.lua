local lhash = require "lhash"
local ipairs = ipairs
local setmetatable = setmetatable

module(...)

local hashes = { "md5", "sha1", "sha256", "sha384", "sha512" }
local custmac = { sha384=lhash.hmac128, sha512=lhash.hmac128 }

local function new_mac(hashf, macf)
	local mac_mt = {
		update = function(self, str)
			self.i:update(str)
		end,
		final = function(self, str)
			if str ~= nil then
				self:update(str)
			end
			return self.o:update(self.i:final()):final()
		end
	}
	mac_mt.__index = mac_mt
	return function(key, str)
		local ipad, opad = macf(key)
		local l=setmetatable({o=hashf():update(opad), i=hashf():update(ipad)}, mac_mt)
		if str then
			return l:final(str)
		end
		return l
	end
end

for _,v in ipairs(hashes) do
	_M[v] = new_mac(lhash[v], custmac[v] or lhash.hmac64)
end

return _M


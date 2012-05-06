-- $Id: util.lua,v 1.2 2006-11-28 02:15:46 kt Exp $ --
function phex(s)
	return(string.gsub(s, ".", function(c) return string.format("%02x", string.byte(c)) end))
end

function shex(s)
	return(string.gsub(s, ".", function(c) return string.format("%02x:", string.byte(c)) end))
end

local function hhex(v)
	return (v >= 48 and v <= 57) and (v-48) or (v-65+10)
end

function ehex(s)
ss = string.gsub(s, "%x%x", function(v)
	v = v:upper()
	local a = v:byte(1)
	local b = v:byte(2)
	return string.char((hhex(a)<<4)|hhex(b))
end)
return ss
end


function dt(t)
--	if type(t) != "table" then print("table is "..type(t)) return end
	for k,v in pairs (t) do
		print(k, "=",v)
	end
end

function prettyhex(desc, v)
	print("\$desc\:")
	print(shex(v))
end

function	recvline(s,buf)
	local line,cr
	assert(buf)
	s:nbread(true)
	while true do
--		print("parsing")
		line, cr = string.match(buf, "(.-)(\r*)\n")
--		print("parsed", line)
		if line then
			local bl = buf:off(0)
			local skip = #line + #cr + 1
			assert(bl >= skip)
--			print("moving ",skip," -> 0, bl=",bl)
			buf:append(buf, skip, bl-skip)
--			print("after move ", buf:off(), tostring(buf))
			break
		end
		if buf:left() == 0 then
			break
		end
		buf = s:recv(buf)
--		print("s:recv() returned", buf)
		if not buf then break end
	end
	s:nbread(false)
	return line
end


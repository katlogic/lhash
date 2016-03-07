return setmetatable({}, {__index=function(t,k) 
	return require("lhash."..k)
end})

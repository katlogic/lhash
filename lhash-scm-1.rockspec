package = "lhash"
version = "scm-1"
source = {
	url = "git://github.com/katlogic/lhash.git";
	branch = "master";
}

description = {
	summary = "self contained SHA1/2/3 and MD5 + HMAC";
	detailed = "SHA1/2/3 and MD5 bindings.";
	homepage = "http://github.com/katlogic/lhash";
	license = "MIT";
}

dependencies = {
	"lua >= 5.1"
}

build = {
	type = "builtin";
	modules = {
		["lhash.init"] = "init.lua";
		["lhash.sha1"] = {
			sources = { "sha1.c" };
		};
		["lhash.sha2"] = {
			sources = { "sha2.c" };
		};
		["lhash.sha3"] = {
			sources = { "sha3.c" };
		};
		["lhash.md5"] = {
			sources = { "md5.c" };
		}
	}
}

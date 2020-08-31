package = "lua-resty-sniproxy"
version = "0.22-1"
source = {
   url = "git+ssh://git@github.com/fffonion/lua-resty-sniproxy.git",
   tag = "0.22"
}
description = {
   summary = "lua-resty-sniproxy - SNI Proxy based on the ngx_lua cosocket API",
   detailed = "lua-resty-sniproxy - SNI Proxy based on the ngx_lua cosocket API",
   homepage = "https://github.com/fffonion/lua-resty-sniproxy",
   license = "BSD"
}
build = {
   type = "builtin",
   modules = {
      ["resty.sniproxy"] = "lib/resty/sniproxy.lua"
   }
}

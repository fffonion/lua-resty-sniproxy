Name
====

lua-resty-sniproxy - SNI Proxy based on the ngx_lua cosocket API

Table of Contents
=================

- [Description](#description)
- [Status](#status)
- [Synopsis](#synopsis)
- [TODO](#todo)
- [Copyright and License](#copyright-and-license)
- [See Also](#see-also)


Description
===========

This library is an [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication) proxy written in Lua. TLS parsing part is rewritten from [dlundquist/sniproxy](https://github.com/dlundquist/sniproxy)

Note that nginx [stream module](https://nginx.org/en/docs/stream/ngx_stream_core_module.html) and [ngx_stream_lua_module](https://github.com/openresty/stream-lua-nginx-module) is required.

Tested on Openresty 1.9.15.1.

[Back to TOC](#table-of-contents)

Status
========

Experimental.

Synopsis
========


```
stream {
    lua_resolver 8.8.8.8;
    init_worker_by_lua_block {
        sni_rules = { 
            ["www.google.com"] = {"www.google.com", 443},
            ["www.facebook.com"] = {"9.8.7.6", 443},
            ["api.twitter.com"] = {"1.2.3.4"},
            [".+.twitter.com"] = {nil, 443},
            ["."] = {"unix:/var/run/nginx-default.sock"}
        }   
    }

    server {
            error_log /var/log/nginx/sniproxy-error.log error;
            listen 443;
            content_by_lua_block {
                    local sni = require("resty.sniproxy")
                    local sp = sni:new()
                    sp:run()
            }   
    }
}
```

A Lua table `sni_rules` should be defined in the `init_worker_by_lua_block` directive.

The key can be either whole host name or regular expression. Use `.` for a default host name. If no entry is matched, connection will be closed.

The value is a table containing host name and port. A host can be DNS name, IP address and UNIX domain socket path. If host is set to `nil`, the server_name in SNI will be used. If the port is not defined or set to `nil`, **443** will be used.

Rules are applied with the priority as its occurrence sequence in the table. In the example above, **api.twitter.com** will match the third rule **api.twitter.com** rather than the fourth **.+.twitter.com**.

If the protocol version is less than TLSv1 (eg. SSLv3, SSLv2), connection will be closed, since SNI extension is not supported in these versions.

[Back to TOC](#table-of-contents)


TODO
====

- stress and performance test

[Back to TOC](#table-of-contents)


Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2016, by fffonion <fffonion@gmail.com>.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)

See Also
========
* the ngx_stream_lua_module: https://github.com/openresty/stream-lua-nginx-module
* [dlundquist/sniproxy] (https://github.com/dlundquist/sniproxy)

[Back to TOC](#table-of-contents)
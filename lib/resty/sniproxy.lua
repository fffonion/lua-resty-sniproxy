

local sub = string.sub
local byte = string.byte
local format = string.format
local tcp = ngx.socket.tcp
local setmetatable = setmetatable
local spawn = ngx.thread.spawn
local wait = ngx.thread.wait

local bit = require("bit")


local ok, new_tab = pcall(require, "table.new")
if not ok or type(new_tab) ~= "function" then
    new_tab = function (narr, nrec) return {} end
end


local _M = new_tab(0, 100)
_M._VERSION = '0.01'

local mt = { __index = _M }

function _M.new(self, bufsize, timeout)
    local srvsock, err = tcp()
    if not srvsock then
        return nil, err
    end
    local reqsock, err = ngx.req.socket()
    if not reqsock then
        return nil, err
    end
    return setmetatable({
        srvsock = srvsock,
        reqsock = reqsock,
        exit_flag = false,
        server_name = nil,
        bufsize = bufsize or 1024,
        timeout = timeout or 30000
    }, mt)
end

local function _cleanup(self)
    if self.srvsock ~= nil then
        local ok, err = self.srvsock:close()
        if not ok then
            --
        end
    end
    
    if self.reqsock ~= nil and self.reqsock.close ~= nil then
        local ok, err = self.reqsock:close()
        if not ok then
            --
        end
    end
    
end

local function _parse_tls_header(self, dt_record, pos, data_len, hostname)
    -- https://github.com/dlundquist/sniproxy/blob/master/src/tls.c
    local TLS_HEADER_LEN = 5
    local TLS_HANDSHAKE_CONTENT_TYPE = 0x16
    local TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
    
    local TLS_HEADER_MAX_LENGHTH = 2048
    
    local dt_overhead, err = self.reqsock:receive(TLS_HEADER_LEN)
    
    -- parse TLS header starts
    
    -- hex_dump(dt_overhead)
    
    if (bit.band(byte(dt_overhead, 1), 0x80) > 0 and byte(dt_overhead, 3) == 1) then
        ngx.log(ngx.INFO, "Received SSL 2.0 Client Hello which can not support SNI.")
        return -2
    end

    local tls_content_type = byte(dt_overhead, 1)
    if (tls_content_type ~= TLS_HANDSHAKE_CONTENT_TYPE) then
        ngx.log(ngx.INFO, "Request did not begin with TLS handshake.");
         return -2
    end

    local tls_version_major = byte(dt_overhead, 2)
    local tls_version_minor = byte(dt_overhead, 3)
    if (tls_version_major < 3) then
        ngx.log(ngx.INFO, "Received SSL", tls_version_major, tls_version_minor, "handshake which which can not support SNI.")
        return -2
    end

    -- protocol: TLS record length 
    local data_len = bit.lshift(byte(dt_overhead, 4), 8) + byte(dt_overhead, 5)
    
    if data_len > TLS_HEADER_MAX_LENGHTH then
        ngx.log(ngx.INFO, "TLS ClientHello exceeds max length configured", data_len, ">", TLS_HEADER_MAX_LENGHTH)
        return -5
    end

    -- protocol: Handshake
    
    local dt_record, err = self.reqsock:receive(data_len)
    
    -- hex_dump(dt_record)
    
    local pos = 1
    
    if (byte(dt_record, 1) ~= TLS_HANDSHAKE_TYPE_CLIENT_HELLO) then
        ngx.log(ngx.INFO, "Not a client hello");
        return -5
    end

    --[[ Skip past fixed length records:
       1    Handshake Type
       3    Length
       2    Version (again)
       32    Random
       to    Session ID Length
    ]]--
    pos = pos + 38;

    local len
    -- protocol: Session ID
    if (pos > data_len) then
        return -5
    end
    len = byte(dt_record, pos);
    pos = pos + 1 + len;

    -- protocol: Cipher Suites
    if (pos > data_len) then
        return -5
    end
    len = bit.lshift(byte(dt_record, pos), 8) + byte(dt_record, pos + 1)
    pos = pos + 2 + len;

    -- protocol: Compression Methods
    if (pos > data_len) then
        return -5
    end
    len = byte(dt_record, pos)
    pos = pos + 1 + len;

    if (pos == data_len and tls_version_major == 3 and tls_version_minor == 0) then
        ngx.log(ngx.INFO, "Received SSL 3.0 handshake without extensions");
        return -2
    end

    -- protocol: Extensions
    if (pos + 1 > data_len) then
        return -5
    end
    len = bit.lshift(byte(dt_record, pos), 8) + byte(dt_record, pos + 1)
    pos = pos + 2;

    
    if (pos + len - 1 > data_len) then
        return -5
    end
    
    
    -- Parse each 4 bytes for the extension header

    while (pos + 3 <= data_len) do
        -- Extension Length */
        len = bit.lshift(byte(dt_record, pos + 2), 8) + byte(dt_record, pos + 3)
        
        -- Check if it's a server name extension */
        if (byte(dt_record, pos) == 0 and byte(dt_record, pos + 1) == 0) then
            -- There can be only one extension of each type,
            -- so we break our state and move p to beinnging of the extension here
            if (pos + 3 + len > data_len) then
                return -5
            end
            pos = pos + 6 -- skip extension header(4) + server name list length(2)
            
            -- starts parse server name extension
            while (pos + 3 < data_len) do
                ngx.log(ngx.INFO, "pos is now", string.format("0x%0X", pos-1))
                len = bit.lshift(byte(dt_record, pos + 1), 8) + byte(dt_record, pos + 2)
                
                if (pos + 2 + len > data_len) then
                    return -5
                end

                if(byte(dt_record, pos) ~= 0) then -- name type
                    ngx.log(ngx.INFO, "Unknown server name extension name type:", string.format("0x%0X", byte(dt_record, pos)))
                else
                    self.server_name = sub(dt_record, pos + 3, pos + 2 + len)
                    return 0, dt_overhead, dt_record
                end
                pos = pos + 3 + len;
            end
            
            --[[ Check we ended where we expected to */
            if (pos ~= data_len)
                return -5;
            ]]--

            return -2
            -- ends parse server name extension
        end
        pos = pos + 4 + len -- Advance to the next extension header
    end
    
    --[[Check we ended where we expected to
    if (pos ~= data_len)
        return -5;
    ]]--

    return 0
end

local function _upl(self)
    -- proxy client request to server
    local buf, len, _
    local rsock = self.reqsock
    local ssock = self.srvsock
    while not self.exit_flag do
        if self.reqsock == nil then
            break
        end
        hd, _ = rsock:receive(5)
        if hd == nil then
            break
        end
        len = bit.lshift(byte(hd, 4), 8) + byte(hd, 5)
        buf, _ = rsock:receive(len)
        if self.srvsock == nil then
            break
        end
        ssock:send(hd)
        ssock:send(buf)
    end
    self.exit_flag = true
end

local function _dwn(self)
    -- proxy response to client
    local buf, _, __
    local rsock = self.reqsock
    local ssock = self.srvsock
    while not self.exit_flag do
        --[[if self.srvsock == nil then
            break
        end]]--
        hd, _, __ = ssock:receive(5)
        if _ then
            break
        end
        rsock:send(hd)
        len = bit.lshift(byte(hd, 4), 8) + byte(hd, 5)
        buf, _ = ssock:receive(len)
        --[[if self.reqsock == nil then
            break
        end]]--
        rsock:send(buf)
    end
    self.exit_flag = true
end

function _M.run(self)
    if sni_rules == nil then
        ngx.log(ngx.ERR, "sni_rules not defined")
        return
    end
    while true do
        local code, dt1, dt2 = _parse_tls_header(self)
        if code ~= 0 then
            ngx.log(ngx.INFO, "Cleaning up with an exit code", code)
            break
        end
        ngx.log(ngx.INFO, format("tls server_name:%s exit:%d", self.server_name, code))
        local upstream, port
        for k, v in pairs(sni_rules) do
            local m, e = ngx.re.match(self.server_name, k)
            if m then
                upstream = v[1] or self.server_name
                port = v[2] or 443
                break
            end
        end
        if upstream == nil or port == nil then
            ngx.log(ngx.WARN, format("no entries matching server_name: %s", self.server_name))
            break
        end
        ngx.log(ngx.INFO, format("selecting upstream: %s:%d", upstream, port, err))
        local ok, err = self.srvsock:connect(upstream, port)
        if not ok then
            ngx.log(ngx.ERR, format("failed to connect to proxy upstream: %s:%s, err:%s", self.server_name, port, err))
            break
        end
        -- send tls headers 
        self.srvsock:send(dt1)
        self.srvsock:send(dt2)
        
        wait(
            spawn(_upl, self),
            spawn(_dwn, self)
        )
        
        break
    end
    _cleanup(self)
    
end


return _M
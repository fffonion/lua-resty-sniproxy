

local sub = string.sub
local byte = string.byte
local format = string.format
local tcp = ngx.socket.tcp
local setmetatable = setmetatable
local spawn = ngx.thread.spawn
local wait = ngx.thread.wait

local bit = require("bit")
local lshift = bit.lshift

local balancer = require "ngx.balancer"

local TLS_HEADER_LEN = 5
local TLS_HANDSHAKE_CONTENT_TYPE = 0x16
local TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
local TLS_HEADER_MAX_LENGHTH = 2048 -- anti dos attack


local ok, new_tab = pcall(require, "table.new")
if not ok or type(new_tab) ~= "function" then
    new_tab = function (narr, nrec) return {} end
end


local _M = new_tab(0, 4)
_M._VERSION = '0.10'
_M.rules = nil

local mt = { __index = _M }

local function check_version()
    if not ngx.config
        or not ngx.config.ngx_lua_version
        or ngx.config.ngx_lua_version < 6
    then
        return false
    end
    return true
end

local peak_supported = check_version()

function _M.new(self, connect_timeout, send_timeout, read_timeout)
    if not _M.rules then
        return nil, "sni rules not defined"
    end

    local reqsock, err = ngx.req.socket()
    if not reqsock then
        return nil, err
    end
    reqsock:settimeouts(connect_timeout or 10000, send_timeout or 10000, read_timeout or 10000)

    return setmetatable({
        reqsock = reqsock,
        server_name = nil,
    }, mt)
end


local function _parse_tls_header(sock, is_preread)
    local f = is_preread and sock.peek or sock.receive
    local server_name

    -- https://github.com/dlundquist/sniproxy/blob/master/src/tls.c
    local dt_overhead, err = f(sock, TLS_HEADER_LEN)
    if err then
        return nil, nil, "error reading from reqsock: " .. err
    end

    local dt_read
    
    -- parse TLS header starts
    
    -- hex_dump(dt_overhead)
    
    if (bit.band(byte(dt_overhead, 1), 0x80) > 0 and byte(dt_overhead, 3) == 1) then
        return nil, nil, "Received SSL 2.0 Client Hello which can not support SNI."
    end

    local tls_content_type = byte(dt_overhead, 1)
    if (tls_content_type ~= TLS_HANDSHAKE_CONTENT_TYPE) then
        return nil, nil, "Request did not begin with TLS handshake."
    end

    local tls_version_major = byte(dt_overhead, 2)
    local tls_version_minor = byte(dt_overhead, 3)
    if (tls_version_major < 3) then
        return nil, nil, format("Received SSL %d.%d handshake which which can not support SNI.", tls_version_major, tls_version_minor)
    end

    -- protocol: TLS record length 
    local data_len = lshift(byte(dt_overhead, 4), 8) + byte(dt_overhead, 5)
    
    if data_len > TLS_HEADER_MAX_LENGHTH then
        return nil, nil, format("TLS ClientHello exceeds max length configured %d > %d", data_len, TLS_HEADER_MAX_LENGHTH)
    end

    -- protocol: Handshake
    local dt_record, err

    if is_preread then
        -- peek always start from beginning
        dt_read, err = f(sock, data_len + TLS_HEADER_LEN)
        if dt_read then
            dt_record = dt_read:sub(TLS_HEADER_LEN+1)
        end
    else
        dt_record, err = f(sock, data_len)
        if dt_record then
            dt_read = dt_overhead .. dt_record
        end
    end
    if err then
        return nil, nil, "error reading from reqsock: " .. err
    end
    
    -- hex_dump(dt_record)
    
    local pos = 1
    
    if (byte(dt_record, 1) ~= TLS_HANDSHAKE_TYPE_CLIENT_HELLO) then
        return nil, nil, "Not a client hello"
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
        return nil, nil, "Protocol error: Session ID"
    end
    len = byte(dt_record, pos);
    pos = pos + 1 + len;

    -- protocol: Cipher Suites
    if (pos > data_len) then
        return nil, nil, "Protocol error: Cipher Suites"
    end
    len = lshift(byte(dt_record, pos), 8) + byte(dt_record, pos + 1)
    pos = pos + 2 + len;

    -- protocol: Compression Methods
    if (pos > data_len) then
        return nil, nil, "Protocol error: Compression Methods"
    end
    len = byte(dt_record, pos)
    pos = pos + 1 + len;

    if (pos == data_len and tls_version_major == 3 and tls_version_minor == 0) then
        return nil, nil, "Received SSL 3.0 handshake without extensions"
    end

    -- protocol: Extensions
    if (pos + 1 > data_len) then
        return nil, nil, "Protocol error: Extensions"
    end
    len = lshift(byte(dt_record, pos), 8) + byte(dt_record, pos + 1)
    pos = pos + 2;

    
    if (pos + len - 1 > data_len) then
        return nil, nil, "Protocol error: Extensions headers"
    end
    
    
    -- Parse each 4 bytes for the extension header

    while (pos + 3 <= data_len) do
        -- Extension Length */
        len = lshift(byte(dt_record, pos + 2), 8) + byte(dt_record, pos + 3)
        
        -- Check if it's a server name extension */
        if (byte(dt_record, pos) == 0 and byte(dt_record, pos + 1) == 0) then
            -- There can be only one extension of each type,
            -- so we break our state and move p to beinnging of the extension here
            if (pos + 3 + len > data_len) then
                return nil, nil, "Protocol error: Extension type"
            end
            pos = pos + 6 -- skip extension header(4) + server name list length(2)
            
            -- starts parse server name extension
            while (pos + 3 < data_len) do
                ngx.log(ngx.INFO, "pos is now", string.format("0x%0X", pos-1))
                len = lshift(byte(dt_record, pos + 1), 8) + byte(dt_record, pos + 2)
                
                if (pos + 2 + len > data_len) then
                    return nil, nil, "Protocol error: Extension data"
                end

                if(byte(dt_record, pos) ~= 0) then -- name type
                    ngx.log(ngx.INFO, "Unknown server name extension name type:", string.format("0x%0X", byte(dt_record, pos)))
                else
                    server_name = sub(dt_record, pos + 3, pos + 2 + len)
                    return dt_read, server_name, nil
                end
                pos = pos + 3 + len;
            end
            
            --[[ Check we ended where we expected to */
            if (pos ~= data_len)
                return -5;
            ]]--

            return nil, nil, "Protocol error: extra data in Extensions"
            -- ends parse server name extension
        end
        pos = pos + 4 + len -- Advance to the next extension header
    end
    
    --[[Check we ended where we expected to
    if (pos ~= data_len)
        return -5;
    ]]--

    return dt_read, server_name, nil
end

local function _select_upstream(server_name)
    local upstream, port
    if not server_name then -- no sni extension, only match default rule
        server_name = "."
    end
    for _, v in pairs(_M.rules) do
        local m, e = ngx.re.match(server_name, v[1], "jo")
        if m then
            upstream = v[2] or server_name
            port = v[3] or 443
            break
        end
    end
    return upstream, port, nil
end

function _M.preread_by(self)
    if not peak_supported then
        ngx.log(ngx.ERR, "reqsock:peak is required to use preread mode")
        ngx.exit(ngx.ERROR)
    end
    local _, server_name, err = _parse_tls_header(self.reqsock, true)
    if err then
        ngx.log(ngx.INFO, "tls header parsing error: ", err)
        ngx.exit(ngx.ERROR)
    end
    ngx.log(ngx.INFO, "tls server_name: ", server_name)

    local upstream, port = _select_upstream(server_name)
    ngx.log(ngx.INFO, "selecting upstream: ", upstream, ":", port)
    ngx.var.sniproxy_upstream = upstream
    ngx.var.sniproxy_port = port
end


local function _upl(self)
    -- proxy client request to server
    local buf, len, err, hd, discard
    local rsock = self.reqsock
    local ssock = self.srvsock
    while true do
        hd = rsock:receive(5)
        if not hd then
            break
        end
        len = lshift(byte(hd, 4), 8) + byte(hd, 5)
        buf = rsock:receive(len)
        if not buf then
            break
        end
        
        ssock:send(hd)
        discard, err = ssock:send(buf)
        if err then
            break
        end
    end
end

local function _dwn(self)
    -- proxy response to client
    local buf, len, err, hd, discard
    local rsock = self.reqsock
    local ssock = self.srvsock
    while true do
        hd = ssock:receive(5)
        if not hd then
            break
        end
        len = lshift(byte(hd, 4), 8) + byte(hd, 5)
        buf = ssock:receive(len)
        if not buf then
            break
        end
        
        rsock:send(hd)
        discard, err = rsock:send(buf)
        if err then
            break
        end
    end
end

function _M.content_by(self)
    local srvsock, err = tcp()
    if not srvsock then
        return nil, err
    end
    srvsock:settimeouts(connect_timeout or 10000, send_timeout or 10000, read_timeout or 10000)
    self.srvsock = srvsock

    while true do
        local header, server_name, err = _parse_tls_header(self.reqsock, false)
        if err then
            ngx.log(ngx.INFO, "tls header parsing error: ", err)
            break
        end
        ngx.log(ngx.INFO, "tls server_name: ", server_name)

        local upstream, port = _select_upstream(server_name)

        if not upstream or not port then
            ngx.log(ngx.WARN, "no entries matching server_name: ", server_name)
            break
        end
        ngx.log(ngx.INFO, "selecting upstream: ", upstream, ":", port)
        local ok, err = self.srvsock:connect(upstream, port)
        if not ok then
            ngx.log(ngx.ERR, format("failed to connect to proxy upstream: %s:%s, err:%s", server_name, port, err))
            break
        end
        -- send tls headers 
        self.srvsock:send(header)
        
        local co_upl = spawn(_upl, self)
        local co_dwn = spawn(_dwn, self)
        wait(co_upl)
        wait(co_dwn)
        
        break
    end

    -- make sure buffers are clean
    ngx.flush(true)

    local srvsock = self.srvsock
    local reqsock = self.reqsock
    if srvsock ~= nil then
        if srvsock.shutdown then
            srvsock:shutdown("send")
        end
        if srvsock.close ~= nil then
            local ok, err = srvsock:setkeepalive()
            if not ok then
                --
            end
        end
    end
    
    if reqsock ~= nil then
        if reqsock.shutdown then
            reqsock:shutdown("send")
        end
        if reqsock.close ~= nil then
            local ok, err = reqsock:close()
            if not ok then
                --
            end
        end
    end
    
end

-- backward compatibility
function _M.run(self)
    local phase = ngx.get_phase()
    if phase == 'content' then
        ngx.log(ngx.ERR, "content_by")
        self:content_by()
    elseif phase == 'preread' then
        ngx.log(ngx.ERR, "preread_by")
        self:preread_by()
    else
        ngx.log(ngx.ERR, "sniproxy doesn't support running in ", phase)
        ngx.exit(ngx.ERROR)
    end
end


return _M

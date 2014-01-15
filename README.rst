A Lua binding to libpcap
========================

``lpcap`` is a Lua binding to libpcap. This binding implements the full libpcap
API.

License: MIT (see LICENSE)

Dependencies
------------

| Lua >= 5.1
| libpcap >= 1.0.0

Compilation
-----------

To compile, just type the following command in the terminal::

    make

If you are on a debian-like system and you have installed all the required
dependencies, it should work as-is. If you are out of luck, you can tweak the
compilation process using the following variables:

- LUA_VERSION
- LUA_CFLAGS
- PCAP_VERSION
- PCAP_CFLAGS

For example, say that you want to compile ``lpcap`` for Lua 5.1 (by default
``lpcap`` is compiled for Lua 5.2) you can try::

    make LUA_VERSION=5.1

Or for LuaJIT::

    make LUA_VERSION=jit

If the Lua development headers are not in a common location, you can try::

    make LUA_CFLAGS="-I/path/to/lua/headers"

If you want to compile ``lpcap`` with libpcap 1.1.0 you can use::

    make PCAP_VERSION=110 PCAP_CFLAGS="-I/path/to/libpcap/headers"

Examples
--------

::

    local lpcap = require('lpcap')
    
    local h = lpcap.open_live('wlan0', 65535, 1, 0)
    print(h:fileno())
    print(h:get_selectable_fd())
    print(h:datalink())
    local d = h:dump_open('/tmp/test.pcap')
    print(h:dispatch(-1, function(ctx, hdr, data)
        print(hdr.caplen, hdr.len, hdr.ts.tv_sec, hdr.ts.tv_usec)
        lpcap.dump(d, hdr, data)
    end))
    print(h:loop(10, lpcap.dump, d))
    local f = h:compile('tcp port 443', 1, lpcap.PCAP_NETMASK_UNKNOWN)
    h:setfilter(f)
    print(h:loop(10, lpcap.dump, d))
    f:freecode()
    d:close()
    h:close()
    

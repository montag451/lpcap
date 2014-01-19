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

Documentation
-------------

Because ``lpcap`` mimics the libpcap API it does not provide a documentation of
its own but rather rely on the official documentation of libpcap (which can be
found `here <http://www.tcpdump.org/#documentation>`_). In short:

- all the constants of libpcap (DLT_*, PCAP_*) can be found at the "root"
  of the module.
- all the functions of libpcap have their "pcap\_" prefix removed in
  ``lpcap`` (i.e the equivalent of pcap_open_live() is open_live()).
- all the functions of libpcap which does not take a pcap_t pointer, a
  pcap_dump_t pointer or a bpf_program pointer as their first argument can be
  found at the "root" of the module.
- all the functions of libpcap which take a pcap_t pointer as their first
  argument are methods of the "Handle" objects returned by:

    - create()
    - open_dead()
    - open_live()
    - open_offline()

- all the functions of libpcap which take a pcap_dumper_t pointer as their
  first argument are methods of the "Dumper" objects returned by:

    - dump_open() (which is a method of "Handle" objects)

- all the functions of libpcap which take a bpf_program pointer as their first
  argument are methods of the "Filter" objects returned by:

    - compile() (which is a method of "Handle" objects)

- all the functions of libpcap which take an error buffer to store error
  messages (i.e functions which does not rely on geterr()) throw errors when
  something is wrong. Errors are string giving the reason of the error.

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
    -- the three lines below are not really necessary since the GC will
    -- automatically execute these functions for us but it's a good practice to
    -- release resources when they are needed anymore.
    f:freecode()
    d:close()
    h:close()
    devs = lpcap.findalldevs()
    for _, dev in ipairs(devs) do
        print(dev.name)
    end

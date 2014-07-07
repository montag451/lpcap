#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>

#include <lua.h>
#include <lauxlib.h>

#if LUA_VERSION_NUM == 501

#define LUA_OK 0

static void luaL_setfuncs(lua_State *L, const luaL_Reg *l, int nup)
{
    luaL_checkstack(L, nup + 1, "too many upvalues");
    for (; l->name != NULL; l++) {
        int i;
        lua_pushstring(L, l->name);
        for (i = 0; i < nup; i++) {
            lua_pushvalue(L, -(nup + 1));
        }
        lua_pushcclosure(L, l->func, nup);
        lua_settable(L, -(nup + 3));
    }
    lua_pop(L, nup);
}

static void luaL_setmetatable(lua_State *L, const char *tname)
{
    luaL_getmetatable(L, tname);
    lua_setmetatable(L, -2);
}

static lua_Number lua_tonumberx (lua_State *L, int idx, int *isnum)
{
    if (lua_isnumber(L, idx)) {
        if (isnum != NULL) {
            *isnum = 1;
        }
        return lua_tonumber(L, idx);
    } else {
        if (isnum != NULL) {
            *isnum = 0;
        }
        return 0;
    }
}

#define luaL_newlibtable(L,l) lua_createtable(L, 0, sizeof(l)/sizeof((l)[0]) - 1)
#define luaL_newlib(L,l) (luaL_newlibtable(L,l), luaL_setfuncs(L,l,0))

#endif

#define LPCAP_FILTER_TNAME "lpcap.Filter"
#define LPCAP_DUMPER_TNAME "lpcap.Dumper"
#define LPCAP_HANDLE_TNAME "lpcap.Handle"

static int print(lua_State* L)
{
    int nargs = lua_gettop(L);
    int i;

    luaL_checkstack(L, nargs + 1, "too many values to print");
    lua_getglobal(L, "print");
    if (lua_isnil(L, -1)) {
        return 0;
    }
    for (i = 1; i <= nargs; ++i) {
        lua_pushvalue(L, i);
    }
    lua_call(L, nargs, 0);
    return 0;
}

/* Use at most 3 stack slots */
static void pkthdr2table(lua_State* L, struct pcap_pkthdr* h)
{
    lua_createtable(L, 0, 3);
    lua_createtable(L, 0, 2);
    lua_pushnumber(L, h->ts.tv_sec);
    lua_setfield(L, -2, "tv_sec");
    lua_pushnumber(L, h->ts.tv_usec);
    lua_setfield(L, -2, "tv_usec");
    lua_setfield(L, -2, "ts");
    lua_pushnumber(L, h->caplen);
    lua_setfield(L, -2, "caplen");
    lua_pushnumber(L, h->len);
    lua_setfield(L, -2, "len");
}

/* Use at most 5 stack slots */
static void table2pkthdr(lua_State* L, int table, struct pcap_pkthdr* h)
{
    int isnum;

    lua_getfield(L, table, "caplen");
    h->caplen = lua_tonumberx(L, -1, &isnum);
    if (!isnum) {
        luaL_error(L, "\"caplen\" field is missing or not a number");
    }
    lua_getfield(L, table, "len");
    h->len = lua_tonumberx(L, -1, &isnum);
    if (!isnum) {
        luaL_error(L, "\"len\" field is missing or not a number");
    }
    lua_getfield(L, table, "ts");
    if (!lua_istable(L, -1)) {
        luaL_error(L, "\"ts\" field is missing or not a table");
    }
    lua_getfield(L, -1, "tv_sec");
    h->ts.tv_sec = lua_tonumberx(L, -1, &isnum);
    if (!isnum) {
        luaL_error(L, "\"tv_sec\" field is missing or not a number");
    }
    lua_getfield(L, -2, "tv_usec");
    h->ts.tv_usec = lua_tonumberx(L, -1, &isnum);
    if (!isnum) {
        luaL_error(L, "\"tv_usec\" field is missing or not a number");
    }
}

/* Use at most 2 stack slots */
static void saddr2table(lua_State* L, struct sockaddr* sa)
{
    lua_newtable(L);
    switch (sa->sa_family) {

        case AF_INET: {
            struct in_addr* addr = &((struct sockaddr_in*)sa)->sin_addr;
            char buf[INET_ADDRSTRLEN];
            lua_pushliteral(L, "inet");
            lua_setfield(L, -2, "type");
            if (inet_ntop(AF_INET, addr, buf, sizeof(buf)) != NULL) {
                lua_pushstring(L, buf);
                lua_setfield(L, -2, "value");
            }
            break;
        }

        case AF_INET6: {
            struct in6_addr* addr = &((struct sockaddr_in6*)sa)->sin6_addr;
            char buf[INET6_ADDRSTRLEN];
            lua_pushliteral(L, "inet6");
            lua_setfield(L, -2, "type");
            if (inet_ntop(AF_INET6, addr, buf, sizeof(buf)) != NULL) {
                lua_pushstring(L, buf);
                lua_setfield(L, -2, "value");
            }
            lua_pushnumber(L, ((struct sockaddr_in6*)sa)->sin6_scope_id);
            lua_setfield(L, -2, "scope");
            break;
        }

        case AF_PACKET: {
            struct sockaddr_ll* sll = (struct sockaddr_ll*)sa;
            lua_pushliteral(L, "hw");
            lua_setfield(L, -2, "type");
            lua_pushlstring(L, (const char*)sll->sll_addr, sll->sll_halen);
            lua_setfield(L, -2, "value");
            lua_pushnumber(L, sll->sll_ifindex);
            lua_setfield(L, -2, "index");
            lua_pushnumber(L, sll->sll_hatype);
            lua_setfield(L, -2, "hatype");
            break;
        }

        default:
            lua_pushliteral(L, "unknown");
            lua_setfield(L, -2, "type");
            break;
    }
}

static struct bpf_program* check_filter(lua_State* L, int idx)
{
    return luaL_checkudata(L, idx, LPCAP_FILTER_TNAME);
}

static int filter_freecode(lua_State* L)
{
    pcap_freecode(luaL_checkudata(L, 1, LPCAP_FILTER_TNAME));
    return 0;
}

static int filter_offline_filter(lua_State* L)
{
    struct bpf_program* f = check_filter(L, 1);
    size_t len;
    const char* data; 
    struct pcap_pkthdr h;

    luaL_checktype(L, 2, LUA_TTABLE);
    data = luaL_checklstring(L, 3, &len);
    table2pkthdr(L, 2, &h);
    h.caplen = h.caplen > len ? len : h.caplen;
    lua_pushinteger(L, pcap_offline_filter(f, &h, (const u_char*)data));
    return 1;
}

static int filter_gc(lua_State* L)
{
    return filter_freecode(L);
}

static const luaL_Reg lpcap_filter_meth[] = {
    {"freecode", filter_freecode},
    {"offline_filter", filter_offline_filter},
    {"__gc", filter_gc},
    {NULL, NULL}
};

static void create_filter_meta(lua_State* L)
{
    luaL_newmetatable(L, LPCAP_FILTER_TNAME);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, lpcap_filter_meth, 0);
    lua_pop(L, 1);
}

static pcap_dumper_t** check_dumper(lua_State* L, int idx)
{
    pcap_dumper_t** d = luaL_checkudata(L, idx, LPCAP_DUMPER_TNAME);

    if (*d == NULL) {
        luaL_error(L, "closed dumper");
    }
    return d;
}

static int dumper_close(lua_State* L)
{
    pcap_dumper_t** d = luaL_checkudata(L, 1, LPCAP_DUMPER_TNAME);

    if (*d != NULL) {
        pcap_dump_close(*d);
        *d = NULL;
    }
    return 0;
}

static int dumper_flush(lua_State* L)
{
    lua_pushinteger(L, pcap_dump_flush(*check_dumper(L, 1)));
    return 1;
}

static int dumper_ftell(lua_State* L)
{
    lua_pushnumber(L, pcap_dump_ftell(*check_dumper(L, 1)));
    return 1;
}

static int dumper_gc(lua_State* L)
{
    return dumper_close(L);
}

static const luaL_Reg lpcap_dumper_meth[] = {
    {"close", dumper_close},
    {"flush", dumper_flush},
    {"ftell", dumper_ftell},
    {"__gc", dumper_gc},
    {NULL, NULL}
};

static void create_dumper_meta(lua_State* L)
{
    luaL_newmetatable(L, LPCAP_DUMPER_TNAME);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, lpcap_dumper_meth, 0);
    lua_pop(L, 1);
}

static pcap_t** check_handle(lua_State* L, int idx)
{
    pcap_t** h = luaL_checkudata(L, idx, LPCAP_HANDLE_TNAME);

    if (*h == NULL) {
        luaL_error(L, "closed handle");
    }
    return h;
}

static int handle_activate(lua_State* L)
{
    lua_pushinteger(L, pcap_activate(*check_handle(L, 1)));
    return 1;
}

static int handle_breakloop(lua_State* L)
{
    pcap_breakloop(*check_handle(L, 1));
    return 0;
}

static int handle_can_set_rfmon(lua_State* L)
{
    lua_pushinteger(L, pcap_can_set_rfmon(*check_handle(L, 1)));
    return 1;
}

static int handle_close(lua_State* L)
{
    pcap_t** h = luaL_checkudata(L, 1, LPCAP_HANDLE_TNAME);

    if (*h != NULL) {
        pcap_close(*h);
        *h = NULL;
    }
    return 0;
}

static int handle_compile(lua_State* L)
{
    pcap_t** h = check_handle(L, 1);
    const char* str = luaL_checkstring(L, 2);
    int optimize = luaL_checkinteger(L, 3);
    bpf_u_int32 netmask = luaL_checknumber(L, 4);
    struct bpf_program* f;

    f = lua_newuserdata(L, sizeof(*f));
    if (pcap_compile(*h, f, str, optimize, netmask) != 0) {
        lua_pushnil(L);
        return 1;
    }
    luaL_setmetatable(L, LPCAP_FILTER_TNAME);
    return 1;
}

static int handle_datalink(lua_State* L)
{
    lua_pushinteger(L, pcap_datalink(*check_handle(L, 1)));
    return 1;
}

static int protected_dispatch(lua_State* L)
{
    struct pcap_pkthdr* h = lua_touserdata(L, 3);
    const u_char* bytes = lua_touserdata(L, 4);

    lua_pushvalue(L, 1);
    lua_pushvalue(L, 2);
    pkthdr2table(L, h);
    lua_pushlstring(L, (const char*)bytes, h->caplen);
    lua_call(L, 3, 0);
    return 0;
}

static void dispatch(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes)
{
    lua_State* L = (lua_State*)user;

    lua_pushcfunction(L, protected_dispatch);
    lua_pushvalue(L, 3);
    lua_pushvalue(L, 4);
    lua_pushlightuserdata(L, (void*)h);
    lua_pushlightuserdata(L, (void*)bytes);
    if (lua_pcall(L, 4, 0, 0) != LUA_OK) {
        lua_pushcfunction(L, print);
        lua_pushvalue(L, -2);
        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            lua_pop(L, 2);
        } else {
            lua_pop(L, 1);
        }
    }
}

static int handle_dispatch(lua_State* L)
{
    pcap_t** h = check_handle(L, 1);
    int cnt = luaL_checkinteger(L, 2);

    luaL_checktype(L, 3, LUA_TFUNCTION);
    if (lua_gettop(L) == 3) {
        lua_pushnil(L);
    }
    lua_pushinteger(L, pcap_dispatch(*h, cnt, dispatch, (u_char*)L));
    return 1;
}

static int handle_dump_open(lua_State* L)
{
    pcap_t** h = check_handle(L, 1);
    const char* fname = luaL_checkstring(L, 2);
    pcap_dumper_t** d;

    d = lua_newuserdata(L, sizeof(*d));
    *d = pcap_dump_open(*h, fname);
    if (*d == NULL) {
        lua_pushnil(L);
        return 1;
    }
    luaL_setmetatable(L, LPCAP_DUMPER_TNAME);
    return 1;
}

static int handle_fileno(lua_State* L)
{
    lua_pushinteger(L, pcap_fileno(*check_handle(L, 1)));
    return 1;
}

static int handle_geterr(lua_State* L)
{
    lua_pushstring(L, pcap_geterr(*check_handle(L, 1)));
    return 1;
}

static int handle_getnonblock(lua_State* L)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;

    ret = pcap_getnonblock(*check_handle(L, 1), errbuf);
    lua_pushinteger(L, ret);
    if (ret == -1) {
        lua_pushstring(L, errbuf);
        return 2;
    }
    return 1;
}

static int handle_get_selectable_fd(lua_State* L)
{
    lua_pushinteger(L, pcap_get_selectable_fd(*check_handle(L, 1)));
    return 1;
}

#if PCAP_API_VERSION >= 151

static int handle_get_tstamp_precision(lua_State* L)
{
    lua_pushinteger(L, pcap_get_tstamp_precision(*check_handle(L, 1)));
    return 1;
}

#endif

static int handle_inject(lua_State* L)
{
    pcap_t** h = check_handle(L, 1);
    size_t len;
    const char* buf = luaL_checklstring(L, 2, &len);

    lua_pushinteger(L, pcap_inject(*h, buf, len));
    return 1;
}

static int handle_is_swapped(lua_State* L)
{
    lua_pushinteger(L, pcap_is_swapped(*check_handle(L, 1)));
    return 1;
}

static int protected_list_datalinks(lua_State* L)
{
    int* dlt_buf = lua_touserdata(L, 1);
    int nb_dlt = lua_tointeger(L, 1);
    int i;

    lua_createtable(L, nb_dlt, 0);
    for (i = 0; i < nb_dlt; ++i) {
        lua_pushinteger(L, dlt_buf[i]);
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

static int handle_list_datalinks(lua_State* L)
{
    pcap_t** h = check_handle(L, 1);
    int status;
    int* dlt_buf;
    int nb_dlt;

    nb_dlt = pcap_list_datalinks(*h, &dlt_buf);
    if (nb_dlt < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, nb_dlt);
        return 2;
    }
    lua_pushcfunction(L, protected_list_datalinks);
    lua_pushlightuserdata(L, dlt_buf);
    lua_pushinteger(L, nb_dlt);
    status = lua_pcall(L, 2, 1, 0);
    pcap_free_datalinks(dlt_buf);
    if (status != LUA_OK) {
        return lua_error(L);
    }
    return 1;
}

#if PCAP_API_VERSION >= 120

static int protected_list_tstamp_types(lua_State* L)
{
    int* tst_buf = lua_touserdata(L, 1);
    int nb_tst = lua_tointeger(L, 1);
    int i;

    lua_createtable(L, nb_tst, 0);
    for (i = 0; i < nb_tst; ++i) {
        lua_pushinteger(L, tst_buf[i]);
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

static int handle_list_tstamp_types(lua_State* L)
{
    pcap_t** h = check_handle(L, 1);
    int status;
    int* tst_buf;
    int nb_tst;

    nb_tst = pcap_list_tstamp_types(*h, &tst_buf);
    if (nb_tst < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, nb_tst);
        return 2;
    }
    lua_pushcfunction(L, protected_list_tstamp_types);
    lua_pushlightuserdata(L, tst_buf);
    lua_pushinteger(L, nb_tst);
    status = lua_pcall(L, 2, 1, 0);
    pcap_free_tstamp_types(tst_buf);
    if (status != LUA_OK) {
        return lua_error(L);
    }
    return 1;
}

#endif

static int handle_loop(lua_State* L)
{
    pcap_t** h = check_handle(L, 1);
    int cnt = luaL_checkinteger(L, 2);

    luaL_checktype(L, 3, LUA_TFUNCTION);
    if (lua_gettop(L) == 3) {
        lua_pushnil(L);
    }
    lua_pushinteger(L, pcap_loop(*h, cnt, dispatch, (u_char*)L));
    return 1;
}

static int handle_major_version(lua_State* L)
{
    lua_pushinteger(L, pcap_major_version(*check_handle(L, 1)));
    return 1;
}

static int handle_minor_version(lua_State* L)
{
    lua_pushinteger(L, pcap_minor_version(*check_handle(L, 1)));
    return 1;
}

static int handle_next(lua_State* L)
{
    struct pcap_pkthdr h;
    const u_char* data;

    data = pcap_next(*check_handle(L, 1), &h);
    if (data != NULL) {
        pkthdr2table(L, &h);
        lua_pushlstring(L, (const char*)data, h.caplen);
    } else {
        lua_pushnil(L);
        lua_pushnil(L);
    }
    return 2;
}

static int handle_next_ex(lua_State* L)
{
    struct pcap_pkthdr* h;
    const u_char* data;
    int ret;

    ret = pcap_next_ex(*check_handle(L, 1), &h, &data);
    lua_pushinteger(L, ret);
    if (ret == 1) {
        pkthdr2table(L, h);
        lua_pushlstring(L, (const char*)data, h->caplen);
        return 3;
    }
    return 1;
}

static int handle_sendpacket(lua_State* L)
{
    pcap_t** h = check_handle(L, 1);
    size_t len;
    const char* buf = luaL_checklstring(L, 2, &len);

    lua_pushinteger(L, pcap_sendpacket(*h, (const u_char*)buf, len));
    return 1;
}

static int handle_set_buffer_size(lua_State* L)
{
    lua_pushinteger(L, pcap_set_buffer_size(*check_handle(L, 1), luaL_checkinteger(L, 2)));
    return 1;
}

static int handle_set_datalink(lua_State* L)
{
    lua_pushinteger(L, pcap_set_datalink(*check_handle(L, 1), luaL_checkinteger(L, 2)));
    return 1;
}

static int handle_setdirection(lua_State* L)
{
    lua_pushinteger(L, pcap_setdirection(*check_handle(L, 1), luaL_checkinteger(L, 2)));
    return 1;
}

static int handle_setfilter(lua_State* L)
{
    lua_pushinteger(L, pcap_setfilter(*check_handle(L, 1), check_filter(L, 2)));
    return 1;
}

#if PCAP_API_VERSION >= 151

static int handle_set_immediate_mode(lua_State* L)
{
    lua_pushinteger(L, pcap_set_immediate_mode(*check_handle(L, 1), luaL_checkinteger(L, 2)));
    return 1;
}

#endif

static int handle_setnonblock(lua_State* L)
{
    pcap_t** h = check_handle(L, 1);
    int nonblock;
    char errbuf[PCAP_ERRBUF_SIZE];

    nonblock = lua_isnone(L, 2) ? 1 : lua_toboolean(L, 2);
    if (pcap_setnonblock(*h, nonblock, errbuf) == -1) {
        lua_pushstring(L, errbuf);
        return 1;
    }
    return 0;
}

static int handle_set_promisc(lua_State* L)
{
    lua_pushinteger(L, pcap_set_promisc(*check_handle(L, 1), luaL_checkinteger(L, 2)));
    return 1;
}

static int handle_set_rfmon(lua_State* L)
{
    lua_pushinteger(L, pcap_set_rfmon(*check_handle(L, 1), luaL_checkinteger(L, 2)));
    return 1;
}

static int handle_set_snaplen(lua_State* L)
{
    lua_pushinteger(L, pcap_set_snaplen(*check_handle(L, 1), luaL_checkinteger(L, 2)));
    return 1;
}

static int handle_set_timeout(lua_State* L)
{
    lua_pushinteger(L, pcap_set_timeout(*check_handle(L, 1), luaL_checkinteger(L, 2)));
    return 1;
}

#if PCAP_API_VERSION >= 151

static int handle_set_tstamp_precision(lua_State* L)
{
    lua_pushinteger(L, pcap_set_tstamp_precision(*check_handle(L, 1), luaL_checkinteger(L, 2)));
    return 1;
}

#endif

#if PCAP_API_VERSION >= 120

static int handle_set_tstamp_type(lua_State* L)
{
    lua_pushinteger(L, pcap_set_tstamp_type(*check_handle(L, 1), luaL_checkinteger(L, 2)));
    return 1;
}

#endif

static int handle_snapshot(lua_State* L)
{
    lua_pushinteger(L, pcap_snapshot(*check_handle(L, 1)));
    return 1;
}

static int handle_stats(lua_State* L)
{
    struct pcap_stat stat;
    int ret;

    ret = pcap_stats(*check_handle(L, 1), &stat);
    if (ret == -1) {
        lua_pushnil(L);
        return 1;
    }
    lua_createtable(L, 0, 3);
    lua_pushnumber(L, stat.ps_recv);
    lua_setfield(L, -2, "ps_recv");
    lua_pushnumber(L, stat.ps_drop);
    lua_setfield(L, -2, "ps_drop");
    lua_pushnumber(L, stat.ps_ifdrop);
    lua_setfield(L, -2, "ps_ifdrop");
    return 1;
}

static int handle_gc(lua_State* L)
{
    return handle_close(L);
}

static const luaL_Reg lpcap_handle_meth[] = {
    {"activate", handle_activate},
    {"breakloop", handle_breakloop},
    {"can_set_rfmon", handle_can_set_rfmon},
    {"close", handle_close},
    {"compile", handle_compile},
    {"datalink", handle_datalink},
    {"dispatch", handle_dispatch},
    {"dump_open", handle_dump_open},
    {"fileno", handle_fileno},
    {"geterr", handle_geterr},
    {"getnonblock", handle_getnonblock},
    {"get_selectable_fd", handle_get_selectable_fd},
#if PCAP_API_VERSION >= 151
    {"get_tstamp_precision", handle_get_tstamp_precision},
#endif
    {"inject", handle_inject},
    {"is_swapped", handle_is_swapped},
    {"list_datalinks", handle_list_datalinks},
#if PCAP_API_VERSION >= 120
    {"list_tstamp_types", handle_list_tstamp_types},
#endif
    {"loop", handle_loop},
    {"major_version", handle_major_version},
    {"minor_version", handle_minor_version},
    {"next", handle_next},
    {"next_ex", handle_next_ex},
    {"sendpacket", handle_sendpacket},
    {"set_buffer_size", handle_set_buffer_size},
    {"set_datalink", handle_set_datalink},
    {"setdirection", handle_setdirection},
    {"setfilter", handle_setfilter},
#if PCAP_API_VERSION >= 151
    {"set_immediate_mode", handle_set_immediate_mode},
#endif
    {"setnonblock", handle_setnonblock},
    {"set_promisc", handle_set_promisc},
    {"set_rfmon", handle_set_rfmon},
    {"set_snaplen", handle_set_snaplen},
    {"set_timeout", handle_set_timeout},
#if PCAP_API_VERSION >= 151
    {"set_tstamp_precision", handle_set_tstamp_precision},
#endif
#if PCAP_API_VERSION >= 120
    {"set_tstamp_type", handle_set_tstamp_type},
#endif
    {"snapshot", handle_snapshot},
    {"stats", handle_stats},
    {"__gc", handle_gc},
    {NULL, NULL}
};

static void create_handle_meta(lua_State* L)
{
    luaL_newmetatable(L, LPCAP_HANDLE_TNAME);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, lpcap_handle_meth, 0);
    lua_pop(L, 1);
}

static int lpcap_create(lua_State* L)
{
    const char* source = luaL_checkstring(L, 1);
    pcap_t** h;
    char errbuf[PCAP_ERRBUF_SIZE];

    h = lua_newuserdata(L, sizeof(*h));
    *h = pcap_create(source, errbuf);
    if (*h == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, errbuf);
        return 2;
    }
    luaL_setmetatable(L, LPCAP_HANDLE_TNAME);
    return 1;
}

static int lpcap_datalink_name_to_val(lua_State* L)
{
    lua_pushinteger(L, pcap_datalink_name_to_val(luaL_checkstring(L, 1)));
    return 1;
}

static int lpcap_datalink_val_to_description(lua_State* L)
{
    lua_pushstring(L, pcap_datalink_val_to_description(luaL_checkinteger(L, 1)));
    return 1;
}

static int lpcap_datalink_val_to_name(lua_State* L)
{
    lua_pushstring(L, pcap_datalink_val_to_name(luaL_checkinteger(L, 1)));
    return 1;
}

static int lpcap_dump(lua_State* L)
{
    pcap_dumper_t** d = check_dumper(L, 1);
    size_t len;
    const char* data;
    struct pcap_pkthdr h;

    luaL_checktype(L, 2, LUA_TTABLE);
    data = luaL_checklstring(L, 3, &len);
    table2pkthdr(L, 2, &h);
    h.caplen = h.caplen > len ? len : h.caplen;
    pcap_dump((u_char*)*d, &h, (u_char*)data);
    return 0;
}

static int protected_findalldevs(lua_State* L)
{
    pcap_if_t* devs = lua_touserdata(L, 1);
    pcap_if_t* dev;
    pcap_addr_t* pa;
    int i, j;

    lua_newtable(L);
    for (i = 1, dev = devs; dev != NULL; ++i, dev = dev->next) {
        lua_createtable(L, 0, 4);
        lua_pushstring(L, dev->name);
        lua_setfield(L, -2, "name");
        lua_pushstring(L, dev->description == NULL ? "" : dev->description);
        lua_setfield(L, -2, "description");
        lua_pushnumber(L, dev->flags);
        lua_setfield(L, -2, "flags");
        lua_newtable(L);
        for (j = 1, pa = dev->addresses; pa != NULL; ++j, pa = pa->next) {
            lua_createtable(L, 0, 4);
            saddr2table(L, pa->addr);
            lua_setfield(L, -2, "addr");
            if (pa->netmask != NULL) {
                saddr2table(L, pa->netmask);
                lua_setfield(L, -2, "netmask");
            }
            if (pa->broadaddr != NULL) {
                saddr2table(L, pa->broadaddr);
                lua_setfield(L, -2, "broadaddr");
            }
            if (pa->dstaddr != NULL) {
                saddr2table(L, pa->dstaddr);
                lua_setfield(L, -2, "dstaddr");
            }
            lua_rawseti(L, -2, j);
        }
        lua_setfield(L, -2, "addresses");
        lua_rawseti(L, -2, i);
    }
    return 1;
}

static int lpcap_findalldevs(lua_State* L)
{
    pcap_if_t* devs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int status;

    if (pcap_findalldevs(&devs, errbuf) != 0) {
        lua_pushnil(L);
        lua_pushstring(L, errbuf);
        return 2;
    }
    lua_pushcfunction(L, protected_findalldevs);
    lua_pushlightuserdata(L, devs);
    status = lua_pcall(L, 1, 1, 0);
    pcap_freealldevs(devs);
    if (status != LUA_OK) {
        return lua_error(L);
    }
    return 1;
}

static int lpcap_lib_version(lua_State* L)
{
    lua_pushstring(L, pcap_lib_version());
    return 1;
}

static int lpcap_lookupdev(lua_State* L)
{
    char* dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, errbuf);
        return 2;
    }
    lua_pushstring(L, dev);
    return 1;
}

static int lpcap_lookupnet(lua_State* L)
{
    const char* dev = luaL_checkstring(L, 1);
    bpf_u_int32 net;
    bpf_u_int32 mask;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_lookupnet(dev, &net, &mask, errbuf) != 0) {
        lua_pushnil(L);
        lua_pushnil(L);
        lua_pushstring(L, errbuf);
        return 3;
    } else {
        lua_pushnumber(L, net);
        lua_pushnumber(L, mask);
        return 2;
    }
}

static int lpcap_open_dead(lua_State* L)
{
    int linktype = luaL_checkinteger(L, 1);
    int snaplen = luaL_checkinteger(L, 2);
    pcap_t** h;

    h = lua_newuserdata(L, sizeof(*h));
    *h = pcap_open_dead(linktype, snaplen);
    if (*h == NULL) {
        lua_pushnil(L);
        return 1;
    }
    luaL_setmetatable(L, LPCAP_HANDLE_TNAME);
    return 1;
}

static int lpcap_open_live(lua_State* L)
{
    const char* device = luaL_checkstring(L, 1);
    int snaplen = luaL_checkinteger(L, 2);
    int promisc = lua_toboolean(L, 3);
    int to_ms = luaL_checkinteger(L, 4);
    pcap_t** h;
    char errbuf[PCAP_ERRBUF_SIZE];

    h = lua_newuserdata(L, sizeof(*h));
    *h = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
    if (*h == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, errbuf);
        return 2;
    }
    luaL_setmetatable(L, LPCAP_HANDLE_TNAME);
    return 1;
}

static int lpcap_open_offline(lua_State* L)
{
    const char* fname = luaL_checkstring(L, 1);
    pcap_t** h;
    char errbuf[PCAP_ERRBUF_SIZE];

    h = lua_newuserdata(L, sizeof(*h));
    *h = pcap_open_offline(fname, errbuf);
    if (*h == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, errbuf);
        return 2;
    }
    luaL_setmetatable(L, LPCAP_HANDLE_TNAME);
    return 1;
}

static int lpcap_statustostr(lua_State* L)
{
    lua_pushstring(L, pcap_statustostr(luaL_checkinteger(L, 1)));
    return 1;
}

static int lpcap_strerror(lua_State* L)
{
    lua_pushstring(L, pcap_strerror(luaL_checkinteger(L, 1)));
    return 1;
}

#if PCAP_API_VERSION >= 120

static int lpcap_tstamp_type_name_to_val(lua_State* L)
{
    lua_pushinteger(L, pcap_tstamp_type_name_to_val(luaL_checkstring(L, 1)));
    return 1;
}

static int lpcap_tstamp_type_val_to_name(lua_State* L)
{
    lua_pushstring(L, pcap_tstamp_type_val_to_name(luaL_checkinteger(L, 1)));
    return 1;
}

#endif

static const luaL_Reg lpcaplib[] = {
    {"create", lpcap_create},
    {"datalink_name_to_val", lpcap_datalink_name_to_val},
    {"datalink_val_to_description", lpcap_datalink_val_to_description},
    {"datalink_val_to_name", lpcap_datalink_val_to_name},
    {"dump", lpcap_dump},
    {"findalldevs", lpcap_findalldevs},
    {"lib_version", lpcap_lib_version},
    {"lookupdev", lpcap_lookupdev},
    {"lookupnet", lpcap_lookupnet},
    {"open_dead", lpcap_open_dead},
    {"open_live", lpcap_open_live},
    {"open_offline", lpcap_open_offline},
    {"statustostr", lpcap_statustostr},
    {"strerror", lpcap_strerror},
#if PCAP_API_VERSION >= 120
    {"tstamp_type_name_to_val", lpcap_tstamp_type_name_to_val},
    {"tstamp_type_val_to_name", lpcap_tstamp_type_val_to_name},
#endif
    {NULL, NULL}
};

int luaopen_lpcap(lua_State* L)
{
    luaL_newlib(L, lpcaplib);
#ifdef DLT_A429
    lua_pushnumber(L, DLT_A429);
    lua_setfield(L, -2, "DLT_A429");
#endif
#ifdef DLT_A653_ICM
    lua_pushnumber(L, DLT_A653_ICM);
    lua_setfield(L, -2, "DLT_A653_ICM");
#endif
#ifdef DLT_AIRONET_HEADER
    lua_pushnumber(L, DLT_AIRONET_HEADER);
    lua_setfield(L, -2, "DLT_AIRONET_HEADER");
#endif
#ifdef DLT_AOS
    lua_pushnumber(L, DLT_AOS);
    lua_setfield(L, -2, "DLT_AOS");
#endif
#ifdef DLT_APPLE_IP_OVER_IEEE1394
    lua_pushnumber(L, DLT_APPLE_IP_OVER_IEEE1394);
    lua_setfield(L, -2, "DLT_APPLE_IP_OVER_IEEE1394");
#endif
#ifdef DLT_ARCNET
    lua_pushnumber(L, DLT_ARCNET);
    lua_setfield(L, -2, "DLT_ARCNET");
#endif
#ifdef DLT_ARCNET_LINUX
    lua_pushnumber(L, DLT_ARCNET_LINUX);
    lua_setfield(L, -2, "DLT_ARCNET_LINUX");
#endif
#ifdef DLT_ATM_CLIP
    lua_pushnumber(L, DLT_ATM_CLIP);
    lua_setfield(L, -2, "DLT_ATM_CLIP");
#endif
#ifdef DLT_ATM_RFC1483
    lua_pushnumber(L, DLT_ATM_RFC1483);
    lua_setfield(L, -2, "DLT_ATM_RFC1483");
#endif
#ifdef DLT_AURORA
    lua_pushnumber(L, DLT_AURORA);
    lua_setfield(L, -2, "DLT_AURORA");
#endif
#ifdef DLT_AX25
    lua_pushnumber(L, DLT_AX25);
    lua_setfield(L, -2, "DLT_AX25");
#endif
#ifdef DLT_AX25_KISS
    lua_pushnumber(L, DLT_AX25_KISS);
    lua_setfield(L, -2, "DLT_AX25_KISS");
#endif
#ifdef DLT_BACNET_MS_TP
    lua_pushnumber(L, DLT_BACNET_MS_TP);
    lua_setfield(L, -2, "DLT_BACNET_MS_TP");
#endif
#ifdef DLT_BLUETOOTH_HCI_H4
    lua_pushnumber(L, DLT_BLUETOOTH_HCI_H4);
    lua_setfield(L, -2, "DLT_BLUETOOTH_HCI_H4");
#endif
#ifdef DLT_BLUETOOTH_HCI_H4_WITH_PHDR
    lua_pushnumber(L, DLT_BLUETOOTH_HCI_H4_WITH_PHDR);
    lua_setfield(L, -2, "DLT_BLUETOOTH_HCI_H4_WITH_PHDR");
#endif
#ifdef DLT_BLUETOOTH_LE_LL
    lua_pushnumber(L, DLT_BLUETOOTH_LE_LL);
    lua_setfield(L, -2, "DLT_BLUETOOTH_LE_LL");
#endif
#ifdef DLT_CAN20B
    lua_pushnumber(L, DLT_CAN20B);
    lua_setfield(L, -2, "DLT_CAN20B");
#endif
#ifdef DLT_CAN_SOCKETCAN
    lua_pushnumber(L, DLT_CAN_SOCKETCAN);
    lua_setfield(L, -2, "DLT_CAN_SOCKETCAN");
#endif
#ifdef DLT_CHAOS
    lua_pushnumber(L, DLT_CHAOS);
    lua_setfield(L, -2, "DLT_CHAOS");
#endif
#ifdef DLT_CHDLC
    lua_pushnumber(L, DLT_CHDLC);
    lua_setfield(L, -2, "DLT_CHDLC");
#endif
#ifdef DLT_C_HDLC
    lua_pushnumber(L, DLT_C_HDLC);
    lua_setfield(L, -2, "DLT_C_HDLC");
#endif
#ifdef DLT_C_HDLC_WITH_DIR
    lua_pushnumber(L, DLT_C_HDLC_WITH_DIR);
    lua_setfield(L, -2, "DLT_C_HDLC_WITH_DIR");
#endif
#ifdef DLT_CIP
    lua_pushnumber(L, DLT_CIP);
    lua_setfield(L, -2, "DLT_CIP");
#endif
#ifdef DLT_CISCO_IOS
    lua_pushnumber(L, DLT_CISCO_IOS);
    lua_setfield(L, -2, "DLT_CISCO_IOS");
#endif
#ifdef DLT_DBUS
    lua_pushnumber(L, DLT_DBUS);
    lua_setfield(L, -2, "DLT_DBUS");
#endif
#ifdef DLT_DECT
    lua_pushnumber(L, DLT_DECT);
    lua_setfield(L, -2, "DLT_DECT");
#endif
#ifdef DLT_DOCSIS
    lua_pushnumber(L, DLT_DOCSIS);
    lua_setfield(L, -2, "DLT_DOCSIS");
#endif
#ifdef DLT_DVB_CI
    lua_pushnumber(L, DLT_DVB_CI);
    lua_setfield(L, -2, "DLT_DVB_CI");
#endif
#ifdef DLT_ECONET
    lua_pushnumber(L, DLT_ECONET);
    lua_setfield(L, -2, "DLT_ECONET");
#endif
#ifdef DLT_EN10MB
    lua_pushnumber(L, DLT_EN10MB);
    lua_setfield(L, -2, "DLT_EN10MB");
#endif
#ifdef DLT_EN3MB
    lua_pushnumber(L, DLT_EN3MB);
    lua_setfield(L, -2, "DLT_EN3MB");
#endif
#ifdef DLT_ENC
    lua_pushnumber(L, DLT_ENC);
    lua_setfield(L, -2, "DLT_ENC");
#endif
#ifdef DLT_ERF
    lua_pushnumber(L, DLT_ERF);
    lua_setfield(L, -2, "DLT_ERF");
#endif
#ifdef DLT_ERF_ETH
    lua_pushnumber(L, DLT_ERF_ETH);
    lua_setfield(L, -2, "DLT_ERF_ETH");
#endif
#ifdef DLT_ERF_POS
    lua_pushnumber(L, DLT_ERF_POS);
    lua_setfield(L, -2, "DLT_ERF_POS");
#endif
#ifdef DLT_FC_2
    lua_pushnumber(L, DLT_FC_2);
    lua_setfield(L, -2, "DLT_FC_2");
#endif
#ifdef DLT_FC_2_WITH_FRAME_DELIMS
    lua_pushnumber(L, DLT_FC_2_WITH_FRAME_DELIMS);
    lua_setfield(L, -2, "DLT_FC_2_WITH_FRAME_DELIMS");
#endif
#ifdef DLT_FDDI
    lua_pushnumber(L, DLT_FDDI);
    lua_setfield(L, -2, "DLT_FDDI");
#endif
#ifdef DLT_FLEXRAY
    lua_pushnumber(L, DLT_FLEXRAY);
    lua_setfield(L, -2, "DLT_FLEXRAY");
#endif
#ifdef DLT_FR
    lua_pushnumber(L, DLT_FR);
    lua_setfield(L, -2, "DLT_FR");
#endif
#ifdef DLT_FRELAY
    lua_pushnumber(L, DLT_FRELAY);
    lua_setfield(L, -2, "DLT_FRELAY");
#endif
#ifdef DLT_FRELAY_WITH_DIR
    lua_pushnumber(L, DLT_FRELAY_WITH_DIR);
    lua_setfield(L, -2, "DLT_FRELAY_WITH_DIR");
#endif
#ifdef DLT_GCOM_SERIAL
    lua_pushnumber(L, DLT_GCOM_SERIAL);
    lua_setfield(L, -2, "DLT_GCOM_SERIAL");
#endif
#ifdef DLT_GCOM_T1E1
    lua_pushnumber(L, DLT_GCOM_T1E1);
    lua_setfield(L, -2, "DLT_GCOM_T1E1");
#endif
#ifdef DLT_GPF_F
    lua_pushnumber(L, DLT_GPF_F);
    lua_setfield(L, -2, "DLT_GPF_F");
#endif
#ifdef DLT_GPF_T
    lua_pushnumber(L, DLT_GPF_T);
    lua_setfield(L, -2, "DLT_GPF_T");
#endif
#ifdef DLT_GPRS_LLC
    lua_pushnumber(L, DLT_GPRS_LLC);
    lua_setfield(L, -2, "DLT_GPRS_LLC");
#endif
#ifdef DLT_GSMTAP_ABIS
    lua_pushnumber(L, DLT_GSMTAP_ABIS);
    lua_setfield(L, -2, "DLT_GSMTAP_ABIS");
#endif
#ifdef DLT_GSMTAP_UM
    lua_pushnumber(L, DLT_GSMTAP_UM);
    lua_setfield(L, -2, "DLT_GSMTAP_UM");
#endif
#ifdef DLT_HHDLC
    lua_pushnumber(L, DLT_HHDLC);
    lua_setfield(L, -2, "DLT_HHDLC");
#endif
#ifdef DLT_IBM_SN
    lua_pushnumber(L, DLT_IBM_SN);
    lua_setfield(L, -2, "DLT_IBM_SN");
#endif
#ifdef DLT_IBM_SP
    lua_pushnumber(L, DLT_IBM_SP);
    lua_setfield(L, -2, "DLT_IBM_SP");
#endif
#ifdef DLT_IEEE802
    lua_pushnumber(L, DLT_IEEE802);
    lua_setfield(L, -2, "DLT_IEEE802");
#endif
#ifdef DLT_IEEE802_11
    lua_pushnumber(L, DLT_IEEE802_11);
    lua_setfield(L, -2, "DLT_IEEE802_11");
#endif
#ifdef DLT_IEEE802_11_RADIO
    lua_pushnumber(L, DLT_IEEE802_11_RADIO);
    lua_setfield(L, -2, "DLT_IEEE802_11_RADIO");
#endif
#ifdef DLT_IEEE802_11_RADIO_AVS
    lua_pushnumber(L, DLT_IEEE802_11_RADIO_AVS);
    lua_setfield(L, -2, "DLT_IEEE802_11_RADIO_AVS");
#endif
#ifdef DLT_IEEE802_15_4
    lua_pushnumber(L, DLT_IEEE802_15_4);
    lua_setfield(L, -2, "DLT_IEEE802_15_4");
#endif
#ifdef DLT_IEEE802_15_4_LINUX
    lua_pushnumber(L, DLT_IEEE802_15_4_LINUX);
    lua_setfield(L, -2, "DLT_IEEE802_15_4_LINUX");
#endif
#ifdef DLT_IEEE802_15_4_NOFCS
    lua_pushnumber(L, DLT_IEEE802_15_4_NOFCS);
    lua_setfield(L, -2, "DLT_IEEE802_15_4_NOFCS");
#endif
#ifdef DLT_IEEE802_15_4_NONASK_PHY
    lua_pushnumber(L, DLT_IEEE802_15_4_NONASK_PHY);
    lua_setfield(L, -2, "DLT_IEEE802_15_4_NONASK_PHY");
#endif
#ifdef DLT_IEEE802_16_MAC_CPS
    lua_pushnumber(L, DLT_IEEE802_16_MAC_CPS);
    lua_setfield(L, -2, "DLT_IEEE802_16_MAC_CPS");
#endif
#ifdef DLT_IEEE802_16_MAC_CPS_RADIO
    lua_pushnumber(L, DLT_IEEE802_16_MAC_CPS_RADIO);
    lua_setfield(L, -2, "DLT_IEEE802_16_MAC_CPS_RADIO");
#endif
#ifdef DLT_INFINIBAND
    lua_pushnumber(L, DLT_INFINIBAND);
    lua_setfield(L, -2, "DLT_INFINIBAND");
#endif
#ifdef DLT_IPFILTER
    lua_pushnumber(L, DLT_IPFILTER);
    lua_setfield(L, -2, "DLT_IPFILTER");
#endif
#ifdef DLT_IPMB
    lua_pushnumber(L, DLT_IPMB);
    lua_setfield(L, -2, "DLT_IPMB");
#endif
#ifdef DLT_IPMB_LINUX
    lua_pushnumber(L, DLT_IPMB_LINUX);
    lua_setfield(L, -2, "DLT_IPMB_LINUX");
#endif
#ifdef DLT_IPNET
    lua_pushnumber(L, DLT_IPNET);
    lua_setfield(L, -2, "DLT_IPNET");
#endif
#ifdef DLT_IPOIB
    lua_pushnumber(L, DLT_IPOIB);
    lua_setfield(L, -2, "DLT_IPOIB");
#endif
#ifdef DLT_IP_OVER_FC
    lua_pushnumber(L, DLT_IP_OVER_FC);
    lua_setfield(L, -2, "DLT_IP_OVER_FC");
#endif
#ifdef DLT_IPV4
    lua_pushnumber(L, DLT_IPV4);
    lua_setfield(L, -2, "DLT_IPV4");
#endif
#ifdef DLT_IPV6
    lua_pushnumber(L, DLT_IPV6);
    lua_setfield(L, -2, "DLT_IPV6");
#endif
#ifdef DLT_IRDA
    lua_pushnumber(L, DLT_IRDA);
    lua_setfield(L, -2, "DLT_IRDA");
#endif
#ifdef DLT_JUNIPER_ATM1
    lua_pushnumber(L, DLT_JUNIPER_ATM1);
    lua_setfield(L, -2, "DLT_JUNIPER_ATM1");
#endif
#ifdef DLT_JUNIPER_ATM2
    lua_pushnumber(L, DLT_JUNIPER_ATM2);
    lua_setfield(L, -2, "DLT_JUNIPER_ATM2");
#endif
#ifdef DLT_JUNIPER_ATM_CEMIC
    lua_pushnumber(L, DLT_JUNIPER_ATM_CEMIC);
    lua_setfield(L, -2, "DLT_JUNIPER_ATM_CEMIC");
#endif
#ifdef DLT_JUNIPER_CHDLC
    lua_pushnumber(L, DLT_JUNIPER_CHDLC);
    lua_setfield(L, -2, "DLT_JUNIPER_CHDLC");
#endif
#ifdef DLT_JUNIPER_ES
    lua_pushnumber(L, DLT_JUNIPER_ES);
    lua_setfield(L, -2, "DLT_JUNIPER_ES");
#endif
#ifdef DLT_JUNIPER_ETHER
    lua_pushnumber(L, DLT_JUNIPER_ETHER);
    lua_setfield(L, -2, "DLT_JUNIPER_ETHER");
#endif
#ifdef DLT_JUNIPER_FIBRECHANNEL
    lua_pushnumber(L, DLT_JUNIPER_FIBRECHANNEL);
    lua_setfield(L, -2, "DLT_JUNIPER_FIBRECHANNEL");
#endif
#ifdef DLT_JUNIPER_FRELAY
    lua_pushnumber(L, DLT_JUNIPER_FRELAY);
    lua_setfield(L, -2, "DLT_JUNIPER_FRELAY");
#endif
#ifdef DLT_JUNIPER_GGSN
    lua_pushnumber(L, DLT_JUNIPER_GGSN);
    lua_setfield(L, -2, "DLT_JUNIPER_GGSN");
#endif
#ifdef DLT_JUNIPER_ISM
    lua_pushnumber(L, DLT_JUNIPER_ISM);
    lua_setfield(L, -2, "DLT_JUNIPER_ISM");
#endif
#ifdef DLT_JUNIPER_MFR
    lua_pushnumber(L, DLT_JUNIPER_MFR);
    lua_setfield(L, -2, "DLT_JUNIPER_MFR");
#endif
#ifdef DLT_JUNIPER_MLFR
    lua_pushnumber(L, DLT_JUNIPER_MLFR);
    lua_setfield(L, -2, "DLT_JUNIPER_MLFR");
#endif
#ifdef DLT_JUNIPER_MLPPP
    lua_pushnumber(L, DLT_JUNIPER_MLPPP);
    lua_setfield(L, -2, "DLT_JUNIPER_MLPPP");
#endif
#ifdef DLT_JUNIPER_MONITOR
    lua_pushnumber(L, DLT_JUNIPER_MONITOR);
    lua_setfield(L, -2, "DLT_JUNIPER_MONITOR");
#endif
#ifdef DLT_JUNIPER_PIC_PEER
    lua_pushnumber(L, DLT_JUNIPER_PIC_PEER);
    lua_setfield(L, -2, "DLT_JUNIPER_PIC_PEER");
#endif
#ifdef DLT_JUNIPER_PPP
    lua_pushnumber(L, DLT_JUNIPER_PPP);
    lua_setfield(L, -2, "DLT_JUNIPER_PPP");
#endif
#ifdef DLT_JUNIPER_PPPOE
    lua_pushnumber(L, DLT_JUNIPER_PPPOE);
    lua_setfield(L, -2, "DLT_JUNIPER_PPPOE");
#endif
#ifdef DLT_JUNIPER_PPPOE_ATM
    lua_pushnumber(L, DLT_JUNIPER_PPPOE_ATM);
    lua_setfield(L, -2, "DLT_JUNIPER_PPPOE_ATM");
#endif
#ifdef DLT_JUNIPER_SERVICES
    lua_pushnumber(L, DLT_JUNIPER_SERVICES);
    lua_setfield(L, -2, "DLT_JUNIPER_SERVICES");
#endif
#ifdef DLT_JUNIPER_SRX_E2E
    lua_pushnumber(L, DLT_JUNIPER_SRX_E2E);
    lua_setfield(L, -2, "DLT_JUNIPER_SRX_E2E");
#endif
#ifdef DLT_JUNIPER_ST
    lua_pushnumber(L, DLT_JUNIPER_ST);
    lua_setfield(L, -2, "DLT_JUNIPER_ST");
#endif
#ifdef DLT_JUNIPER_VP
    lua_pushnumber(L, DLT_JUNIPER_VP);
    lua_setfield(L, -2, "DLT_JUNIPER_VP");
#endif
#ifdef DLT_JUNIPER_VS
    lua_pushnumber(L, DLT_JUNIPER_VS);
    lua_setfield(L, -2, "DLT_JUNIPER_VS");
#endif
#ifdef DLT_LANE8023
    lua_pushnumber(L, DLT_LANE8023);
    lua_setfield(L, -2, "DLT_LANE8023");
#endif
#ifdef DLT_LAPB_WITH_DIR
    lua_pushnumber(L, DLT_LAPB_WITH_DIR);
    lua_setfield(L, -2, "DLT_LAPB_WITH_DIR");
#endif
#ifdef DLT_LAPD
    lua_pushnumber(L, DLT_LAPD);
    lua_setfield(L, -2, "DLT_LAPD");
#endif
#ifdef DLT_LIN
    lua_pushnumber(L, DLT_LIN);
    lua_setfield(L, -2, "DLT_LIN");
#endif
#ifdef DLT_LINUX_EVDEV
    lua_pushnumber(L, DLT_LINUX_EVDEV);
    lua_setfield(L, -2, "DLT_LINUX_EVDEV");
#endif
#ifdef DLT_LINUX_IRDA
    lua_pushnumber(L, DLT_LINUX_IRDA);
    lua_setfield(L, -2, "DLT_LINUX_IRDA");
#endif
#ifdef DLT_LINUX_LAPD
    lua_pushnumber(L, DLT_LINUX_LAPD);
    lua_setfield(L, -2, "DLT_LINUX_LAPD");
#endif
#ifdef DLT_LINUX_PPP_WITHDIRECTION
    lua_pushnumber(L, DLT_LINUX_PPP_WITHDIRECTION);
    lua_setfield(L, -2, "DLT_LINUX_PPP_WITHDIRECTION");
#endif
#ifdef DLT_LINUX_SLL
    lua_pushnumber(L, DLT_LINUX_SLL);
    lua_setfield(L, -2, "DLT_LINUX_SLL");
#endif
#ifdef DLT_LOOP
    lua_pushnumber(L, DLT_LOOP);
    lua_setfield(L, -2, "DLT_LOOP");
#endif
#ifdef DLT_LTALK
    lua_pushnumber(L, DLT_LTALK);
    lua_setfield(L, -2, "DLT_LTALK");
#endif
#ifdef DLT_MFR
    lua_pushnumber(L, DLT_MFR);
    lua_setfield(L, -2, "DLT_MFR");
#endif
#ifdef DLT_MOST
    lua_pushnumber(L, DLT_MOST);
    lua_setfield(L, -2, "DLT_MOST");
#endif
#ifdef DLT_MPEG_2_TS
    lua_pushnumber(L, DLT_MPEG_2_TS);
    lua_setfield(L, -2, "DLT_MPEG_2_TS");
#endif
#ifdef DLT_MPLS
    lua_pushnumber(L, DLT_MPLS);
    lua_setfield(L, -2, "DLT_MPLS");
#endif
#ifdef DLT_MTP2
    lua_pushnumber(L, DLT_MTP2);
    lua_setfield(L, -2, "DLT_MTP2");
#endif
#ifdef DLT_MTP2_WITH_PHDR
    lua_pushnumber(L, DLT_MTP2_WITH_PHDR);
    lua_setfield(L, -2, "DLT_MTP2_WITH_PHDR");
#endif
#ifdef DLT_MTP3
    lua_pushnumber(L, DLT_MTP3);
    lua_setfield(L, -2, "DLT_MTP3");
#endif
#ifdef DLT_MUX27010
    lua_pushnumber(L, DLT_MUX27010);
    lua_setfield(L, -2, "DLT_MUX27010");
#endif
#ifdef DLT_NETANALYZER
    lua_pushnumber(L, DLT_NETANALYZER);
    lua_setfield(L, -2, "DLT_NETANALYZER");
#endif
#ifdef DLT_NETANALYZER_TRANSPARENT
    lua_pushnumber(L, DLT_NETANALYZER_TRANSPARENT);
    lua_setfield(L, -2, "DLT_NETANALYZER_TRANSPARENT");
#endif
#ifdef DLT_NFC_LLCP
    lua_pushnumber(L, DLT_NFC_LLCP);
    lua_setfield(L, -2, "DLT_NFC_LLCP");
#endif
#ifdef DLT_NFLOG
    lua_pushnumber(L, DLT_NFLOG);
    lua_setfield(L, -2, "DLT_NFLOG");
#endif
#ifdef DLT_NG40
    lua_pushnumber(L, DLT_NG40);
    lua_setfield(L, -2, "DLT_NG40");
#endif
#ifdef DLT_NULL
    lua_pushnumber(L, DLT_NULL);
    lua_setfield(L, -2, "DLT_NULL");
#endif
#ifdef DLT_PCI_EXP
    lua_pushnumber(L, DLT_PCI_EXP);
    lua_setfield(L, -2, "DLT_PCI_EXP");
#endif
#ifdef DLT_PFLOG
    lua_pushnumber(L, DLT_PFLOG);
    lua_setfield(L, -2, "DLT_PFLOG");
#endif
#ifdef DLT_PFSYNC
    lua_pushnumber(L, DLT_PFSYNC);
    lua_setfield(L, -2, "DLT_PFSYNC");
#endif
#ifdef DLT_PPI
    lua_pushnumber(L, DLT_PPI);
    lua_setfield(L, -2, "DLT_PPI");
#endif
#ifdef DLT_PPP
    lua_pushnumber(L, DLT_PPP);
    lua_setfield(L, -2, "DLT_PPP");
#endif
#ifdef DLT_PPP_BSDOS
    lua_pushnumber(L, DLT_PPP_BSDOS);
    lua_setfield(L, -2, "DLT_PPP_BSDOS");
#endif
#ifdef DLT_PPP_ETHER
    lua_pushnumber(L, DLT_PPP_ETHER);
    lua_setfield(L, -2, "DLT_PPP_ETHER");
#endif
#ifdef DLT_PPP_PPPD
    lua_pushnumber(L, DLT_PPP_PPPD);
    lua_setfield(L, -2, "DLT_PPP_PPPD");
#endif
#ifdef DLT_PPP_SERIAL
    lua_pushnumber(L, DLT_PPP_SERIAL);
    lua_setfield(L, -2, "DLT_PPP_SERIAL");
#endif
#ifdef DLT_PPP_WITH_DIR
    lua_pushnumber(L, DLT_PPP_WITH_DIR);
    lua_setfield(L, -2, "DLT_PPP_WITH_DIR");
#endif
#ifdef DLT_PPP_WITH_DIRECTION
    lua_pushnumber(L, DLT_PPP_WITH_DIRECTION);
    lua_setfield(L, -2, "DLT_PPP_WITH_DIRECTION");
#endif
#ifdef DLT_PRISM_HEADER
    lua_pushnumber(L, DLT_PRISM_HEADER);
    lua_setfield(L, -2, "DLT_PRISM_HEADER");
#endif
#ifdef DLT_PRONET
    lua_pushnumber(L, DLT_PRONET);
    lua_setfield(L, -2, "DLT_PRONET");
#endif
#ifdef DLT_RAIF1
    lua_pushnumber(L, DLT_RAIF1);
    lua_setfield(L, -2, "DLT_RAIF1");
#endif
#ifdef DLT_RAW
    lua_pushnumber(L, DLT_RAW);
    lua_setfield(L, -2, "DLT_RAW");
#endif
#ifdef DLT_REDBACK_SMARTEDGE
    lua_pushnumber(L, DLT_REDBACK_SMARTEDGE);
    lua_setfield(L, -2, "DLT_REDBACK_SMARTEDGE");
#endif
#ifdef DLT_RIO
    lua_pushnumber(L, DLT_RIO);
    lua_setfield(L, -2, "DLT_RIO");
#endif
#ifdef DLT_RTAC_SERIAL
    lua_pushnumber(L, DLT_RTAC_SERIAL);
    lua_setfield(L, -2, "DLT_RTAC_SERIAL");
#endif
#ifdef DLT_SCCP
    lua_pushnumber(L, DLT_SCCP);
    lua_setfield(L, -2, "DLT_SCCP");
#endif
#ifdef DLT_SCTP
    lua_pushnumber(L, DLT_SCTP);
    lua_setfield(L, -2, "DLT_SCTP");
#endif
#ifdef DLT_SITA
    lua_pushnumber(L, DLT_SITA);
    lua_setfield(L, -2, "DLT_SITA");
#endif
#ifdef DLT_SLIP
    lua_pushnumber(L, DLT_SLIP);
    lua_setfield(L, -2, "DLT_SLIP");
#endif
#ifdef DLT_SLIP_BSDOS
    lua_pushnumber(L, DLT_SLIP_BSDOS);
    lua_setfield(L, -2, "DLT_SLIP_BSDOS");
#endif
#ifdef DLT_STANAG_5066_D_PDU
    lua_pushnumber(L, DLT_STANAG_5066_D_PDU);
    lua_setfield(L, -2, "DLT_STANAG_5066_D_PDU");
#endif
#ifdef DLT_SUNATM
    lua_pushnumber(L, DLT_SUNATM);
    lua_setfield(L, -2, "DLT_SUNATM");
#endif
#ifdef DLT_SYMANTEC_FIREWALL
    lua_pushnumber(L, DLT_SYMANTEC_FIREWALL);
    lua_setfield(L, -2, "DLT_SYMANTEC_FIREWALL");
#endif
#ifdef DLT_TZSP
    lua_pushnumber(L, DLT_TZSP);
    lua_setfield(L, -2, "DLT_TZSP");
#endif
#ifdef DLT_USB
    lua_pushnumber(L, DLT_USB);
    lua_setfield(L, -2, "DLT_USB");
#endif
#ifdef DLT_USB_LINUX
    lua_pushnumber(L, DLT_USB_LINUX);
    lua_setfield(L, -2, "DLT_USB_LINUX");
#endif
#ifdef DLT_USB_LINUX_MMAPPED
    lua_pushnumber(L, DLT_USB_LINUX_MMAPPED);
    lua_setfield(L, -2, "DLT_USB_LINUX_MMAPPED");
#endif
#ifdef DLT_USBPCAP
    lua_pushnumber(L, DLT_USBPCAP);
    lua_setfield(L, -2, "DLT_USBPCAP");
#endif
#ifdef DLT_USER0
    lua_pushnumber(L, DLT_USER0);
    lua_setfield(L, -2, "DLT_USER0");
#endif
#ifdef DLT_USER1
    lua_pushnumber(L, DLT_USER1);
    lua_setfield(L, -2, "DLT_USER1");
#endif
#ifdef DLT_USER10
    lua_pushnumber(L, DLT_USER10);
    lua_setfield(L, -2, "DLT_USER10");
#endif
#ifdef DLT_USER11
    lua_pushnumber(L, DLT_USER11);
    lua_setfield(L, -2, "DLT_USER11");
#endif
#ifdef DLT_USER12
    lua_pushnumber(L, DLT_USER12);
    lua_setfield(L, -2, "DLT_USER12");
#endif
#ifdef DLT_USER13
    lua_pushnumber(L, DLT_USER13);
    lua_setfield(L, -2, "DLT_USER13");
#endif
#ifdef DLT_USER14
    lua_pushnumber(L, DLT_USER14);
    lua_setfield(L, -2, "DLT_USER14");
#endif
#ifdef DLT_USER15
    lua_pushnumber(L, DLT_USER15);
    lua_setfield(L, -2, "DLT_USER15");
#endif
#ifdef DLT_USER2
    lua_pushnumber(L, DLT_USER2);
    lua_setfield(L, -2, "DLT_USER2");
#endif
#ifdef DLT_USER3
    lua_pushnumber(L, DLT_USER3);
    lua_setfield(L, -2, "DLT_USER3");
#endif
#ifdef DLT_USER4
    lua_pushnumber(L, DLT_USER4);
    lua_setfield(L, -2, "DLT_USER4");
#endif
#ifdef DLT_USER5
    lua_pushnumber(L, DLT_USER5);
    lua_setfield(L, -2, "DLT_USER5");
#endif
#ifdef DLT_USER6
    lua_pushnumber(L, DLT_USER6);
    lua_setfield(L, -2, "DLT_USER6");
#endif
#ifdef DLT_USER7
    lua_pushnumber(L, DLT_USER7);
    lua_setfield(L, -2, "DLT_USER7");
#endif
#ifdef DLT_USER8
    lua_pushnumber(L, DLT_USER8);
    lua_setfield(L, -2, "DLT_USER8");
#endif
#ifdef DLT_USER9
    lua_pushnumber(L, DLT_USER9);
    lua_setfield(L, -2, "DLT_USER9");
#endif
#ifdef DLT_WIHART
    lua_pushnumber(L, DLT_WIHART);
    lua_setfield(L, -2, "DLT_WIHART");
#endif
#ifdef DLT_WIRESHARK_UPPER_PDU
    lua_pushnumber(L, DLT_WIRESHARK_UPPER_PDU);
    lua_setfield(L, -2, "DLT_WIRESHARK_UPPER_PDU");
#endif
#ifdef DLT_X2E_SERIAL
    lua_pushnumber(L, DLT_X2E_SERIAL);
    lua_setfield(L, -2, "DLT_X2E_SERIAL");
#endif
#ifdef DLT_X2E_XORAYA
    lua_pushnumber(L, DLT_X2E_XORAYA);
    lua_setfield(L, -2, "DLT_X2E_XORAYA");
#endif
    lua_pushnumber(L, PCAP_D_IN);
    lua_setfield(L, -2, "PCAP_D_IN");
    lua_pushnumber(L, PCAP_D_INOUT);
    lua_setfield(L, -2, "PCAP_D_INOUT");
    lua_pushnumber(L, PCAP_D_OUT);
    lua_setfield(L, -2, "PCAP_D_OUT");
#ifdef PCAP_ERROR
    lua_pushnumber(L, PCAP_ERROR);
    lua_setfield(L, -2, "PCAP_ERROR");
#endif
#ifdef PCAP_ERROR_ACTIVATED
    lua_pushnumber(L, PCAP_ERROR_ACTIVATED);
    lua_setfield(L, -2, "PCAP_ERROR_ACTIVATED");
#endif
#ifdef PCAP_ERROR_BREAK
    lua_pushnumber(L, PCAP_ERROR_BREAK);
    lua_setfield(L, -2, "PCAP_ERROR_BREAK");
#endif
#ifdef PCAP_ERROR_CANTSET_TSTAMP_TYPE
    lua_pushnumber(L, PCAP_ERROR_CANTSET_TSTAMP_TYPE);
    lua_setfield(L, -2, "PCAP_ERROR_CANTSET_TSTAMP_TYPE");
#endif
#ifdef PCAP_ERROR_IFACE_NOT_UP
    lua_pushnumber(L, PCAP_ERROR_IFACE_NOT_UP);
    lua_setfield(L, -2, "PCAP_ERROR_IFACE_NOT_UP");
#endif
#ifdef PCAP_ERROR_NO_SUCH_DEVICE
    lua_pushnumber(L, PCAP_ERROR_NO_SUCH_DEVICE);
    lua_setfield(L, -2, "PCAP_ERROR_NO_SUCH_DEVICE");
#endif
#ifdef PCAP_ERROR_NOT_ACTIVATED
    lua_pushnumber(L, PCAP_ERROR_NOT_ACTIVATED);
    lua_setfield(L, -2, "PCAP_ERROR_NOT_ACTIVATED");
#endif
#ifdef PCAP_ERROR_NOT_RFMON
    lua_pushnumber(L, PCAP_ERROR_NOT_RFMON);
    lua_setfield(L, -2, "PCAP_ERROR_NOT_RFMON");
#endif
#ifdef PCAP_ERROR_PERM_DENIED
    lua_pushnumber(L, PCAP_ERROR_PERM_DENIED);
    lua_setfield(L, -2, "PCAP_ERROR_PERM_DENIED");
#endif
#ifdef PCAP_ERROR_PROMISC_PERM_DENIED
    lua_pushnumber(L, PCAP_ERROR_PROMISC_PERM_DENIED);
    lua_setfield(L, -2, "PCAP_ERROR_PROMISC_PERM_DENIED");
#endif
#ifdef PCAP_ERROR_RFMON_NOTSUP
    lua_pushnumber(L, PCAP_ERROR_RFMON_NOTSUP);
    lua_setfield(L, -2, "PCAP_ERROR_RFMON_NOTSUP");
#endif
#ifdef PCAP_ERROR_TSTAMP_PRECISION_NOTSUP
    lua_pushnumber(L, PCAP_ERROR_TSTAMP_PRECISION_NOTSUP);
    lua_setfield(L, -2, "PCAP_ERROR_TSTAMP_PRECISION_NOTSUP");
#endif
#ifdef PCAP_IF_LOOPBACK
    lua_pushnumber(L, PCAP_IF_LOOPBACK);
    lua_setfield(L, -2, "PCAP_IF_LOOPBACK");
#endif
#ifdef PCAP_NETMASK_UNKNOWN
    lua_pushnumber(L, PCAP_NETMASK_UNKNOWN);
    lua_setfield(L, -2, "PCAP_NETMASK_UNKNOWN");
#endif
#ifdef PCAP_TSTAMP_ADAPTER
    lua_pushnumber(L, PCAP_TSTAMP_ADAPTER);
    lua_setfield(L, -2, "PCAP_TSTAMP_ADAPTER");
#endif
#ifdef PCAP_TSTAMP_ADAPTER_UNSYNCED
    lua_pushnumber(L, PCAP_TSTAMP_ADAPTER_UNSYNCED);
    lua_setfield(L, -2, "PCAP_TSTAMP_ADAPTER_UNSYNCED");
#endif
#ifdef PCAP_TSTAMP_HOST
    lua_pushnumber(L, PCAP_TSTAMP_HOST);
    lua_setfield(L, -2, "PCAP_TSTAMP_HOST");
#endif
#ifdef PCAP_TSTAMP_HOST_HIPREC
    lua_pushnumber(L, PCAP_TSTAMP_HOST_HIPREC);
    lua_setfield(L, -2, "PCAP_TSTAMP_HOST_HIPREC");
#endif
#ifdef PCAP_TSTAMP_HOST_LOWPREC
    lua_pushnumber(L, PCAP_TSTAMP_HOST_LOWPREC);
    lua_setfield(L, -2, "PCAP_TSTAMP_HOST_LOWPREC");
#endif
#ifdef PCAP_TSTAMP_PRECISION_MICRO
    lua_pushnumber(L, PCAP_TSTAMP_PRECISION_MICRO);
    lua_setfield(L, -2, "PCAP_TSTAMP_PRECISION_MICRO");
#endif
#ifdef PCAP_TSTAMP_PRECISION_NANO
    lua_pushnumber(L, PCAP_TSTAMP_PRECISION_NANO);
    lua_setfield(L, -2, "PCAP_TSTAMP_PRECISION_NANO");
#endif
#ifdef PCAP_VERSION_MAJOR
    lua_pushnumber(L, PCAP_VERSION_MAJOR);
    lua_setfield(L, -2, "PCAP_VERSION_MAJOR");
#endif
#ifdef PCAP_VERSION_MINOR
    lua_pushnumber(L, PCAP_VERSION_MINOR);
    lua_setfield(L, -2, "PCAP_VERSION_MINOR");
#endif
#ifdef PCAP_WARNING
    lua_pushnumber(L, PCAP_WARNING);
    lua_setfield(L, -2, "PCAP_WARNING");
#endif
#ifdef PCAP_WARNING_PROMISC_NOTSUP
    lua_pushnumber(L, PCAP_WARNING_PROMISC_NOTSUP);
    lua_setfield(L, -2, "PCAP_WARNING_PROMISC_NOTSUP");
#endif
#ifdef PCAP_WARNING_TSTAMP_TYPE_NOTSUP
    lua_pushnumber(L, PCAP_WARNING_TSTAMP_TYPE_NOTSUP);
    lua_setfield(L, -2, "PCAP_WARNING_TSTAMP_TYPE_NOTSUP");
#endif
    create_handle_meta(L);
    create_dumper_meta(L);
    create_filter_meta(L);
    return 1;
}


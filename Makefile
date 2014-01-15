LUA_VERSION=5.2
PCAP_VERSION=100
LUA_CFLAGS=$(shell pkg-config --cflags lua$(LUA_VERSION))
PCAP_CFLAGS=$(shell pcap-config --cflags)
PCAP_LDFLAGS=$(shell pcap-config --libs)
CPPFLAGS=-DPCAP_API_VERSION=$(PCAP_VERSION) $(MY_CPPFLAGS)
ifeq ($(DEBUG),1)
	CFLAGS=-g -fpic -Wall -Wextra -Werror $(LUA_CFLAGS) $(PCAP_CFLAGS) $(MY_CFLAGS)
else
	CFLAGS=-O2 -fpic -Wall -Wextra -Werror $(LUA_CFLAGS) $(PCAP_CFLAGS) $(MY_CFLAGS)
endif
LDFLAGS=-shared -fpic $(PCAP_LDFLAGS) $(MY_LDFLAGS)
TARGET=lpcap.so
OBJS=lpcap.o

$(TARGET): $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f $(OBJS)
	rm -f $(TARGET)


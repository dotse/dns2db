PROG=dns2db
PCAP_READER=read_libtrace.o
CC=gcc
LIB=-lldns -lDNSLog -lsqlite3 -lglib-2.0 -ltrace 
LDFLAGS= -L/opt/local/lib   -L/usr/local/lib   
LIBOBJS= lstat$U.o
CFLAGS=  -I/opt/local/include/glib-2.0 -I/opt/local/lib/glib-2.0/include -I/opt/local/include   -I/usr/local/include    -DHAVE_CONFIG_H


OBJS=dns2db.o \
	$(PCAP_READER) \
	arg_handle.o \
	tcp_factory_assemble.o \
	e_filter.o 




all: $(PROG)



$(PROG): $(OBJS)
	$(CXX) -o $@ $(OBJS) $(LDFLAGS) $(LIBOBJ) $(LIB)


clean:
	rm -rf $(OBJS)
	rm -rf $(PROG)

clean_temp:
	rm -rf *~

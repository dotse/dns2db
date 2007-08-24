PROG=dns2db
CC=gcc
LIB=-lldns -lDNSLog -lpcap -lsqlite3 -lglib-2.0 
LDFLAGS=   -L/usr/local/lib   
LIBOBJS=
CFLAGS=  -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include   -I/usr/local/include    -DHAVE_CONFIG_H


OBJS=dns2db.o \
	read_pcap.o \
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

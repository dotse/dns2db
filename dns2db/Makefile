PROG=dns2db
CC=gcc
LIB=-lldns -lDNSLog -lsqlite3 -lpcap 
LDFLAGS= 
LIBOBJS= lstat$U.o
CFLAGS= -g -O2  -DHAVE_CONFIG_H


OBJS=dns2db.o \
	read_pcap.o \
	arg_handle.o \
	e_filter.o 




all: $(PROG)



$(PROG): $(OBJS)
	$(CXX) -o $@ $(OBJS) $(LDFLAGS) $(LIBOBJ) $(LIB)


clean:
	rm -rf $(OBJS)
	rm -rf $(PROG)

clean_temp:
	rm -rf *~

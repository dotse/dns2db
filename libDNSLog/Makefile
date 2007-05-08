#
#  $Id: Makefile,v 1.12 2007/05/05 17:04:57 calle Exp $
#
#  Copyright(c) 2007 by Carl Olsen
#  
#  


CC=gcc
PROG=libTest
CFLAGS=-g -O2  -DHAVE_CONFIG_H
LIBOBJS=
LDFLAGS= -lsqlite3 
ARCHIVE=libDNSLog.a

OBJS=\
	DNSLog.o \
	DNSLogTest.o \
	ram2disk.o \
	create_db_msg.o \
	libTimer.o 


all:  $(PROG)


#$(PROG): $(OBJS) $(LIBS)
$(PROG): $(OBJS) 
	$(CXX) -o $@ $(OBJS) $(LIBOBJ) $(LDFLAGS)
#$(CXX) -o $@ $(OBJS) $(LIBS)

archive: $(OBJS) $(LIBS)
	ar rc $(ARCHIVE) $(OBJS)
	ranlib $(ARCHIVE)

install: $(ARCHIVE)
	install $(ARCHIVE) /usr/local/lib/
	install DNSLog.h /usr/local/include/
	install DNSLog_Int.h /usr/local/include/

clean:
	rm -f *.o
	rm -f *.a
	rm -f dnslog.db


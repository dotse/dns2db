#
#  $Id: Makefile.in,v 1.4 2007/05/05 17:04:57 calle Exp $
#
#  Copyright(c) 2007 by Carl Olsen
#  
#  


CC=gcc
PROG=libTest
CFLAGS=-g -O2 -I/usr/local/include    -DHAVE_CONFIG_H
LIBOBJS=
LDFLAGS= -L/usr/local/lib   -lsqlite3 
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
	install -m 644 $(ARCHIVE) /usr/local/lib/ 
	install -m 644 DNSLog.h /usr/local/include/ 
	install -m 644 DNSLog_Int.h /usr/local/include/
	install -m 644 DNSLog.pc /usr/local/lib/pkgconfig

clean:
	rm -f *.o
	rm -f *.a
	rm -f dnslog.db
	rm -f *.status
	rm -f *.log
	rm -f libTest
	rm -f DNSLog.pc



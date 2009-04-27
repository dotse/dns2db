SUBDIRS = src

bin_SCRIPTS = bin/dns2db.pl

AUTOMAKE_OPTIONS = foreign

install-exec-hook:
	@if [ -e /etc/dns2db.conf ] ; then echo "/etc/dns2db.conf not replaced"; else cp etc/dns2db.conf /etc/dns2db.conf; fi;\
	if [ -e /etc/init.d/ ]; then\
	   if [ ! -e /etc/init.d/dns2db.sh ] ; then\
	       cp bin/dns2db.sh /etc/init.d/; \
	   fi;\
	fi;
	

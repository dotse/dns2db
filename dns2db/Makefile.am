SUBDIRS = src

bin_SCRIPTS = bin/dns2db.pl

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST  = etc/dns2db.conf
EXTRA_DIST += bin/dns2db.pl
EXTRA_DIST += bin/dns2db.sh
EXTRA_DIST += www/dns2db.php  
EXTRA_DIST += www/dns2db.swf  
EXTRA_DIST += www/dns2db_conf.php.example  
EXTRA_DIST += www/dns2dbnode.php  
EXTRA_DIST += www/dns2dbnode_conf.php.example  
EXTRA_DIST += www/index.php  
EXTRA_DIST += www/reversedb.db3
EXTRA_DIST += dns2db_template

install-exec-hook:
	@if [ -e /etc/dns2db.conf ] ; then echo "/etc/dns2db.conf not replaced"; else cp etc/dns2db.conf /etc/dns2db.conf; fi;\
	if [ -e /etc/init.d/ ]; then\
	   if [ ! -e /etc/init.d/dns2db.sh ] ; then\
	       cp bin/dns2db.sh /etc/init.d/; \
	   fi;\
	fi;
	

dns2db_template: tabledefs.sql
	sqlite3 dns2db_template <tabledefs.sql

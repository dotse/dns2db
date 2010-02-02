SUBDIRS = src

ACLOCAL_AMFLAGS = -I m4

bin_SCRIPTS = bin/dns2db.pl

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST  = etc/dns2db.conf
EXTRA_DIST += bin/dns2db.pl
EXTRA_DIST += bin/dns2db.sh
EXTRA_DIST += www/dns2db.php  
EXTRA_DIST += www/dns2db.swf  
EXTRA_DIST += www/dns2db_conf.php.example  
EXTRA_DIST += www/dns2dbnode.php.src
EXTRA_DIST += www/dns2dbnode_conf.php.example  
EXTRA_DIST += www/index.php  
EXTRA_DIST += www/reversedb.db3
EXTRA_DIST += docs/userman.pdf
EXTRA_DIST += docs/xmldoc.pdf
EXTRA_DIST += www/reversedb.db3
EXTRA_DIST += GUI_INSTALL
EXTRA_DIST += man/dns2sqlite.1
EXTRA_DIST += man/tracedns.1
EXTRA_DIST += src/dns2sqlite/tabledefs.sql

BUILT_SOURCES = www/dns2dbnode.php


#tabledefs.h: Makefile
#	cat tabledefs.sql | sed -e "s/\"/\\\"/" | sed -e "s/\(.*\)/\"\1\\\\n\"/" >$@

www/dns2dbnode.php: Makefile configure www/dns2dbnode.php.src
	echo generation dns2dbnode.php with version ${VERSION};\
	sed -e "s/\(?>\).*\(<?php #version_here DO NOT EDIT THIS LINE\)/\1${VERSION}\2/" www/dns2dbnode.php.src >www/dns2dbnode.php


man1_MANS  = man/dns2sqlite.1
man1_MANS += man/tracedns.1

install-exec-hook:
	@if [ -e /etc/dns2db.conf ] ; then echo "/etc/dns2db.conf not replaced"; else cp etc/dns2db.conf /etc/dns2db.conf; fi;\
	if [ -e /etc/init.d/ ]; then\
	   if [ ! -e /etc/init.d/dns2db.sh ] ; then\
	       cp bin/dns2db.sh /etc/init.d/dns2db; \
	   fi;\
	fi;
	
uninstall-local:
	@if [ -e /etc/init.d/dns2db.sh ] ; then rm /etc/init.d/dns2db.sh ; fi; \
	if [ -e /etc/init.d/dns2db ] ; then rm /etc/init.d/dns2db ; fi;

docs/userman.pdf: ../docs/userman.pdf
	if [ ! -d docs ]; then mkdir docs; fi; \
	cp ../docs/userman.pdf docs/

docs/xmldoc.pdf: ../docs/xmldoc.pdf
	if [ ! -d docs ]; then mkdir docs; fi; \
	cp ../docs/xmldoc.pdf docs/




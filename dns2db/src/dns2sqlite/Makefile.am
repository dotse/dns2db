AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = dns2sqlite

dns2sqlite_SOURCES = global.h trace_data.h trace_data.c db.h db.c db_access.h db_access.c dns2sqlite.h dns2sqlite.c line_parser.h line_parser.c

nodist_dns2sqlite_SOURCES = tabledefs.h

BUILT_SOURCES = tabledefs.h
CLEANFILES = tabledefs.h

tabledefs.h: Makefile
	cat tabledefs.sql | sed -e "s/\"/\\\"/" | sed -e "s/\(.*\)/\"\1\\\\n\"/" >$@

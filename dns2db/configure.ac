#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([DNS2db], [2.0], [bugs@iis.se], [DNS2db])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AC_CANONICAL_TARGET
#AM_INIT_AUTOMAKE(tracedns,2.0)
#AM_INIT_AUTOMAKE(dns2sqlite,2.0)
#AM_INIT_AUTOMAKE(DNS2db,2.0)
AM_INIT_AUTOMAKE

# Platform-specific tweaks
case $target in
*openbsd*)
    CFLAGS="$CFLAGS -I/usr/local/include"
    CPPFLAGS="$CPPFLAGS -I/usr/local/include"
    LIBS="$LIBS -L/usr/local/lib/";;
esac

# Checks for programs.
AC_PROG_CC_C99

# Checks for libraries.
AC_CHECK_LIB([trace], [trace_help])
AC_CHECK_LIB([ldns], [ldns_version])
AC_CHECK_LIB([sqlite3], [sqlite3_libversion_number])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h limits.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h])
AC_CHECK_HEADER(net/ethernet.h, AC_DEFINE(HAVE_NET_ETHERNET_H,1,[has net/ethernet.h header]))
AC_CHECK_HEADER(net/ethertypes.h, AC_DEFINE(HAVE_NET_ETHERTYPES_H,1,[has net/ethertypes.h header]))
AC_CHECK_HEADER(libtrace.h, AC_DEFINE(HAVE_LIBTRACE_H,1,[has net/libtrace.h header]))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_REALLOC
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([bzero regcomp strtoul])

# Language used for further checks.
AC_LANG([C])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/dns2sqlite/Makefile
                 src/tracedns/Makefile])

AC_OUTPUT


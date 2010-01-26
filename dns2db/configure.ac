#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([DNS2db], [2.2.1], [niclas.rosell@iis.se], [DNS2db])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AC_CANONICAL_TARGET
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
AC_PROG_CXX

# Checks for libraries.
AC_CHECK_LIB([trace], [trace_help])
AC_CHECK_LIB([ldns], [ldns_version])
AC_CHECK_LIB([sqlite3], [sqlite3_libversion_number]) 

m4_include([m4/acx_sqlite3.m4])
ACX_SQLITE3

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h limits.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h])
AC_CHECK_HEADER(net/ethernet.h, AC_DEFINE(HAVE_NET_ETHERNET_H,1,[has net/ethernet.h header]))
AC_CHECK_HEADER(net/ethertypes.h, AC_DEFINE(HAVE_NET_ETHERTYPES_H,1,[has net/ethertypes.h header]))
AC_CHECK_HEADER(libtrace.h, AC_DEFINE(HAVE_LIBTRACE_H,1,[has net/libtrace.h header]))
AC_CHECK_HEADER(ldns/ldns.h, AC_DEFINE(HAVE_LDNS_H,1,[has ldns/ldns.h header]))

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
AC_CHECK_FUNCS([dup2])
AC_CHECK_FUNCS([mkdir])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strerror])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([syslog.h])

# Language used for further checks.
AC_LANG([C])

# Check library versions
AC_MSG_CHECKING(for ldns version >=1.3.0)

    AC_RUN_IFELSE([AC_LANG_SOURCE([[
	#include <stdio.h>
	#include <string.h>

	#ifdef HAVE_LDNS_H
		#include <ldns/ldns.h>
	
		int main(int argc,char **argv)
		{
			int res = 0;
			int a,b,c;
			
			sscanf(LDNS_VERSION,"%d.%d.%d",&a,&b,&c);
	
			if (a < 1)
				res=1;
			else if (a==1 && b<3) 
				res=1;
			return res;
		}
	#else
		int main(int argc,char **argv)
		{
			printf("ldns/ldns.h not found - version check disabled -");
			return 0; 
		}	
	#endif
	    ]])],[AC_MSG_RESULT(yes)]          ,[AC_MSG_RESULT(no);AC_MSG_ERROR(dns2db needs a never ldns version)],[])
    
AC_MSG_CHECKING(for libtrace version >=3.0.4)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
     		#include <libtrace.h>
			#if LIBTRACE_API_VERSION < ((3<<16)|(0<<8)|(4))
		 			#error LIBTRACE_API_VERSION 
			#endif
		     ]])],
		     [AC_MSG_RESULT(yes)],
		     [AC_MSG_RESULT(no);AC_MSG_ERROR(dns2db needs a never libtrace version)])
		     

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/dns2sqlite/Makefile
                 src/tracedns/Makefile])

AC_OUTPUT


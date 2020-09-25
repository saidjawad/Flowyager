AC_INIT([Flowtree], [4.0])
AC_PREREQ([2.69])
AM_INIT_AUTOMAKE([foreign 1.13 subdir-objects])
AC_PROG_CXX([g++])
#AC_PROG_CC
#AX_CXX_COMPILE_STDCXX_11
AC_PROG_RANLIB
AM_PROG_AR
AC_PROG_LIBTOOL
#AC_CHECK_HEADERS([libcli.h])
#AC_SEARCH_LIBS([cli_init],[libcli],[],[LIBS+=-lcli])
AC_SEARCH_LIBS(pthread_create, [pthread], ,AC_MSG_ERROR([ERROR: can't find pthreds]))
PKG_CHECK_MODULES([CONFIG], [libconfig])
#PKG_CHECK_MODULES([PCAP], [libpcap])
AC_CONFIG_MACRO_DIRS([m4])
#ACLOCAL_AMFLAGS
#PKG_CHECK_MODULES([THRIFT], [thrift])
#PKG_CHECK_MODULES([MONGO], [libmongoc-1.0])
#PKG_CHECK_MODULES([BOOLST], [boolstuff-0.1])
#PKG_CHECK_MODULES([YAMLCPP], [yaml-cpp])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT


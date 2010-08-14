AC_INIT([SSTPClient],[0.1],[hugsy@pyc.li],[sspclient],[http://localhost/])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 -Werror no-define foreign])

dnl Define compiler
AC_PROG_CC
AC_PROG_MAKE_SET

dnl Checks for header files and libs
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(unistd.h getopt.h netdb.h inittypes.h signal.h string.h)
AC_CHECK_HEADERS(sys/types.h sys/socket.h stdarg.h arpa/inet.h)
AC_CHECK_HEADERS(gnutls/gnutls.h)

AC_CHECK_HEADERS(iconv.h)
AC_CHECK_LIB(gnutls, gnutls_init,, AC_MSG_ERROR("GnuTLS lib required"))
AC_CHECK_FUNCS(select socket getaddrinfo strstr strcasestr daemon)
AC_CONFIG_FILES([Makefile])

dnl Create output
AC_OUTPUT
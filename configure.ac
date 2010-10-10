AC_INIT([SSTPClient],[0.1],[hugsy@pyc.li],[sspclient],[http://localhost/])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 -Werror no-define foreign])

dnl Define compiler
AC_PROG_CC
AC_PROG_MAKE_SET

dnl Checks for header files and libs
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(arpa/inet.h \
errno.h \
getopt.h \
gnutls/gnutls.h \
inttypes.h \
netdb.h \
pty.h \
signal.h \
src/sstpclient.h \
src/libsstp.h \
stdarg.h \
stdint.h \
stdio.h \
stdlib.h \
string.h \
sys/select.h \
sys/socket.h \
sys/time.h \
sys/types.h \
time.h \
unistd.h)

AC_CHECK_LIB(gnutls, gnutls_init,, AC_MSG_ERROR("GnuTLS lib required"))
AC_CHECK_LIB(crypto, HMAC,, AC_MSG_ERROR("Crypto lib required"))
AC_CHECK_LIB(util, openpty,, AC_MSG_ERROR("Utils lib required"))
AC_CONFIG_FILES([Makefile])

dnl Create output
AC_OUTPUT
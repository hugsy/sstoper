PROJECT			= "SSTPClient"

EXTRA_DIST		= LICENSE NEWS ChangeLog README
AUTOMAKE_OPTIONS	= foreign no-dependencies subdir-objects
ACLOCAL_AMFLAGS		= ${ACLOCAL_FLAGS}

bin_PROGRAMS 		= sstpclient
sstpclient_SOURCES	= src/sstpclient.h src/sstpclient.c \
			src/libsstp.h src/libsstp.c 
dist_noinst_SCRIPTS	= autogen.sh
PROJECT			= "SSTPClient"

EXTRA_DIST		= LICENSE NEWS ChangeLog README
SUBDIRS 		= @SUBDIRS@
AUTOMAKE_OPTIONS	= foreign no-dependencies subdir-objects
ACLOCAL_AMFLAGS		= ${ACLOCAL_FLAGS}

bin_PROGRAMS 		= sstpclient
ssptclient_SOURCES	= src/sstpclient.h src/sstpclient.c \
			src/libsstp.c src/libsstp.h
dist_noinst_SCRIPTS	= autogen.sh
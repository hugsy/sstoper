################################################################################
# SSToPer Makefile
#
# Requirements :
# - openssl-devel
# - libcap-devel
#
# For SSL, either one of:
# - libgnutls-devel
# - libpolarssl-devel
#
# To compile with PolarSSL: make USE_POLARSSL=1
# To compile with GnuTLS: make USE_POLARSSL=0
#

PROGNAME	=	\"SSToPer\"
AUTHOR		=	\"Christophe Alladoum\"
VERSION		=	0.40
ARCH		=	$(shell uname)
DEBUG		=	0
USE_POLARSSL	= 	0

CC		=	cc
DEFINES		= 	-D PROGNAME=$(PROGNAME) -D VERSION=$(VERSION)
INC		= 	-I/usr/include
CFLAGS		=	$(DEFINES) $(INC) $(LIB) -Wall -Wextra
LDFLAGS		= 	-lcrypto -lutil -lcap
OBJECTS		=	main.o libsstp.o
BIN		=	sstoper

ifeq ($(DEBUG), 1)
CFLAGS		+=	-ggdb -DDEBUG -O0 -fsanitize=address
else
CFLAGS		+=	-O3 -fstack-protector-all -fPIE
LDFLAGS		+= 	-Wl,-z,relro,-z,now -pie
endif

ifeq ($(USE_POLARSSL), 1)
CFLAGS		+=	-DHAS_POLARSSL
OBJECTS		+=	pem2der.o
LDFLAGS		+=	-lpolarssl
else
CFLAGS		+=	-DHAS_GNUTLS
LDFLAGS		+=	-lgnutls
endif

SSTOPER_USR	= 	root
SSTOPER_GRP	= 	sstoper


.PHONY : clean all release snapshot check-syntax check-leaks

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : $(BIN)

$(BIN) : $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean :
	rm -fr -- $(OBJECTS) $(BIN) *~ *swp \#*\# *.core pppd_log ./docs/$(BIN).8.gz /tmp/sstoper-*

snapshot: clean
	git add . && git ci -m "$(shell date): Generating snapshot release" && \
	git archive --format=tar --prefix=$(BIN)-$(VERSION)/ HEAD |gzip > /tmp/$(BIN)-latest.tgz

release: clean
	git add . && git ci -m "$(shell date): Generating stable release" && \
	git archive --format=tar --prefix=$(BIN)-$(VERSION)/ master |gzip > /tmp/$(BIN)-$(VERSION).tgz

install: $(BIN)
	@echo "Creating '$(SSTOPER_GRP)' group"
	@groupadd -f $(SSTOPER_GRP)
	install -s -m 750 -o $(SSTOPER_USR) -g $(SSTOPER_GRP) -- ./$(BIN) /usr/bin/
	setcap cap_setuid,cap_kill+eip /usr/bin/$(BIN)
	gzip -c ./docs/$(BIN).8 >> ./docs/$(BIN).8.gz
	install -m 644 -o root -- ./docs/$(BIN).8.gz /usr/share/man/man8/
	@echo -e "\nInstallation done\nRemember to add users to '$(SSTOPER_GRP)' group"

uninstall: clean
	rm -fr /usr/bin/$(BIN) /usr/share/man/man8/$(BIN).8.gz
	@echo "Deleting '$(SSTOPER_GRP)' group"
	@groupdel $(SSTOPER_GRP)

check-syntax:
	$(CC) $(CFLAGS) -fsyntax-only $(CHK_SOURCES)

check-leaks: $(BIN)
	./$(BIN) -s dc-2012.vm -c tests/dc-2012.vm.pem -U jfrench -P Hello1234 -vv

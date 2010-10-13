################################################################################
# Simple Makefile
#
#

PROGNAME	=	\"SSToPer\"
AUTHOR		=	\"Christophe Alladoum\"
VERSION		=	0.1
RELEASE		=	\"Tartiflette\"
ARCH		=	$(shell uname)

CC		=	gcc
DBGFLAGS	=	-ggdb
DEFINES		= 	-D __$(ARCH)__ -D PROGNAME=$(PROGNAME) -D VERSION=$(VERSION) -D RELEASE=$(RELEASE)
INC		= 	-I/usr/include
LIB		= 	-L/usr/lib
CFLAGS		=	-O2 -Wall $(DBGFLAGS) $(DEFINES) $(INC)
LDFLAGS		= 	-lcrypto -lutil -lgnutls
OBJECTS		=	sstpclient.o libsstp.o
BIN		=	sstoper

ARGS		=	-s vpn.tweety.looney -c ~/tmp/vpn.tweety.looney.crt -U test-sstp -P Hello1234


.PHONY : clean all valgrind release snapshot test

.c.o :
	@echo "Using $(ARCH) options"
#
# OS specific compilation options
# Linux 
# FreeBSD
# OpenBSD
# Darwin
#
ifeq ($(ARCH), FreeBSD)
	$(CC) $(CFLAGS) -I/usr/local/include -L/usr/local/lib -c -o $@ $<
else ifeq ($(ARCH), OpenBSD)
	$(CC) $(CFLAGS) -I/usr/local/include -L/usr/local/lib -c -o $@ $<
else ifeq ($(ARCH), Darwin)
	$(CC) $(CFLAGS) -I/opt/local/include -L/opt/local/lib -L/opt/local/var/macports/software/gnutls/2.8.6_0/opt/local/lib -I/opt/local/var/macports/software/gnutls/2.8.6_0/opt/local/include -c -o $@ $<
else ifeq ($(ARCH), Linux)
	$(CC) $(CFLAGS) -c -o $@ $<
endif


all : $(BIN)

$(BIN) : $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) 

clean :
	rm -fr $(OBJECTS) $(BIN) *~ *swp \#*\#

valgrind: clean $(BIN)
	valgrind --leak-check=full --show-reachable=yes ./$(BIN) $(ARGS)

snapshot: clean
	git add . && git ci -m "$(shell date): Generating snapshot release" && \
	git archive --format=tar --prefix=$(BIN)-$(VERSION)/ HEAD |gzip > /tmp/$(BIN)-latest.tgz 

release: clean
	git add . && git ci -m "$(shell date): Generating stable release" && \
	git archive --format=tar --prefix=$(BIN)-$(VERSION)/ master |gzip > /tmp/$(BIN)-$(VERSION).tgz

test:   $(BIN)
	./$(BIN) $(ARGS)

cvs:	clean
	cp -r * ~/cvs/trucs/sstoper/ && cd ~/cvs/trucs/sstoper/ && cvs ci
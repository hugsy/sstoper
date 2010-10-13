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

#
# OS specific compilation options
# Linux 
# FreeBSD
# OpenBSD
# Darwin
#
ifeq ($(ARCH), FreeBSD)
INC		+= 	-I/usr/local/include
LIB		+= 	-L/usr/local/lib
else ifeq ($(ARCH), OpenBSD)
INC		+= 	-I/usr/local/include
LIB		+= 	-L/usr/local/lib
else ifeq ($(ARCH), Darwin)
INC		+= 	-I/opt/local/include -I/opt/local/var/macports/software/gnutls/2.8.6_0/opt/local/include 
LIB		+= 	-L/opt/local/lib -L/opt/local/var/macports/software/gnutls/2.8.6_0/opt/local/lib
endif

CFLAGS		=	-O2 -Wall $(DBGFLAGS) $(DEFINES) $(INC) $(LIB)
LDFLAGS		= 	-lcrypto -lutil -lgnutls
OBJECTS		=	sstpclient.o libsstp.o
BIN		=	sstoper

ARGS		=	-s vpn.tweety.looney -c ~/tmp/vpn.tweety.looney.crt -U test-sstp -P Hello1234


.PHONY : clean all valgrind release snapshot test cvs

.c.o :
	@echo "Using $(ARCH) options"

	$(CC) $(CFLAGS) -c -o $@ $<


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
	test -d ~/cvs/trucs/sstoper && cp -r * ~/cvs/trucs/sstoper/ && cd ~/cvs/trucs/sstoper/ && cvs ci
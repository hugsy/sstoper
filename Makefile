################################################################################
# Simple Makefile
#
#

PROGNAME	=	\"SSTPClient\"
AUTHOR		=	\"Christophe Alladoum\"
VERSION		=	0.1
RELEASE		=	\"Tartiflette\"

CC		=	gcc
DBGFLAGS	=	-ggdb
DEFINES		= 	-D PROGNAME=$(PROGNAME) -D VERSION=$(VERSION) -D RELEASE=$(RELEASE)
INC		= 	-I/usr/include
LIB		= 	-L/usr/lib
CFLAGS		=	-O2 -Wall $(DBGFLAGS) $(DEFINES) $(INC)
LDFLAGS		= 	-lcrypto -lutil -lgnutls
OBJECTS		=	sstpclient.o libsstp.o
BIN		=	sstpclient

ARGS		=	-s vpn.tweety.looney -c ~/tmp/vpn.tweety.looney.crt -U test-sstp -P Hello1234


# OS specific compilation options
ifeq ($(shell uname), FreeBSD)
INC		+=	-I/usr/local/include
LIB		+=	-I/usr/local/lib
else
DEFINES		+=	-D HAVE_PTY_H
endif


.PHONY : clean all valgrind release snapshot test

.c.o :
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


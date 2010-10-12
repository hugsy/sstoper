PROGNAME	=	\"SSTPClient\"
AUTHOR		=	\"Christophe Alladoum\"
VERSION		=	0.1
RELEASE		=	\"Tartiflette\"

CC		=	gcc
DBGFLAGS	=	-ggdb
DEFINES		= 	-D PROGNAME=$(PROGNAME) -D VERSION=$(VERSION) -D RELEASE=$(RELEASE)
CFLAGS		=	-O2 -Wall $(DBGFLAGS) $(DEFINES)
LDFLAGS		= 	-lcrypto -lutil -lgnutls
OBJECTS		=	sstpclient.o libsstp.o
BIN		=	sstpclient

ARGS		=	-s vpn.coyote.looney -c ~/tmp/vpn.coyote.looney.crt -U test-sstp -P Hello1234


all : $(BIN)

$(BIN) : $(OBJECTS)
ifeq ($(shell uname), "FreeBSD")
	$(CC) $(CFLAGS) -D HAVE_PTY_H=0 -o $@ $* $(OBJECTS) $(LDFLAGS) 
else
	$(CC) $(CFLAGS) -D HAVE_PTY_H=1 -o $@ $* $(OBJECTS) $(LDFLAGS)
endif

.c.o :
ifeq ($(shell uname), "FreeBSD")
	$(CC) $(CFLAGS) -D HAVE_PTY_H=0 -c -o $@ $< 
else
	$(CC) $(CFLAGS) -D HAVE_PTY_H=1 -c -o $@ $<
endif

clean :
	rm -fr $(OBJECTS) $(BIN)

valgrind: clean $(BIN)
        valgrind --leak-check=full ./$(BIN) $(ARGS)

snapshot: clean
	git add . && git ci -m $(shell date %+F)": before snapshot"
	git archive --format=tar --prefix=$(BIN) HEAD |gzip > /tmp/$(BIN)-latest.tgz 

release: clean
	git archive --format=tar --prefix=$(BIN) master |gzip > /tmp/$(BIN)-$(VERSION).tgz

test:   $(BIN)
	./$(BIN) $(ARGS)


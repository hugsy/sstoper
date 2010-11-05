################################################################################
# SSToPer Makefile
#

PROGNAME	=	\"SSToPer\"
AUTHOR		=	\"Christophe Alladoum\"
VERSION		=	0.1
ARCH		=	$(shell uname)
DEBUG		=	0

CC			=	gcc
DEFINES		= 	-D PROGNAME=$(PROGNAME) -D VERSION=$(VERSION)
INC			= 	-I/usr/include
CFLAGS		=	-O2 -Wall $(DEFINES) $(INC) $(LIB)
LDFLAGS		= 	-lcrypto -lutil -lgnutls
OBJECTS		=	sstpclient.o libsstp.o
BIN			=	sstoper
ARGS		=	-s 192.168.111.195 -c ~/tmp/certnew.cer -U test-sstp -P Hello1234
ifeq ($(shell uname -m), x86_64)
LIB			= 	-L/usr/lib64
else
LIB			= 	-L/usr/lib
endif

ifeq ($(DEBUG), 1)
CFLAGS		+=	$(DBGFLAGS)
DBGFLAGS	=	-ggdb
ARGS		+=	-vvv -l ./pppd_log
endif

.PHONY : clean all valgrind release snapshot test

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : $(BIN)

$(BIN) : $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) 

clean :
	rm -fr $(OBJECTS) $(BIN) *~ *swp \#*\# *.core pppd_log ./docs/$(BIN).8.gz

valgrind: clean $(BIN)
	valgrind --leak-check=full --show-reachable=yes ./$(BIN) $(ARGS)

snapshot: clean
	git add . && git ci -m "$(shell date): Generating snapshot release" && \
	git archive --format=tar --prefix=$(BIN)-$(VERSION)/ HEAD |gzip > /tmp/$(BIN)-latest.tgz 

release: clean
	git add . && git ci -m "$(shell date): Generating stable release" && \
	git archive --format=tar --prefix=$(BIN)-$(VERSION)/ master |gzip > /tmp/$(BIN)-$(VERSION).tgz

install: $(BIN) 
	install -s -m 755 -o root -- ./$(BIN) /usr/bin/
	gzip -c ./docs/$(BIN).8 >> ./docs/$(BIN).8.gz
	install -m 644 -o root -- ./docs/$(BIN).8.gz /usr/share/man/man8/

uninstall: clean
	rm -fr /usr/bin/$(BIN) /usr/share/man/man8/$(BIN).8.gz

test:   $(BIN)
	./$(BIN) $(ARGS)

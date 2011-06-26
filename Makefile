################################################################################
# SSToPer Makefile
#
# requires :
# - openssl-devel
# - libgnutls-devel
# - libcap-devel
#

PROGNAME	=	\"SSToPer\"
AUTHOR		=	\"Christophe Alladoum\"
VERSION		=	0.21
ARCH		=	$(shell uname)
DEBUG		=	0

CC		=	gcc
DEFINES		= 	-D PROGNAME=$(PROGNAME) -D VERSION=$(VERSION)
INC		= 	-I/usr/include 
CFLAGS		=	-O2 -Wall $(DEFINES) $(INC) $(LIB)
LDFLAGS		= 	-lcrypto -lutil -lgnutls -lcap
OBJECTS		=	main.o libsstp.o
BIN		=	sstoper

ifeq ($(shell uname -m), x86_64)
LIB		= 	-L/usr/lib64
else
LIB		= 	-L/usr/lib
endif

ifeq ($(DEBUG), 1)
DBGFLAGS	=	-ggdb -D DEBUG
CFLAGS		+=	$(DBGFLAGS)
endif

ARGS		= 	-s tweety -c /tmp/certnew.cer -U test-sstp -P Hello1234 -vv

SSTOPER_USR	= 	root
SSTOPER_GRP	= 	sstoper

.PHONY : clean all valgrind release snapshot check-syntax 

.c.o :
	$(CC) $(CFLAGS) -c -o $@ $<

all : $(BIN)

$(BIN) : $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) 

clean :
	rm -fr $(OBJECTS) $(BIN) *~ *swp \#*\# *.core pppd_log ./docs/$(BIN).8.gz

valgrind:  $(BIN)
	valgrind --leak-check=full --show-reachable=yes ./$(BIN) $(ARGS)

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

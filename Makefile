CC	= gcc
CFLAGS 	= -Werror -O4
DBGFLAGS= -D_DEBUG_ON -ggdb
RM	= rm -fr
INC	= -L.
LIB	= -lgnutls
INC	= 
TEST	= test

PARAMS  = -s vpn.coyote.looney -c $(TEST)/vpn.coyote.looney.crt

.c.o : 
	$(CC) $(CFLAGS) $(DBGFLAGS) $(INC) -c $^

all: sstpclient

sstpclient: sstpclient.o libsstp.o
	$(CC) $(CFLAGS) $(INC) $(LIB) -o $@ $^

clean :
	$(RM) *.o sstpclient

valgrind : sstpclient
	/usr/bin/valgrind --leak-check=full $< $(PARAMS)

efence : sstpclient
	/usr/bin/ef $< $(PARAMS)

dbg : sstpclient.o libsstp.o
	$(CC) $(CFLAGS) $(DBGFLAGS) $(INC) $(LIB) -o sstpclient $^

server :
	gnutls-serv --http \
	--x509cafile $(TEST)/x509-trust.pem \
	--x509keyfile $(TEST)/x509-server-key.pem \
	--x509certfile $(TEST)/x509-server.pem

client : sstpclient
	./$< $(PARAMS)

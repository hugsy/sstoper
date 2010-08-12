CC	= gcc
CFLAGS 	= -Werror 
CFLAGS 	+= $(DBGFLAGS)
DBGFLAGS= -D_DEBUG_ON -ggdb
RM	= rm -fr
INC	= -L.
LIB	= -lgnutls
INC	= 
TEST	= test
PARAMS  = -s 172.16.0.2 -t $(TEST)/x509-trust.pem -c $(TEST)/x509-client.pem -k $(TEST)/x509-client-key.pem

all: sstpclient

sstpclient: sstpclient.o libsstp.o
	$(CC) $(CFLAGS) $(INC) $(LIB) -o $@ $^

clean :
	$(RM) *.o sstpclient

valgrind : sstpclient
	/usr/bin/valgrind --leak-check=full $< $(PARAMS)

efence : sstpclient
	/usr/bin/ef $< $(PARAMS)

server :
	gnutls-serv --http \
	--x509cafile $(TEST)/x509-trust.pem \
	--x509keyfile $(TEST)/x509-server-key.pem \
	--x509certfile $(TEST)/x509-server.pem

client : sstpclient
	./$< $(PARAMS)

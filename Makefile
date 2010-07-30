CC	= gcc
CFLAGS 	= -Werror -ansi $(DBGFLAGS)
DBGFLAGS= -D_DEBUG_ON -ggdb
RM	= rm -fr
LIB	= -lgnutls
INC	= 
TEST	= test
PARAMS  = -s localhost -p 5556 -t $(TEST)/x509-trust.pem -c $(TEST)/x509-client.pem -k $(TEST)/x509-client-key.pem

all: sstpclient

sstpclient: main.o
	$(CC) $(CFLAGS) $(INC) $(LIB) -o $@ $<

clean :
	$(RM) *.o sstpclient

test : sstpclient
	/usr/bin/valgrind --leak-check=full $< $(PARAMS)

server :
	gnutls-serv --http \
	--x509cafile $(TEST)/x509-trust.pem \
	--x509keyfile $(TEST)/x509-server-key.pem \
	--x509certfile $(TEST)/x509-server.pem

client : sstpclient
	./$< $(PARAMS)

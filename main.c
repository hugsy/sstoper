#define _POSIX_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <string.h>

#include <gnutls/gnutls.h>

#include <sys/types.h>
#include <sys/socket.h>

#define LOG(x) ( fprintf(stdout, x) )
#define ERR(x) ( fprintf(stderr, x) )

typedef struct 
{
  int verbose;
  char* server;
  char port[6];
  
} sstp_config;

void* xmalloc(size_t size);
int init_tcp(char* hostname, char* port);
int init_tls_session(gnutls_session_t session, int sockfd);
void end_tls_session(gnutls_session_t session, int sockfd, int reason);
void usage(char* name, FILE* fd, int retcode);
void parse_options (sstp_config* cfg, int argc, char** argv);

void* xmalloc(size_t size)
{
  void *ptr = malloc(size);
  
  if ( ptr == NULL )
    abort();

  memset(ptr, 0, size);
  return ptr;
}


void usage(char* name, FILE* fd, int retcode)
{
  fprintf(fd,"Usage:\n");
  fprintf(fd, "%s -s server\n", name);
  exit(retcode);
}

void parse_options (sstp_config* cfg, int argc, char** argv)
{
  int curopt, curopt_idx;
 
  const struct option long_opts[] = {
    { "help",    0, 0, 'h' },
    { "verbose", 0, 0, 'v' },
    { "server",  1, 0, 's' },
    { "port",  1, 0, 'p' },
    { 0, 0, 0, 0 } 
  };

  while (1)
    {
      curopt = -1;
      curopt_idx = 0;

      curopt = getopt_long (argc, argv, "hvs:p:", long_opts, &curopt_idx);

      if (curopt == -1)
	break;
      
      switch (curopt)
	{
	case 'h':
	  usage (argv[0], stdout, 0);
	  
	case 'v':
	  cfg->verbose = 1;
	  break;

	case 's':
	  cfg->server = optarg;
	  break;

	case 'p':
	  snprintf(cfg->port, 5, optarg);
	  break;

	case '?': 	  
	default:
	  usage (argv[0], stderr, 1);
	}
      curopt_idx = 0;
    }
}

int init_tcp(char* hostname, char* port)
{
  int sockfd;
  struct addrinfo *hostinfo, *result, *rp;

  hostinfo = (struct addrinfo*) xmalloc(sizeof(struct addrinfo));
  
  memset((void*)hostinfo, 0, sizeof(struct addrinfo));
  hostinfo->ai_family = AF_UNSPEC;
  hostinfo->ai_socktype = SOCK_DGRAM;
  hostinfo->ai_flags = 0;
  hostinfo->ai_protocol = 0;

  if (getaddrinfo(hostname, port, hostinfo, &result) == -1)
    {
      perror("getaddrinfo");
      exit(-1);
    }
  
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    if (rp == NULL)
      break;
    
    sockfd = socket(rp->ai_family,
		    rp->ai_socktype,
		    rp->ai_protocol);
    
    if (sockfd == -1)
      continue;
    
    if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
      break;

    close(sockfd);
  }
  
  if (rp == NULL) {
    ERR("Failed to create connection\n");
    exit(EXIT_FAILURE);
  }

  freeaddrinfo(result);
  
  return sockfd;
}

int init_tls_session(gnutls_session_t session, int sockfd)
{
  int retcode;
      
  gnutls_global_init();
  gnutls_init(&session, GNUTLS_CLIENT);
  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sockfd);

  retcode = gnutls_handshake (session);
  if (retcode < 0) 
    {
      perror("GnuTLS Handshake failed");
      gnutls_perror (retcode);
      end_tls_session(session, *sockfd, retcode);
      exit(retcode);
    }
    
  return retcode;
}


void end_tls_session(gnutls_session_t session, int sockfd, int reason)
{
  shutdown(sockfd, SHUT_RDWR);
  close(sockfd);
  gnutls_deinit(session);
  gnutls_global_deinit();
}


int main (int argc, char** argv) 
{
  
  gnutls_session_t tls_session;
  sstp_config *cfg;
  int sockfd;
  
  cfg = (sstp_config*) xmalloc(sizeof(sstp_config));
  cfg->server = NULL;
  cfg->verbose = 0;
    
  parse_options(cfg, argc, argv);

  if (cfg->server == NULL) {
    fprintf(stderr, "Missing required arg server\n");
    return EXIT_FAILURE;
  }

  if (cfg->port == NULL)
    snprintf(cfg->port, 3, "443");
  
  sockfd = init_tcp(cfg->server, cfg->port);
  
  /* start gnutls session */
  init_tls_session(tls_session, sockfd);

  /* end gnutls session */
  gnutls_bye (tls_session, GNUTLS_SHUT_RDWR);

  end_tls_session(tls_session, sockfd, 0);
  free((void*) cfg);
  
  return EXIT_SUCCESS;
}

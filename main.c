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
  /* char port[6]; */
  char* port;  
  char* ca_file;
  
} sstp_config;

typedef struct 
{
  gnutls_session_t session;
  gnutls_certificate_credentials_t crt_creds;
} TLS;

void* xmalloc(size_t size);
int init_tcp(char* hostname, char* port);
int init_tls_session(TLS* tls, int sockfd, sstp_config* cfg);
void end_tls_session(TLS* tls, int sockfd, int reason);
void usage(char* name, FILE* fd, int retcode);
void parse_options (sstp_config* cfg, int argc, char** argv);

TLS* tls_session;

void* xmalloc(size_t size)
{
  void *ptr = malloc(size);
  
  if ( ptr == NULL )
    {
      perror("xmalloc");
      abort();
    }
    
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
    { "ca-file",  1, 0, 't' },
    { 0, 0, 0, 0 } 
  };

  while (1)
    {
      curopt = -1;
      curopt_idx = 0;

      curopt = getopt_long (argc, argv, "hvs:p:t:", long_opts, &curopt_idx);

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
	  /* snprintf(cfg->port, 5, optarg); */
	  cfg->port = optarg;
	  break;

	case 't':
	  cfg->ca_file = optarg;
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
  hostinfo->ai_family = AF_INET;
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
    return EXIT_FAILURE;
  }

  freeaddrinfo(result);
  free((void*)hostinfo);
 
  return sockfd;
}

int init_tls_session(TLS* tls, int sockfd, sstp_config* cfg)
{
  int retcode;

  /* init and allocate */
  tls = (TLS*) xmalloc(sizeof (TLS));
  gnutls_global_init();
  gnutls_init( &(tls->session), GNUTLS_CLIENT );

  /* setup x509 */
  retcode = gnutls_certificate_allocate_credentials (&(tls->crt_creds));
  if (retcode != GNUTLS_E_SUCCESS )
    {
      ERR("gnutls_certificate_allocate_credentials\n");
      gnutls_perror(retcode);
      return retcode;
    }

  retcode = gnutls_certificate_set_x509_trust_file (tls->crt_creds, cfg->ca_file, GNUTLS_X509_FMT_PEM);
  if (retcode < 1 )
    {
      ERR("At least 1 crt must be valid.\n");
      gnutls_perror(retcode);
      return retcode;
    }
  
  retcode = gnutls_credentials_set (tls->session, GNUTLS_CRD_CERTIFICATE, tls->crt_creds);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      ERR("tls_credentials_se\n");
      gnutls_perror(retcode);
      return retcode;
    }

  
  /* bind gnutls session with the socket */
  gnutls_transport_set_ptr (tls->session, (gnutls_transport_ptr_t) &sockfd);

  
  /* proceed with handshake */
  retcode = gnutls_handshake (tls->session);
  if (retcode != GNUTLS_E_SUCCESS ) 
    {
      ERR("init_tls_session: gnutls_handshake\n");
      gnutls_perror (retcode);
      end_tls_session(tls, sockfd, retcode);
      return retcode;
    }
    
  return retcode;
}


void end_tls_session(TLS* tls, int sockfd, int reason)
{
  shutdown(sockfd, SHUT_RDWR);
  close(sockfd);
  gnutls_deinit(tls->session);
  gnutls_global_deinit();
  free((void*) tls);
}


int main (int argc, char** argv) 
{
  
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
    cfg->port = "443";

  tls_session = (TLS*) xmalloc (sizeof (TLS));
  
  sockfd = init_tcp(cfg->server, cfg->port);
  if (sockfd < 0)
    return EXIT_FAILURE;
  
  /* start gnutls session */
  if (init_tls_session(tls_session, sockfd, cfg) < 0)
    {
      ERR("Failed to initialize TLS session, leaving.\n");
      return EXIT_FAILURE;
    }
  
  /* end gnutls session */
  gnutls_bye (tls_session->session, GNUTLS_SHUT_RDWR);

  end_tls_session(tls_session, sockfd, 0);
  free((void*) cfg);
  
  return EXIT_SUCCESS;
}

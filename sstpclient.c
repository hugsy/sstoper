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
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>

#include "libsstp.h"

/* compat ansi */
extern int snprintf (char *__restrict __s, size_t __maxlen, __const char *__restrict __format, ...);


#ifdef __x86_64
typedef long sock_t;
#else
typedef int sock_t;
#endif



typedef struct 
{
  int verbose;
  char* server;
  char* port;  
  char* ca_file;
  char* crt_file;
  char* key_file;
} sstp_config;


void xlog(int type, char* fmt, ...);
sock_t init_tcp(char* hostname, char* port);
gnutls_session_t* init_tls_session(sock_t, sstp_config*);
void tls_session_loop(gnutls_session_t*, sstp_config*);
void end_tls_session(gnutls_session_t*, sock_t, int reason);
void usage(char* name, FILE* fd, int retcode);
void parse_options (sstp_config* cfg, int argc, char** argv);

gnutls_session_t* tls_session;
sock_t sockfd;
sstp_config *cfg;



enum 
  {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_ERROR
  };

void xlog(int type, char* fmt, ...) 
{
  va_list ap;
  
  va_start(ap, fmt);
  
  switch (type) 
    {
    case LOG_DEBUG:
    case LOG_INFO:
      fprintf(stdout, fmt, ap);
      break;

    case LOG_ERROR:
      fprintf(stderr, fmt, ap);
      break;

    default:
      fprintf(stderr, "[ERROR] Unknown format\n");
      exit(1);
    }
  
  va_end(ap);
}


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
    { "help",      0, 0, 'h' },
    { "verbose",   0, 0, 'v' },
    { "server",    1, 0, 's' },
    { "port",      1, 0, 'p' },
    { "ca-file",   1, 0, 't' },
    { "crt-file",  1, 0, 'c' },
    { "key-file",  1, 0, 'k' },
    { 0, 0, 0, 0 } 
  };

  while (1)
    {
      curopt = -1;
      curopt_idx = 0;

      curopt = getopt_long (argc, argv, "hvs:p:t:c:k:", long_opts, &curopt_idx);

      if (curopt == -1)
	break;
      
      switch (curopt)
	{
	case 'h': usage (argv[0], stdout, 0);
	case 'v': cfg->verbose = 1; break;
	case 's': cfg->server = optarg; break;
	case 'p': cfg->port = optarg; break;
	case 't': cfg->ca_file = optarg; break;
	case 'k': cfg->key_file = optarg; break;
	case 'c': cfg->crt_file = optarg; break;	  
	case '?':
	default:
	  usage (argv[0], stderr, 1);
	}
      curopt_idx = 0;
    }
}


sock_t init_tcp(char* hostname, char* port)
{
  sock_t sock;
  struct addrinfo *hostinfo, *res, *ll;

  hostinfo = (struct addrinfo*) xmalloc(sizeof(struct addrinfo));
  hostinfo->ai_family = AF_UNSPEC;
  hostinfo->ai_socktype = SOCK_STREAM;
  hostinfo->ai_flags = 0;
  hostinfo->ai_protocol = 0;

  printf("Connecting to: %s:%s ", hostname, port);
  
  if (getaddrinfo(hostname, port, hostinfo, &res) == -1)
    {
      perror("getaddrinfo");
      exit(-1);
    }
  
  for (ll=res; ll != NULL; ll=ll->ai_next)
    {
      sock = socket(ll->ai_family,
		    ll->ai_socktype,
		    ll->ai_protocol);
    
      if (sock == -1)
	continue;
    
      if (connect(sock, ll->ai_addr, ll->ai_addrlen) == 0)
	break;
    
      close(sock);
    }
  
  if (ll == NULL)
    {
      xlog(LOG_ERROR, "Failed to create connection.\n");
      perror("init_tcp");
      return -1;
    }

  printf("\tOK [%ld]\n", sock);

  freeaddrinfo(res);
 
  return sock;
}


gnutls_session_t* init_tls_session(sock_t sock, sstp_config* cfg)
{
  int retcode;
  const char* err;
  gnutls_session_t* tls;
  gnutls_certificate_credentials_t creds;

  
  /* init and allocate */
  tls = (gnutls_session_t*) xmalloc(sizeof(gnutls_session_t));
  gnutls_global_init();
  gnutls_init(tls, GNUTLS_CLIENT);
  
  /* setup x509 */
  retcode = gnutls_priority_set_direct (*tls, "PERFORMANCE", &err);
  if (retcode != GNUTLS_E_SUCCESS)
    {
      if (retcode == GNUTLS_E_INVALID_REQUEST)
        {
          xlog(LOG_ERROR, (char*)err);
        }
      return NULL;
    }

  retcode = gnutls_certificate_allocate_credentials (&creds);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      xlog(LOG_ERROR, "gnutls_certificate_allocate_credentials\n");
      gnutls_perror(retcode);
      return NULL;
    }

  /* setting ca trust list */
  retcode = gnutls_certificate_set_x509_trust_file (creds, cfg->ca_file, GNUTLS_X509_FMT_PEM);
  if (retcode < 1 )
    {
      xlog(LOG_ERROR, "init_tls_session:At least 1 certificate must be valid.\n");
      gnutls_perror(retcode);
      return NULL;
    }

  /* setting client private key */
  retcode = gnutls_certificate_set_x509_key_file (creds,
						  cfg->crt_file,
						  cfg->key_file,
						  GNUTLS_X509_FMT_PEM);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      xlog(LOG_ERROR, "init_tls_session:gnutls_certificate_set_x509_key_file\n");
      gnutls_perror(retcode);
      return NULL;
    }  

  /* applying settings to session */
  retcode = gnutls_credentials_set (*tls, GNUTLS_CRD_CERTIFICATE, creds);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      xlog(LOG_ERROR, "init_tls_session:tls_credentials_set\n");
      gnutls_perror(retcode);
      return NULL;
    }

  
  /* bind gnutls session with the socket */
  gnutls_transport_set_ptr (*tls, (gnutls_transport_ptr_t) sock);

  
  /* proceed with handshake */
  retcode = gnutls_handshake (*tls);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      xlog(LOG_ERROR, "init_tls_session: gnutls_handshake\n");
      gnutls_perror (retcode);
      end_tls_session(tls, sockfd, retcode);
      return NULL;
    }

  return tls;
}


void end_tls_session(gnutls_session_t* tls, sock_t sock, int reason)
{
  shutdown(sock, SHUT_RDWR);
  close(sock);
  gnutls_deinit(*tls);
  gnutls_global_deinit();
  free((void*) tls);
}


void tls_session_loop(gnutls_session_t* tls, sstp_config* cfg)
{
  int rbytes;
  char* buf;

  rbytes = -1;
  buf = (char*) xmalloc(BUFFER_SIZE * sizeof(char));

  snprintf(buf, BUFFER_SIZE,
	   "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
	   "Host: %s\r\n"
	   "Content-Length: %llu\r\n"
	   "SSTPCORRELATIONID: %s\r\n"
	   "\r\n\r\n",
	   cfg->server,
	   __UNSIGNED_LONG_LONG_MAX__,
	   __CORRELATION_ID__);

  fprintf(stdout, "--> Sending %ld bytes\n",(strlen(buf) > BUFFER_SIZE ? BUFFER_SIZE : strlen(buf)));
  fprintf(stdout, "%s\n", buf);
  
  gnutls_record_send (*tls, buf, (strlen(buf) > BUFFER_SIZE ? BUFFER_SIZE : strlen(buf))); 
  
  memset(buf, 0, BUFFER_SIZE);
  rbytes = gnutls_record_recv (*tls, buf, BUFFER_SIZE-1);
      
  if (rbytes > 1)
    {
      fprintf(stdout, "<-- Received %d bytes\n", rbytes);
      fprintf(stdout, "%s\n", buf);
    }
  else if (rbytes == 0)
    {
      fprintf(stdout, "!! Connection has been closed !!\n");
      return;
    }
  else 
    {
      xlog(LOG_ERROR, "A problem has occured.\n");
      gnutls_perror(rbytes);
      return;
    }

  if (strstr(buf, "HTTP/1.1 200") == NULL) 
    return;
  
  xlog(LOG_INFO, "Initiating SSTP negociation\n");
  init_sstp(tls);
  
  xlog(LOG_INFO, "SSTP dialog end\n");
  return;
}

void sighandle(int signum)
{
  switch(signum) 
    {
    case SIGINT:
    case SIGTERM:
      fprintf(stdout, "SIG: Closing connection\n");
      fflush(stdout);
      end_tls_session(tls_session, sockfd, 0);
      break;
    }
}

int main (int argc, char** argv) 
{
  sigset_t sigset;
  struct sigaction saction;
  
  /* SIGTERM and SIGINT close the connection properly */
  /* set sigaction */
  saction.sa_mask    = sigset;
  saction.sa_flags   = 0;
  saction.sa_handler = sighandle;

  /* set signal bitmask*/
  sigemptyset(&sigset);
  sigfillset(&sigset);
  sigdelset(&sigset, SIGTERM);
  sigdelset(&sigset, SIGINT);
  sigprocmask(SIG_SETMASK, &sigset, NULL);

  /* apply action to signal in bitmask */
  sigaction(SIGINT, &saction, NULL);
  sigaction(SIGTERM, &saction, NULL);

  /* configuration parsing */
  cfg = (sstp_config*) xmalloc(sizeof(sstp_config));
  cfg->server = NULL;
  cfg->verbose = 0;
    
  parse_options(cfg, argc, argv);

  if (cfg->server == NULL)
    {
      fprintf(stderr, "Missing required arg server\n");
      return EXIT_FAILURE;
    }
  if (cfg->ca_file == NULL)
    {
      fprintf(stderr, "Missing required trusted CA file\n");
      return EXIT_FAILURE;
    }
  if (cfg->crt_file == NULL)
    {
      fprintf(stderr, "Missing required certificate file\n");
      return EXIT_FAILURE;
    }
  if (cfg->key_file == NULL)
    {
      fprintf(stderr, "Missing required private key file\n");
      return EXIT_FAILURE;
    }  
  if (cfg->port == NULL)
    cfg->port = "443";

  sockfd = init_tcp(cfg->server, cfg->port);
  
  if (sockfd < 0)
    return EXIT_FAILURE;

  /* allocate and start gnutls session */
  tls_session = init_tls_session(sockfd, cfg); 
  if (tls_session == NULL)
    {
      xlog(LOG_ERROR, "Failed to initialize TLS session, leaving.\n");
      return EXIT_FAILURE;
    }

  /* gnutls session itself goes here */
  tls_session_loop(tls_session, cfg);
  
  /* end gnutls session and free allocated memory */
  
  end_tls_session(tls_session, sockfd, 0);
  free((void*) cfg);
  
  return EXIT_SUCCESS;
}

#define _POSIX_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <gnutls/gnutls.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "sstpclient.h"
#include "libsstp.h"


void xlog(int type, const char* fmt, ...) 
{
  va_list ap;
  
  va_start(ap, fmt);
  
  switch (type) 
    {
    case LOG_DEBUG:
    case LOG_INFO:
    case LOG_ERROR:
      vfprintf(stderr, fmt, ap);
      break;
    }
  fflush(stderr);
  va_end(ap);
}


void* xmalloc(size_t size)
{
  void *ptr;

  ptr = malloc(size);
  
  if ( ptr == NULL )
    {
      perror("xmalloc");
      abort();
    }
    
  memset(ptr, 0, size);
  return ptr;
}


void usage(char* name, int retcode)
{
  FILE* fd;
  
  if (retcode==0)
    fd = stdout;
  else
    fd = stderr;
      
  fprintf(fd,
	  "SSTPClient: SSTP VPN client for *nix\n"
	  "Usage: %s [ARGUMENTS]\n"
	  "\t-s, --server <sstp.server.address> (mandatory)\tSSTP Server\n"
	  "\t-c, --ca-file /path/to/ca_file (mandatory)\tTrusted CA file\n"
	  "\t-U, --username USERNAME (mandatory)\tWindows username\n"
	  "\t-P, --password PASSWORD (mandatory)\tWindows password\n"	  
	  "\t-p, --port NUM \tAlternative server port (default: 443)\n"
	  "\t-x, --pppd-path /path/to/pppd \tSpecifies path to pppd executable (default: /usr/sbin/pppd)\n"
	  "\t-v, --verbose\tVerbose mode\n"
	  "\t-l, --logfile /path/to/pppd_logfile\tLog pppd activity in specified file\n"
	  "\t-h, --help\tShow this menu\n"
	  "\n\n",
	  name);
  
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
    { "ca-file",   1, 0, 'c' },
    { "username",  1, 0, 'U' },
    { "password",  1, 0, 'P' },
    { "pppd-path", 1, 0, 'x' },
    { "logfile",   1, 0, 'l' },
    { 0, 0, 0, 0 } 
  };

  while (1)
    {
      curopt = -1;
      curopt_idx = 0;

      curopt = getopt_long (argc, argv, "hvs:p:c:U:P:x:l:", long_opts, &curopt_idx);

      if (curopt == -1) break;
      
      switch (curopt)
	{
	case 'h': usage (argv[0], EXIT_SUCCESS);
	case 'v': cfg->verbose++; break;
	case 's': cfg->server = optarg; break;
	case 'p': cfg->port = optarg; break;
	case 'c': cfg->ca_file = optarg; break;
	case 'U': cfg->username = optarg; break;	  
	case 'P': cfg->password = optarg; break;
	case 'x': cfg->pppd_path = optarg; break;	  
	case 'l': cfg->logfile = optarg; break;
  	case '?':
	default:
	  usage (argv[0], EXIT_FAILURE);
	}
      curopt_idx = 0;
    }
}


void check_required_arg(char* argument)
{
  if (argument == NULL)
    {
      xlog(LOG_ERROR, "Missing required argument.\n\n");
      usage("sstpclient", EXIT_FAILURE);
    }
}


void check_default_arg(char** argument, char* default_value)
{
  if ((*argument) == NULL)
    {
      xlog(LOG_ERROR, "Using default value: %s.\n", default_value);
      *argument = default_value;
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

  xlog(LOG_INFO, "Connecting to %s:%s ", hostname, port);
  
  if (getaddrinfo(hostname, port, hostinfo, &res) == -1)
    {
      perror("getaddrinfo");
      return -1;
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

  xlog(LOG_INFO, "\tOK [%ld]\n", sock);

  freeaddrinfo(res);
  free(hostinfo);
 
  return sock;
}


int init_tls_session(sock_t sock, gnutls_session_t* tls_session)
{
  int retcode;
  const char* err;
  gnutls_certificate_credentials_t creds;

  /* initialize and allocate */
  gnutls_global_init();
  gnutls_init(tls_session, GNUTLS_CLIENT);

  retcode = gnutls_record_set_max_size(*tls_session, SSTP_MAX_BUFFER_SIZE);
  if (retcode != GNUTLS_E_SUCCESS)
    {
      gnutls_perror(retcode);
      return -1;
    }
  
  /* setup x509 */
  retcode = gnutls_priority_set_direct (*tls_session, "SECURE256", &err);  
  if (retcode != GNUTLS_E_SUCCESS)
    {
      if (retcode == GNUTLS_E_INVALID_REQUEST)
        {
          xlog(LOG_ERROR, (char*)err);
        }
      return -1;
    }

  retcode = gnutls_certificate_allocate_credentials (&creds);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      xlog(LOG_ERROR, "gnutls_certificate_allocate_credentials %s\n", gnutls_strerror(retcode));
      return -1;
    }

  /* setting trusted ca list */
  retcode = gnutls_certificate_set_x509_trust_file (creds, cfg->ca_file, GNUTLS_X509_FMT_PEM);
  if (retcode < 1 )
    {
      xlog(LOG_ERROR, "init_tls_session:At least 1 certificate must be valid.\n");
      gnutls_perror(retcode);
      return -1;
    }

  /* applying settings to session and free credentials */
  retcode = gnutls_credentials_set (*tls_session, GNUTLS_CRD_CERTIFICATE, &creds);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      xlog(LOG_ERROR, "init_tls_session:tls_credentials_set\n");
      gnutls_perror(retcode);
      return -1;
    }

  gnutls_certificate_free_credentials(creds);
  
  /* bind gnutls session with the socket */
  gnutls_transport_set_ptr (*tls_session, (gnutls_transport_ptr_t) sock);

  
  /* proceed with handshake */
  retcode = gnutls_handshake (*tls_session);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      xlog(LOG_ERROR, "init_tls_session: gnutls_handshake\n");
      gnutls_perror (retcode);
      end_tls_session(retcode);
      return -1;
    }
  
  return 0;
}


void end_tls_session(int reason)
{
  int retcode;

  if (cfg->verbose)
    xlog(LOG_INFO, "End of TLS connection. Reason: %d.\n", reason);
  
  retcode = gnutls_bye(tls, GNUTLS_SHUT_WR);
  if (retcode != GNUTLS_E_SUCCESS)
    xlog(LOG_ERROR, "end_tls_session: %s\n", gnutls_strerror(retcode));
  
  retcode = shutdown(sockfd, SHUT_WR);
  if (retcode < -1)
    xlog(LOG_ERROR, "end_tls_session: %s\n", strerror(retcode));
  
  retcode = close(sockfd);
  if (retcode < -1)
    xlog(LOG_ERROR, "end_tls_session: %s\n", strerror(retcode));

  if (cfg->verbose)
    xlog(LOG_INFO, "Freeing regions.\n");
  
  gnutls_deinit(tls);
  gnutls_global_deinit();
}


void sighandle(int signum)
{
  switch(signum) 
    {
    case SIGALRM:
      xlog(LOG_INFO, "Negociation timer ends\n");
      break;
      
    case SIGINT:
    case SIGTERM:
      if (ctx!=NULL && ctx->pppd_pid < 0)
	{
	  kill(ctx->pppd_pid, SIGINT);
	  waitpid(ctx->pppd_pid, NULL, 0);
	}

      xlog(LOG_INFO, "SIG: Closing connection\n");
      fflush(stdout);
      end_tls_session(SIGINT);
      exit(signum);
    }
}


int main (int argc, char* argv[]) 
{
  sigset_t sigset;
  struct sigaction saction;
  int retcode;
    
  /* SIGTERM and SIGINT close the connection properly */
  /* set signal bitmask */
  sigemptyset(&sigset);
  sigfillset(&sigset);
  sigdelset(&sigset, SIGTERM);
  sigdelset(&sigset, SIGINT);
  sigdelset(&sigset, SIGALRM);  
  sigprocmask(SIG_SETMASK, &sigset, NULL);

  /* set sigaction */
  saction.sa_mask    = sigset;
  saction.sa_flags   = 0;
  saction.sa_handler = sighandle;

  /* apply action to signal in bitmask */
  sigaction(SIGINT, &saction, NULL);
  sigaction(SIGTERM, &saction, NULL);
  sigaction(SIGALRM, &saction, NULL);

  /* configuration parsing and privilege check */
  cfg = (sstp_config*) xmalloc(sizeof(sstp_config));
    
  parse_options(cfg, argc, argv);
  
  check_required_arg(cfg->server);
  check_required_arg(cfg->ca_file);
  check_required_arg(cfg->username);
  check_required_arg(cfg->password);

  check_default_arg(&cfg->port, "443");
  check_default_arg(&cfg->pppd_path, "/usr/sbin/pppd");

  
  /* create socket  */
  sockfd = init_tcp(cfg->server, cfg->port); 
  if (sockfd < 0)
    return EXIT_FAILURE;

  
  /* allocate and start gnutls session */
  retcode = init_tls_session(sockfd, &tls); 
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "Failed to initialize TLS session, leaving.\n");
      return EXIT_FAILURE;
    }

  
  /* http over ssl nego */
  if (cfg->verbose) xlog(LOG_INFO, "Performing HTTPS transaction\n");
  retcode = https_session_negociation();  
  if (retcode < 0) 
    goto end;


  /* starting sstp */
  if (cfg->verbose) xlog(LOG_INFO, "Initiating SSTP negociation\n");
  sstp_loop();

  
  /* end gnutls session and free allocated memory */
 end:  
  if (cfg->verbose) xlog(LOG_INFO, "SSTP dialog end\n");
  end_tls_session(EXIT_SUCCESS);
  
  free((void*) cfg);
  
  return EXIT_SUCCESS;
}

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
#include <gnutls/x509.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "sstpclient.h"
#include "libsstp.h"


#ifndef PROGNAME
#define PROGNAME "SSToPer"
#endif
#ifndef VERSION
#define VERSION  "unk"
#endif
#ifndef RELEASE
#define RELEASE "unk"
#endif


static sock_t init_tcp(char*, char*);
static int init_tls_session();
static int check_tls_session();
static void end_tls_session(int);
char *getpass( const char *prompt);

/**
 * Logging function, displays log message to stderr.
 *
 * @param type : event type
 * @param fmt : format string
 */
void xlog(int type, const char* fmt, ...) 
{
  va_list ap;
  
  switch (type) 
    {
    case LOG_DEBUG:
      fprintf(stderr, "[*] ");
      break;
    case LOG_ERROR:
      fprintf(stderr, "[!] ");
      break;     
    case LOG_INFO:
    default :
      break;
    }
  
  va_start(ap, fmt);  
  vfprintf(stderr, fmt, ap);
  fflush(stderr);
  va_end(ap);
}


/**
 * malloc(3) wrapper. Checks size and zero-fill buffer.
 *
 * @param size: buffer size to allocate
 */
void* xmalloc(size_t size)
{
  void *ptr;

  if (size > SIZE_MAX / sizeof(size_t))
    {
      perror("xmalloc: try to allocate incorrect size");
      abort();
    }
					     
  ptr = malloc(size);
  
  if ( ptr == NULL )
    {
      perror("xmalloc: fail to allocate space");
      abort();
    }
    
  memset(ptr, 0, size);
  return ptr;
}


/**
 * Usage
 */
void usage(char* name, int retcode)
{
  FILE* fd;
  
  fd = (retcode == 0) ? stdout : stderr;
      
  fprintf(fd,
	  "\n%s\nVersion: %.2f\nRelease: %s\n"
	  "--\n"
	  "SSTP VPN client for *nix\n"
	  "----------------------------------------------------------------------\n\n"
	  "Usage (as root):\n\t%s -s server -c ca_file -U username [-P password] [OPTIONS+]\n"
	  "\nOPTIONS:\n"
	  "\t-s, --server=my.sstp.server.com (mandatory)\tSSTP Server URI\n"
	  "\t-c, --ca-file=/path/to/ca_file (mandatory)\tTrusted PEM formatted CA file\n"
	  "\t-U, --username=USERNAME (mandatory)\t\tWindows username\n"
	  "\t-P, --password=PASSWORD\t\t\t\tWindows password\n"	  
	  "\t-p, --port=NUM\t\t\t\t\tAlternative server port\n"
	  "\t-x, --pppd-path=/path/to/pppd\t\t\tSpecifies path to pppd executable\n"
	  "\t-l, --logfile=/path/to/pppd_logfile\t\tLog pppd activity in specified file\n"
	  "\t-d, --domain=MyWindowsDomain\t\t\tSpecify Windows domain for authentication\n"
	  "\t-m, --proxy=PROXY\t\t\t\tSpecify proxy location\n"
	  "\t-n, --proxy-port=PORT\t\t\t\tSpecify proxy port\n"
	  "\t-v, --verbose\t\t\t\t\tIncrease verbose mode (accept multiple)\n"	  
	  "\t-h, --help\t\t\t\t\tShow this menu\n"
	  "\n\n",
	  PROGNAME, VERSION, RELEASE, 
	  name);
  
  exit(retcode);
}


/**
 * Parse options
 */
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
    { "domain",    1, 0, 'd' },    
    { 0, 0, 0, 0 } 
  };

  while (1)
    {
      curopt = -1;
      curopt_idx = 0;

      curopt = getopt_long (argc, argv, "hvs:p:c:U:P:x:l:d:", long_opts, &curopt_idx);

      if (curopt == -1) break;
      
      switch (curopt)
	{
	case 'v': cfg->verbose++; break;
	case 's': cfg->server = optarg; break;
	case 'p': cfg->port = optarg; break;
	case 'c': cfg->ca_file = optarg; break;
	case 'U': cfg->username = optarg; break;	  
	case 'P': cfg->password = optarg; break;
	case 'x': cfg->pppd_path = optarg; break;	  
	case 'l': cfg->logfile = optarg; break;
	case 'd': cfg->domain = optarg; break;
	case 'h':
	  usage (argv[0], EXIT_SUCCESS);
  	case '?':
	default:
	  usage (argv[0], EXIT_FAILURE);
	}
      curopt_idx = 0;
    }
}


/**
 * Validates presence of a mandatory argument. Parameter absence will exit
 * on error.
 *
 * @param argument : argument to be checked
 */
void check_required_arg(char* argument)
{
  if (argument == NULL)
    {
      xlog(LOG_ERROR, "Missing required argument.\n\n");
      usage("sstpclient", EXIT_FAILURE);
    }
}


/**
 * Validates presence of an optional argument. 
 *
 * @param argument : argument to be checked
 * @param default_value : default value to be used if undefined
 */
void check_default_arg(char** argument, char* default_value)
{
  if ((*argument) == NULL)
    {
      xlog(LOG_ERROR, "Using default value: %s\n", default_value);
      *argument = default_value;
    }
}


/**
 * Initiates TCP connection to `hostname` on port `port`
 *
 * @param hostname : host to connect to
 * @param port : TCP port `hostname` is listening
 * @return a socket (fd > 2) on success, a negative value on failure
 */
static sock_t init_tcp(char* hostname, char* port)
{
  sock_t sock;
  struct addrinfo hostinfo, *res, *ll;

  memset(&hostinfo, 0, sizeof(struct addrinfo));
  hostinfo.ai_family = AF_UNSPEC;
  hostinfo.ai_socktype = SOCK_STREAM;
  hostinfo.ai_flags = 0;
  hostinfo.ai_protocol = 0;

  /* TODO: tester en ip6 */
  xlog(LOG_INFO, "Connecting to %s:%s ", hostname, port);
  
  if (getaddrinfo(hostname, port, &hostinfo, &res) == -1)
    {
      xlog(LOG_ERROR, "getaddrinfo failed.\n");
      return -1;
    }
  
  for (ll = res; ll ; ll = ll->ai_next)
    {
      sock = socket(ll->ai_family,
		    ll->ai_socktype,
		    ll->ai_protocol);
    
      if (sock == -1)
	{
	  if (cfg->verbose > 2)
	    xlog(LOG_DEBUG, "Failed to create socket: %s\n", strerror(errno));

	  continue;
	}
	
    
      if (connect(sock, ll->ai_addr, ll->ai_addrlen) == 0)
	break;

      if (cfg->verbose > 2)
	xlog(LOG_DEBUG, "Failed to establish connection: %s\n", strerror(errno));
      
      close(sock);
    }
  
  if (ll == NULL)
    {
      xlog(LOG_INFO, "\t\t[KO]\n");
      return -1;
    }

  xlog(LOG_INFO, "\t[OK]");
  if (cfg->verbose) xlog(LOG_INFO, " (%ld)", sock);
  xlog(LOG_INFO, "\n");

  freeaddrinfo(res);
 
  return sock;
}


/**
 * Wrapper socket in a GnuTLS session. There is no server certificate validation.
 *
 * @return 0 on success, or -1 on error.
 */
static int init_tls_session()
{
  int retcode;
  const char* err;
  gnutls_certificate_credentials_t creds;

  
  /* initialize and allocate */
  gnutls_global_init();
  gnutls_init(&tls, GNUTLS_CLIENT);

  retcode = gnutls_record_set_max_size(tls, SSTP_MAX_BUFFER_SIZE);
  if (retcode != GNUTLS_E_SUCCESS)
    {
      xlog(LOG_ERROR, "gnutls_record_set_max_size: %s", gnutls_strerror(retcode));
      return -1;
    }
  
  /* setup x509 */
  retcode = gnutls_priority_set_direct (tls, "SECURE256", &err);  
  if (retcode != GNUTLS_E_SUCCESS)
    {
      if (retcode == GNUTLS_E_INVALID_REQUEST)
	xlog(LOG_ERROR, (char*)err);
      
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
      xlog(LOG_ERROR, "gnutls_certificate_set_x509_trust_file: no valid certificate.\n%s",
	   gnutls_strerror(retcode));
      return -1;
    }

  /* applying settings to session and free credentials */
  retcode = gnutls_credentials_set (tls, GNUTLS_CRD_CERTIFICATE, &creds);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      xlog(LOG_ERROR, "init_tls_session: tls_credentials_set\n%s",
	   gnutls_strerror(retcode));
      return -1;
    }

  gnutls_certificate_free_credentials(creds);
  
  /* bind gnutls session with the socket */
  gnutls_transport_set_ptr (tls, (gnutls_transport_ptr_t) sockfd);

  /* proceed with handshake */
  retcode = gnutls_handshake (tls);
  if (retcode != GNUTLS_E_SUCCESS)
    {
      xlog(LOG_ERROR, "init_tls_session: gnutls_handshake\n%s",
	   gnutls_strerror(retcode));
      end_tls_session(retcode);
      return -1;
    }

  /* check data in tls session */
  retcode = check_tls_session();
  if (retcode < 0 )
    {
      xlog(LOG_ERROR, "init_tls_session: fail to check tls server certificate\n%s",
	   gnutls_strerror(retcode));
      return -1;
    }

  return 0;
}


/**
 * Ends nicely TLS session
 *
 * @param reason: disconnection reason
 */ 
static void end_tls_session(int reason)
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

  gnutls_x509_crt_deinit (certificate);
  gnutls_deinit(tls);
  gnutls_global_deinit();
}


/**
 * Checks certificate list
 *
 * @return 0 if all is good, -1 if not.
 */
static int check_tls_session()
{
  const gnutls_datum_t *certificate_list;
  unsigned int certificate_list_size;
  int retcode, i;
   
  /* CA trust list verification */
  retcode = gnutls_certificate_type_get (tls);
  if (retcode != GNUTLS_CRT_X509)
    {
      xlog(LOG_ERROR, "check_tls_session: expected GNUTLS_CRT_X509 format\n");
      return -1;
    }
  
  gnutls_x509_crt_init (&certificate);
  certificate_list = gnutls_certificate_get_peers (tls, &certificate_list_size);
  if (certificate_list == NULL)
    {
      xlog(LOG_ERROR, "check_tls_session: fail to get peers\n");
      return -1;
    }
  
  /* browse certificate list, and picking the first valid */
  for (i=0; i<certificate_list_size; i++) 
    {
      retcode = gnutls_x509_crt_import (certificate, &certificate_list[0], GNUTLS_X509_FMT_DER);
      if (retcode == GNUTLS_E_SUCCESS) return 0;
    }

  /* otherwise return on error */
  xlog(LOG_ERROR, "check_tls_session: fail to import certificate\n");  
  return -1;
}


/**
 * Signal handling function.
 * 
 * @param signum : signal number
 */
void sighandle(int signum)
{
  int status = 0;
  
  switch(signum) 
    {
    case SIGALRM:
      xlog(LOG_INFO, "Timer has expired, disconnecting\n");
      set_client_status(CLIENT_CALL_DISCONNECTED);
      break;

    case SIGCHLD:
      waitpid(ctx->pppd_pid, &status, WNOHANG);     
      xlog(LOG_INFO, "pppd (PID:%d) died with retcode %d\n", ctx->pppd_pid, status);

      set_client_status(CLIENT_CALL_DISCONNECTED);
      break;

    case SIGINT:
    case SIGTERM:     /* INT or TERM will provoke a nice ending for the SSTP session */
      
      if (ctx != NULL && ctx->pppd_pid > 0)
	{
	  /* kill pppd */
	  if (cfg->verbose)
	    xlog(LOG_INFO, "Waiting for pppd process to end.\n");
	  if (cfg->verbose > 2)
	    xlog(LOG_DEBUG, "Sending SIGINT to pppd process (PID:%d)\n", ctx->pppd_pid);
	  
	  kill(ctx->pppd_pid, SIGINT);
	  waitpid(ctx->pppd_pid, &status, 0);
	}
      
      xlog(LOG_INFO, "Signal received: closing connection\n");

      if (cfg->verbose)
	xlog(LOG_INFO, "Sending SSTP_MSG_CALL_DISCONNECT message.\n");

      /* close sstp connection, and disconnect */
      send_sstp_control_packet(SSTP_MSG_CALL_DISCONNECT, NULL, 0, 0);
      
      set_client_status(CLIENT_CALL_DISCONNECTED);
      break;      
    }
}


/**
 * Main function:
 * - set up signal handler
 * - parse & set upconfiguration
 * - initialize tcp connection
 * - initialize tls socket
 * - triggers https negocation
 *
 * @param argc: number of command-line argument
 * @param argv: array of command-line argument
 * @param envp: array of environment argument
 * @return EXIT_SUCCESS if all good, EXIT_FAILURE otherwise
 */
int main (int argc, char** argv, char** envp)
{
  sigset_t sigset;
  struct sigaction saction;
  int retcode;

#if !defined  __Linux__ && !defined __FreeBSD__ \
  && !defined __OpenBSD__ && !defined __Darwin__
  xlog (LOG_ERROR, "Operating system not supported");
  return EXIT_FAILURE;
#endif
  
  /* check user identifier */
  if (getuid() != 0) 
    {
      xlog (LOG_ERROR, "pppd requires sstpclient to be executed with root privileges.\n");
      usage(argv[0], EXIT_FAILURE);
    }

  envp = NULL;
  
  /* configuration parsing and privilege check */
  cfg = (sstp_config*) xmalloc(sizeof(sstp_config));
    
  parse_options(cfg, argc, argv);
  
  check_required_arg(cfg->server);
  check_required_arg(cfg->ca_file);
  check_required_arg(cfg->username);

  if (cfg->password == NULL)
    {
      if (cfg->verbose)
	xlog(LOG_INFO, "No password specified, prompting for one.\n");
      
      cfg->password = getpass("Password: ");
    }
  
  check_default_arg(&cfg->port, "443");
  check_default_arg(&cfg->pppd_path, "/usr/sbin/pppd");

  retcode = access (cfg->pppd_path, X_OK);
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "Failed to access pppd.\n");
      if (cfg->verbose)
	xlog(LOG_ERROR, "%s", strerror(retcode));
      return EXIT_FAILURE;
    }

  /* SIGTERM and SIGINT close the connection properly */
  /* set signal bitmask */
  sigemptyset(&sigset);
  sigfillset(&sigset);
  sigdelset(&sigset, SIGTERM);
  sigdelset(&sigset, SIGINT);
  sigdelset(&sigset, SIGALRM);
  sigdelset(&sigset, SIGCHLD);
  sigprocmask(SIG_SETMASK, &sigset, NULL);

  /* set sigaction */
  saction.sa_mask    = sigset;
  saction.sa_flags   = 0;
  saction.sa_handler = sighandle;

  /* apply action to signal in bitmask */
  sigaction(SIGINT, &saction, NULL);
  sigaction(SIGTERM, &saction, NULL);
  sigaction(SIGALRM, &saction, NULL);
  sigaction(SIGCHLD, &saction, NULL);

  
  /* create socket  */
  sockfd = init_tcp(cfg->server, cfg->port); 
  if (sockfd < 0) 
    {
      xlog(LOG_ERROR, "TCP socket has failed, leaving...\n");
      free(cfg);
      return EXIT_FAILURE;
    }

  
  /* allocate and start gnutls session */
  retcode = init_tls_session(sockfd, &tls); 
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "TLS session initialization has failed, leaving...\n");
      free(cfg);
      return EXIT_FAILURE;
    }

  
  /* http over ssl nego */
  if (cfg->verbose)
    xlog(LOG_INFO, "Performing HTTPS transaction\n");
  
  retcode = https_session_negociation();  
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "An error occured in HTTPS negocation, leaving\n");
      end_tls_session(EXIT_FAILURE);
      free(cfg);
      return EXIT_FAILURE;
    }
    

  /* starting sstp */
  if (cfg->verbose)
    xlog(LOG_INFO, "Initiating SSTP negociation\n");
  
  sstp_loop();

  /* end gnutls session */ 
  if (cfg->verbose)
    xlog(LOG_INFO, "SSTP dialog ends successfully\n");
  
  end_tls_session(EXIT_SUCCESS);

  /* free allocated memory */
  free(cfg);
  
  return EXIT_SUCCESS;
}

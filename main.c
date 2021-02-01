/*
 * SSToPer, Linux SSTP Client
 * Christophe Alladoum < christophe __DOT__ alladoum __AT__ hsc __DOT__ fr>
 * Herve Schauer Consultants (http://www.hsc.fr)
 *
 *            GNU GENERAL PUBLIC LICENSE
 *              Version 2, June 1991
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (
 * at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define _GNU_SOURCE 1
#define _POSIX_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/capability.h>

#ifdef HAS_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#else
#include <mbedtls/net.h>
#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>
#include <mbedtls/version.h>
#endif

#include "main.h"
#include "libsstp.h"


#ifndef PROGNAME
#define PROGNAME "SSToPer"
#endif
#ifndef VERSION
#define VERSION 0.1
#endif


/**
 * Logging function, displays log message to stderr.
 *
 * @param type : event type
 * @param fmt : format string
 */
void xlog(int type, const char* fmt, ...)
{
  va_list ap;
  time_t t;
  struct tm *tm;
  char time_buf[128];

  /* if (type != LOG_INFO)  */
    /* {    */
      t = time(NULL);
      tm = localtime(&t);
      strftime(time_buf, 128, "%F %T", tm);
      fprintf(stderr, "%s  ", time_buf);
    /* } */

  switch (type)
    {
    case LOG_DEBUG:
      fprintf(stderr, "[*] ");
      break;
    case LOG_ERROR:
      fprintf(stderr, "[-] ");
      break;
    case LOG_WARNING:
      fprintf(stderr, "[!] ");
      break;
    case LOG_INFO:
      fprintf(stderr, "[+] ");
      break;
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
 * Free configuration blokcs
 *
 * @param ptr: pointer to zone to free
 */
void xfree(void* ptr)
{

  if (ptr)
    free(ptr);
  else
    xlog(LOG_ERROR, "Trying to free NULL pointer\n");

}


/**
 * Usage
 *
 * @param name: argv[0]
 * @param retcode: indicates how program should exit
 */
static void usage(char* name, int retcode)
{
  FILE* fd;

  fd = (retcode == 0) ? stdout : stderr;

  fprintf(fd,
	  "%s, version %.2f\n"
	  "SSTP VPN client for Linux\n"
          "Compiled with SSL library: "
#ifdef HAS_GNUTLS
          "GnuTLS %s\n"
#else
          "mbedSSL %s\n"
#endif
	  "Usage:\n\t%s -s server -c ca_file -U username [-P password] [OPTIONS+]\n"
	  "\nOPTIONS:\n"
	  "\t-s, --server=my.sstp.server.com (mandatory)\tSSTP Server URI\n"
	  "\t-c, --ca-file=/path/to/ca_file (mandatory)\tPEM-format CA file\n"
	  "\t-U, --username=USERNAME (mandatory)\t\tWindows username\n"
	  "\t-P, --password=PASSWORD\t\t\t\tWindows password\n"
	  "\t-p, --port=NUM\t\t\t\t\tAlternative server port\n"
	  "\t-x, --pppd-path=/path/to/pppd\t\t\tpppd path\n"
	  "\t-l, --logfile=/path/to/pppd_logfile\t\tLog pppd in file\n"
	  "\t-d, --domain=MyWindowsDomain\t\t\tSpecify Windows domain\n"
	  "\t-m, --proxy=PROXYHOST\t\t\t\tSpecify proxy location\n"
	  "\t-n, --proxy-port=PROXYPORT\t\t\tSpecify proxy port\n"
	  "\t-v, --verbose\t\t\t\t\tIncrement verbose mode\n"
	  "\t-D, --daemon\t\t\t\t\tStart as daemon\n"
	  "\t-h, --help\t\t\t\t\tShow this menu\n"
	  "\n\n",
	  PROGNAME, VERSION,
#ifdef HAS_GNUTLS
          gnutls_check_version(NULL),
#else
          MBEDTLS_VERSION_STRING,
#endif
	  name);

  exit(retcode);
}


/**
 * Custom function to read password from /dev/tty.
 *
 * @param prompt : string to display for password
 * @return 0 if all is good, -1 otherwise
 */
static int getpassword(const char* prompt)
{
  int fd, rbytes;
  static char pwd[64];
  struct termios orig, no_echo;

  if (!isatty(STDIN_FILENO))
    {
      if (cfg->verbose)
	xlog(LOG_INFO, "Can't be used outside of a tty\n");
      return -1;
    }

  printf("%s", prompt);
  fflush(stdout);

  memset (pwd, 0, 64);
  fd = open("/dev/tty", O_RDWR);

  if (tcgetattr (fd, &orig) < 0)
    return -1;

  no_echo = orig;
  no_echo.c_lflag &= ~ECHO;

  if (tcsetattr (fd, TCSAFLUSH, &no_echo) < 0)
    return -1;

  rbytes = read(fd, pwd, 64);

  switch (rbytes)
    {
    case -1:
      xlog(LOG_ERROR, "failed to read pwd: %s\n", strerror(errno));
      break;

    case 0:
      xlog(LOG_ERROR, "EOF\n");
      rbytes = -1;
      break;

    default:
      pwd[rbytes-1] = '\0';
      cfg->password = pwd;
      rbytes = 0;
      break;
    }

  if (tcsetattr (fd, TCSAFLUSH, &orig) < 0)
    return -1;

  close(fd);
  printf("\n");
  fflush(stdout);

  return rbytes;
}

/**
 * Parse options
 *
 * @param cfg: pointer to sstp_config zone
 * @param argc: number of arguments
 * @param argv: argv
 */
static void parse_options (sstp_config* cfg, int argc, char** argv)
{
  int curopt, curopt_idx;

  const struct option long_opts[] = {
    { "help", 0, 0, 'h' },
    { "verbose", 0, 0, 'v' },
    { "server", 1, 0, 's' },
    { "port", 1, 0, 'p' },
    { "ca-file", 1, 0, 'c' },
    { "username", 1, 0, 'U' },
    { "password", 1, 0, 'P' },
    { "pppd-path", 1, 0, 'x' },
    { "logfile", 1, 0, 'l' },
    { "domain", 1, 0, 'd' },
    { "proxy", 1, 0, 'm' },
    { "proxy-port", 1, 0, 'n' },
    { "daemon", 0, 0, 'D' },
    { 0, 0, 0, 0 }
  };

  while (1)
    {
      curopt = -1;
      curopt_idx = 0;

      curopt = getopt_long (argc, argv,
			    "hvs:p:c:U:P:x:l:d:m:n:D",
			    long_opts, &curopt_idx);

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
	case 'D': cfg->daemon = 1; break;
	case 'm': cfg->proxy = optarg; break;
	case 'n': cfg->proxy_port = optarg; break;
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
static void check_required_arg(char* argument)
{
  if (argument == NULL)
    {
      xlog(LOG_ERROR, "Missing required argument.\n\n");
      usage(PROGNAME, EXIT_FAILURE);
    }
}


/**
 * Validates presence of an optional argument.
 *
 * @param argument : argument to be checked
 * @param default_value : default value to be used if undefined
 */
static void check_default_arg(char** argument, char* default_value)
{
  if ((*argument) == NULL)
    {
      xlog(LOG_WARNING, "Using default value: '%s'\n", default_value);
      *argument = default_value;
    }
}


/**
 * Initiates TCP connection to hostname on port port
 *
 * @return a socket (fd > 2) on success, a negative value on failure
 */
static sock_t init_tcp()
{
  sock_t sock;
  struct addrinfo hostinfo, *res, *ll;
  char *host, *port;

  memset(&hostinfo, 0, sizeof(struct addrinfo));
  hostinfo.ai_family = AF_UNSPEC;
  hostinfo.ai_socktype = SOCK_STREAM;
  hostinfo.ai_flags = 0;
  hostinfo.ai_protocol = 0;
  sock = -1;

  if (cfg->proxy)
    {
      xlog(LOG_INFO, "Using proxy %s:%s\n", cfg->proxy, cfg->proxy_port);
      host = cfg->proxy;
      port = cfg->proxy_port;
    }
  else
    {
      host = cfg->server;
      port = cfg->port;
    }

  if (getaddrinfo(host, port, &hostinfo, &res) < 0)
    {
      xlog(LOG_ERROR, "getaddrinfo failed\n");
      if (cfg->verbose > 2)
	xlog(LOG_DEBUG, "%s\n", strerror(errno));

      freeaddrinfo(res);
      return -1;
    }

  for (ll = res; ll; ll = ll->ai_next)
    {
      sock = socket(ll->ai_family,
		    ll->ai_socktype,
		    ll->ai_protocol);

      if (sock == -1)
	{
	  if (cfg->verbose)
	    xlog(LOG_ERROR, "init_tcp: socket: %s\n", strerror(errno));
	  continue;
	}

      if (connect(sock, ll->ai_addr, ll->ai_addrlen) == 0)
	break;

      if (cfg->verbose)
	xlog(LOG_ERROR, "init_tcp: connect: %s\n", strerror(errno));

      close(sock);
      sock = -1;
    }

  if (!ll || sock == -1)
    {
      xlog(LOG_ERROR, "Failed to create socket\n");
    }
  else
    {
      xlog(LOG_INFO,"Connected to %s:%s\n", host, port);

      if (cfg->verbose > 2)
	xlog(LOG_DEBUG, "Using fd %ld\n", sock);
    }

  freeaddrinfo(res);

  return sock;
}


/**
 * Establishes proxy CONNECT request to SSTP server.
 *
 * @return 0 if succeeded in connecting through proxy, negative otherwise
 */
static int proxy_connect()
{
  char buffer[1024];
  int len;

  memset(buffer, 0, 1024);
  len = snprintf(buffer, 1024,
		 "CONNECT %s:%s HTTP/1.0\r\n"
		 "SSTPVERSION: 1.0\r\n"
		 "User-Agent: %s-%.2f\r\n\r\n",
		 cfg->server, cfg->port,
		 PROGNAME, VERSION);

  if (cfg->verbose > 2)
    xlog(LOG_DEBUG, "Sending: %s\n", buffer);

  if (write(sockfd, buffer, len) < 0 )
    {
      xlog(LOG_ERROR, "Failed to send CONNECT\n%s", strerror(errno));
      return -1;
    }

  memset(buffer, 0, 1024);
  if (read(sockfd, buffer, 1024) < 0)
    {
      xlog(LOG_ERROR, "Failed to read CONNECT response\n%s", strerror(errno));
      return -1;
    }

  if (cfg->verbose > 2)
    xlog(LOG_DEBUG, "Received: %s\n", buffer);

  if (strncmp(buffer, "HTTP/1.0 200", 12) == 0 || strncmp(buffer, "HTTP/1.1 200", 12) == 0)
    return 0;

  xlog(LOG_ERROR, "Bad response from proxy, closing.\n");

  if ( shutdown(sockfd, SHUT_WR) || close(sockfd) )
    xlog(LOG_ERROR, "proxy_connect: %s\n", strerror(errno));

  return -1;
}

/**
 * Wrapper socket in a TLS session. There is no server certificate validation.
 *
 * @return 0 on success, or -1 on error.
 */
static int init_tls_session()
{
  int retcode;

#ifdef HAS_GNUTLS
  static const char *err;

  /*
   * On tested versions on Windows 2008 & 2012, enforcing support of TLS1.2 leads to
   * an error "Error in the pull function".
   *
   * TODO: check if corrected in fully patched Windows version
   */
  static char *ciphersuite = "NORMAL:-VERS-TLS1.2";

  gnutls_global_init();
  gnutls_init(&tls, GNUTLS_CLIENT);
  gnutls_session_set_ptr(tls, (void*) cfg->server);
  gnutls_server_name_set(tls, GNUTLS_NAME_DNS, cfg->server, strlen(cfg->server));

  retcode = gnutls_priority_set_direct(tls, ciphersuite, &err);
  if (retcode != GNUTLS_E_SUCCESS)
    {
      if (retcode == GNUTLS_E_INVALID_REQUEST)
	xlog(LOG_ERROR, (char*)err);
      else
	xlog(LOG_ERROR, "init_tls_session: gnutls_priority_set_direct: %s\n",
	     gnutls_strerror(retcode));
      return -1;
    }

  retcode = gnutls_certificate_allocate_credentials(&creds);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      xlog(LOG_ERROR, "init_tls_session: gnutls_certificate_allocate_credentials: %s\n",
	   gnutls_strerror(retcode));
      return -1;
    }

  retcode = gnutls_certificate_set_x509_trust_file (creds, cfg->ca_file, GNUTLS_X509_FMT_PEM);
  if (retcode < 1 )
    {
      xlog(LOG_ERROR, "init_tls_session: gnutls_certificate_set_x509_trust_file('%s') failed: %s\n",
           cfg->ca_file,
	   gnutls_strerror(retcode));
      return -1;
    }

  retcode = gnutls_credentials_set(tls, GNUTLS_CRD_CERTIFICATE, &creds);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      xlog(LOG_ERROR, "init_tls_session: tls_credentials_set: %s",
	   gnutls_strerror(retcode));
      return -1;
    }

  gnutls_transport_set_int(tls, sockfd);
  gnutls_handshake_set_timeout(tls, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  /* all ok, proceed with handshake */
  do {
          retcode = gnutls_handshake(tls);
          if (gnutls_error_is_fatal(retcode))
                  break;

  } while (retcode < 0);

  if (retcode < 0)
  {
          xlog(LOG_ERROR, "Handshake failed (returned %d): %s\n",
               -retcode, gnutls_strerror(retcode));
          return -1;
  }


#else
  char ssl_strerror[512];

  memset(&tls, 0, sizeof(mbedtls_ssl_context));
  memset(&tls_conf, 0, sizeof(mbedtls_ssl_config));
  memset(ssl_strerror, 0, sizeof(ssl_strerror));

  mbedtls_x509_crt_init( &certificate);
  mbedtls_entropy_init( &entropy );
  mbedtls_ctr_drbg_init( &ctr_drbg); //, mbedtls_entropy_func, &entropy,
                           //(const unsigned char *) PROGNAME,
                           //strlen( PROGNAME ) );


  mbedtls_ssl_init( &tls );
  
  /* PETER
  if( ( retcode = mbedtls_ssl_init( &tls ) ) != 0 )
  {
          mbedtls_strerror(retcode, ssl_strerror, sizeof(ssl_strerror)-1);
          xlog(LOG_ERROR, "init_tls_session: ssl_init returned %d: %s\n",
               retcode ,ssl_strerror);
          return -1;
    }
  */  

  mbedtls_ssl_conf_endpoint( &tls_conf, MBEDTLS_SSL_IS_CLIENT );
  mbedtls_ssl_conf_authmode( &tls_conf, MBEDTLS_SSL_VERIFY_NONE );

  /* See comment in GnuTLS section */
  mbedtls_ssl_conf_min_version( &tls_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
  mbedtls_ssl_conf_max_version( &tls_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);

  mbedtls_ssl_conf_rng( &tls_conf, mbedtls_ctr_drbg_random, &ctr_drbg );
  mbedtls_ssl_set_bio( &tls, &sockfd, mbedtls_net_recv, mbedtls_net_send, NULL );

  while( 1 )
  {
          retcode = mbedtls_ssl_handshake( &tls );
          if (retcode == 0)
                  break;

          if( retcode != MBEDTLS_ERR_SSL_WANT_READ && \
              retcode != MBEDTLS_ERR_SSL_WANT_WRITE )
          {
                  mbedtls_strerror(retcode, ssl_strerror, sizeof(ssl_strerror)-1);
                  xlog(LOG_ERROR, "init_tls_session: ssl_handshake (returns %#x): %s\n",
                       -retcode, ssl_strerror);
                return -1;
          }
  }
#endif

  return 0;
}


/**
 * Ends nicely TLS session
 *
 * @param reason: disconnection reason
 */
void end_tls_session(int reason)
{
  int retcode;

#ifdef HAS_GNUTLS
  retcode = gnutls_bye(tls, GNUTLS_SHUT_WR);
  if (retcode != GNUTLS_E_SUCCESS)
    xlog(LOG_ERROR, "end_tls_session: %s\n", gnutls_strerror(retcode));

  retcode = shutdown(sockfd, SHUT_WR);
  if (retcode < 0)
    xlog(LOG_ERROR, "end_tls_session: %s\n", strerror(errno));

  retcode = close(sockfd);
  if (retcode < 0)
    xlog(LOG_ERROR, "end_tls_session: %s\n", strerror(errno));

  gnutls_deinit(tls);
  gnutls_x509_crt_deinit (certificate);
  gnutls_certificate_free_credentials(creds);
  gnutls_global_deinit();

#else
  mbedtls_ssl_close_notify( &tls );

  retcode = shutdown(sockfd, SHUT_WR);
  if (retcode < 0)
    xlog(LOG_ERROR, "end_tls_session: %s\n", strerror(errno));

  retcode = close(sockfd);
  if (retcode < 0)
    xlog(LOG_ERROR, "end_tls_session: %s\n", strerror(errno));

  mbedtls_x509_crt_free( &certificate );
  mbedtls_ssl_free( &tls );
  mbedtls_entropy_free( &entropy );
  memset(&tls, 0, sizeof(mbedtls_ssl_context));
#endif

  if (cfg->verbose)
    xlog(LOG_INFO, "End of TLS connection, reason: %s.\n", reason ? "Failure" : "Success");
}


/**
 * Checks if process has a capability.
 *
 * @param flag: capability flag (man 7 capabilities)
 * @return: TRUE if process has capability, FALSE otherwise, -1 in case of error
 *
 * @obsolete
 */
static int is_cap(cap_value_t flag)
{
  cap_t caps = NULL;
  cap_flag_value_t cap_status = 0;
  int retcode;

  caps = cap_get_proc();

  if (!caps)
    {
      xlog(LOG_ERROR, "Error while getting caps\n");
      return -1;
    }

  if (cap_get_flag(caps, flag, CAP_EFFECTIVE , &cap_status) == -1)
    {
      xlog(LOG_ERROR, "Failed to get flag\n");
      cap_free(caps);
      return -1;
    }

  switch (cap_status)
    {
    case CAP_SET:
      retcode = TRUE;
      break;

    case CAP_CLEAR:
    default:
      retcode = FALSE;
      break;
    }

  if (cap_free(caps) == -1)
    {
      xlog(LOG_ERROR, "Fail to free caps\n");
      return -1;
    }

  return retcode;
}


/**
 * Checks certificate list
 *
 * @return 0 if all is good, -1 if not.
 */
static int check_tls_session()
{
#ifdef HAS_GNUTLS
  const gnutls_datum_t *certificate_list;
  unsigned int i, certificate_list_size;
  int retcode;

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

  for (i=0; i<certificate_list_size; i++)
    {
      retcode = gnutls_x509_crt_import (certificate, &certificate_list[i], GNUTLS_X509_FMT_DER);
      if (retcode == GNUTLS_E_SUCCESS) return 0;
    }

  xlog(LOG_ERROR, "check_tls_session: fail to import certificate\n");
  return -1;

#else
  int retcode;
  if( ( retcode = mbedtls_ssl_get_verify_result( &tls ) ) != 0 ) {
          if( ( retcode & MBEDTLS_X509_BADCERT_EXPIRED ) != 0 ) {
                  xlog(LOG_ERROR, "%s\n", "server certificate has expired" );
                  return -1;
          }

          if( ( retcode & MBEDTLS_X509_BADCERT_REVOKED ) != 0 ){
                  xlog(LOG_ERROR, "%s\n", "server certificate has been revoked" );
                  return -1;
          }

          if( ( retcode & MBEDTLS_X509_BADCERT_CN_MISMATCH ) != 0 ){
                  xlog(LOG_ERROR, "%s\n", "CN mismatch" );
                  return -1;
          }

          if( ( retcode & MBEDTLS_X509_BADCERT_NOT_TRUSTED ) != 0 ){
                  xlog(LOG_WARNING, "%s\n", "Self-signed or not signed by a trusted CA");
                  return 0;
          }

  } else
          if (cfg->verbose)
                  xlog(LOG_INFO, "%s\n", "Certificate is valid");
  return 0;

#endif
}


/**
 * Signal handling function.
 *
 * @param signum : signal number
 */
void sighandle(int signum)
{

  switch(signum)
    {
    case SIGALRM:
      xlog(LOG_ERROR, "Timer has expired, disconnecting\n");
      if(cfg->verbose)
	{
	  if (ctx->flags & HELLO_TIMER_RAISED)
	    xlog(LOG_ERROR, "HELLO_TIMER_RAISED flag raised (SSTP server did not Pong)\n");
	  if (ctx->flags & NEGOCIATION_TIMER_RAISED)
	    xlog(LOG_ERROR, "NEGOCIATION_TIMER_RAISED flag raised\n");
	}

      set_client_status(CLIENT_CALL_DISCONNECTED);
      break;

    case SIGCHLD:
      if (cfg->verbose)
	xlog(LOG_ERROR, "%s (PID:%d) died\n", cfg->pppd_path, ctx->pppd_pid);
      set_client_status(CLIENT_CALL_DISCONNECTED);
      break;

    case SIGINT:
      if (cfg->verbose)
	xlog(LOG_INFO, "Closing connection\n");

      set_client_status(CLIENT_CALL_DISCONNECTED);
      break;

    case SIGUSR1:
      if (cfg->verbose)
	xlog(LOG_INFO, "do_loop -> FALSE\n");

      do_loop = FALSE;

      break;

    }
}


/**
 * Change user
 *
 * @param user: username to switch to
 * @return 0 if all good, -1 otherwise
 */
int change_user(char* user)
{
  struct passwd* pw_entry;
  int retcode = 0;

  pw_entry = getpwnam(user);

  if (!pw_entry)
    {
      xlog(LOG_ERROR, "Failed to get user '%s': %s\n",
	   user, strerror(errno));
      return -1;
    }

  retcode = setuid(pw_entry->pw_uid);
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "Failed to drop privilege, exit\n");
      xlog(LOG_ERROR, "%s\n", strerror(errno));
      return -1;
    }

  return 0;
}


/**
 * Main function performs the following steps:
 * - set up signal handler
 * - parse & set upconfiguration
 * - initialize tcp connection
 * - initialize tls socket
 * - triggers https negocation
 *
 * @param argc: number of command-line argument
 * @param argv: array of command-line argument
 *
 * @return EXIT_SUCCESS in a perfect world, EXIT_FAILURE otherwise
 */
int main (int argc, char** argv)
{
  struct sigaction saction;
  int retcode;
  pid_t pid = -1;
  char *tempdir = NULL;


#if !defined  __linux__
  xlog (LOG_ERROR, "Operating system not supported\n");
  return EXIT_FAILURE;
#endif

  cfg = (sstp_config*) xmalloc(sizeof(sstp_config));

  parse_options(cfg, argc, argv);


  if (getuid() != 0 || geteuid() != 0)
    {
      /* got root ? */
      xlog (LOG_DEBUG, "%s is not running as root. Using capabilities\n",
	    argv[0]);

      /* or is capable ? *MUST* have KILL and SETEUID */
      retcode = is_cap(CAP_KILL);
      if (retcode != TRUE)
	{
	  xlog(LOG_ERROR, "Process not KILL capable. Check your privileges.\n");
	  goto end;
	}
      retcode = is_cap(CAP_SETUID);
      if (retcode != TRUE)
	{
	  xlog(LOG_ERROR, "Process is not SETEUID capable. Check your privileges.\n");
	  goto end;
	}

    }
  else
    {
      xlog (LOG_WARNING,
	    "%s is running as root. This could be potentially dangerous. "
	    "Consider using capabilities.\n",
	    argv[0]);
    }

  check_required_arg(cfg->server);
  check_required_arg(cfg->username);
  check_required_arg(cfg->ca_file);

  retcode = access (cfg->ca_file, R_OK);
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "%s is not readable.\n", cfg->ca_file);
      goto end;
    }

  cfg->ca_file = realpath(cfg->ca_file, NULL);

  if (!cfg->password)
    {
      if (cfg->verbose)
	xlog(LOG_INFO, "No password specified, prompting for one.\n");

      retcode = getpassword("Password: ");

      if (!cfg->password || retcode < 0)
	{
	  xlog(LOG_ERROR, "Failed to read password\n");
	  if (errno && cfg->verbose > 2)
	    xlog(LOG_ERROR, "errno: %s\n", strerror(errno));

	  goto end;
	}
    }

  check_default_arg(&cfg->port, "443");
  check_default_arg(&cfg->pppd_path, "/usr/sbin/pppd");

  if (cfg->proxy)
    check_default_arg(&cfg->proxy_port, "8080");

  if (cfg->proxy_port && !cfg->proxy)
    xlog(LOG_ERROR, "No PROXYHOST specified for PROXYPORT '%s'. Dropping.\n",
	 cfg->proxy_port);

  retcode = access (cfg->pppd_path, X_OK);
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "Failed to access ppp binary.\n");
      goto end;
    }

  cfg->pppd_path = realpath(cfg->pppd_path, NULL);

  if (cfg->verbose)
    xlog(LOG_INFO, "Verbose level: %d\n", cfg->verbose);


  /* catch signal */
  memset(&saction, 0, sizeof(struct sigaction));
  saction.sa_handler = sighandle;
  saction.sa_flags = SA_NOCLDSTOP|SA_NOCLDWAIT;
  sigemptyset(&saction.sa_mask);

  sigaction(SIGINT, &saction, NULL);
  sigaction(SIGALRM, &saction, NULL);
  sigaction(SIGCHLD, &saction, NULL);
  sigaction(SIGUSR1, &saction, NULL);


  /* main starts here */
  if (cfg->daemon)
    {
      if (cfg->verbose > 1)
	xlog(LOG_DEBUG, "Starting daemon (send SIGINT to close properly)\n");

      if (daemon(0, 0) < 0)
	{
	  xlog(LOG_ERROR, "daemon failed: %s\n", strerror(errno));
	  goto end;
	}
    }

  if (cfg->verbose > 1)
    xlog (LOG_DEBUG, "Starting %s as %d\n", argv[0], getpid());

  /* create socket  */
  sockfd = init_tcp();
  if (sockfd < 0)
    {
      xlog(LOG_ERROR, "TCP socket has failed, leaving...\n");
      goto end;
    }

  if (cfg->proxy != NULL)
    {
      retcode = proxy_connect();
      if (retcode < 0)
	goto end;
    }


  /* drop privileges and change user */
  if (cfg->verbose)
    xlog(LOG_INFO, "Dropping privileges\n");

  tempdir = strdup(NO_PRIV_DIR) ;
  if ( !mkdtemp(tempdir) )
    {
      xlog(LOG_ERROR, "Failed to `mkdtemp': %s\n", strerror(errno));
      retcode = -1;
      goto disco;
    }

  retcode = chdir(tempdir);
  if (retcode)
    {
      xlog(LOG_ERROR, "Failed to `chdir': %s\n", strerror(errno));
      retcode = -1;
      goto disco;
    }
  if (cfg->verbose > 1)
    xlog(LOG_DEBUG, "chdir-ed to'%s'\n", tempdir);

  /* if user is not root, all privileges can be dropped right now */
  /* otherwise, will be done after way down */
  if (getuid() != 0)
    {
      retcode = change_user(NO_PRIV_USER);
      if (retcode < 0)
	goto disco;
      if (cfg->verbose > 1)
	xlog(LOG_DEBUG, "Switch user to '%s'\n", NO_PRIV_USER);
      }

  /* create forked pppd process as suspended */
  pid = sstp_fork();
  if (pid <= 0)
    {
      xlog(LOG_ERROR, "Cannot create pppd process, leaving.\n");
      retcode = -1 ;
      goto disco;
    }

  if (cfg->verbose)
    xlog (LOG_INFO, "'%s' forked with PID %d\n", cfg->pppd_path, pid);


  /* wrap socket with tls socket */
  retcode = init_tls_session();
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "TLS session initialization has failed, leaving.\n");
      goto disco;
    }

  retcode = check_tls_session();
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "TLS session check failed, leaving.\n");
      goto disco;
    }

  if (cfg->verbose)
    xlog(LOG_INFO, "TLS session ready\n");


  if (cfg->verbose)
    xlog(LOG_INFO, "Initiating HTTPS negociation\n");

  retcode = https_session_negociation();
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "An error occured in HTTPS negociation, leaving.\n");
      goto disco;
    }

  if (cfg->verbose)
    xlog(LOG_INFO, "HTTPS session ready\n");

  /* wake up pppd */
  retcode = kill(pid, SIGUSR1);
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "[FATAL] Failed to send signal %d to PID:%d\n", SIGUSR1, pid);
      if (cfg->verbose > 1)
	xlog(LOG_ERROR, "Reason: %s\n", strerror(errno));

      retcode = -1;
      goto disco;
    }


  /* if sstoper was launched as root, we can drop privs here */
  if (getuid() == 0)
    {
      retcode = change_user(NO_PRIV_USER);
      if (retcode < 0)
	goto disco;
      if (cfg->verbose > 1)
	xlog(LOG_DEBUG, "Switch user to '%s'\n", NO_PRIV_USER);
    }

  /* start sstp session */
  if (cfg->verbose)
    xlog(LOG_INFO, "Initiating SSTP negociation\n");

  sleep(1);

  sstp_loop(pid);

 disco:
  unlink(tempdir);

  if (pid > 0)
    kill(pid, SIGTERM);

  retcode = !retcode ? EXIT_SUCCESS : EXIT_FAILURE;
  end_tls_session(retcode);

 end :
  xfree(tempdir);
  xfree(cfg->pppd_path);
  xfree(cfg->ca_file);
  xfree(cfg);
  return retcode;
}

/*
 * SSToPer, Linux SSTP Client
 * Christophe Alladoum < ca __AT__ hsc __DOT__ fr>
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
 */

#define _GNU_SOURCE 1
#define _POSIX_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
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
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/capability.h>

#include "sstpclient.h"
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

  if (type != LOG_INFO) 
    {   
      t = time(NULL);
      tm = localtime(&t);
      strftime(time_buf, 128, "%F %T", tm);
      fprintf(stderr, "%s  ", time_buf);
    }
  
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
  @param ptr: pointer to zone to free
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
void usage(char* name, int retcode)
{
  FILE* fd;
  
  fd = (retcode == 0) ? stdout : stderr;
      
  fprintf(fd,
	  "\n%s, version %.2f : "
	  "SSTP VPN client for %s\n"
	  "\n"
	  "Usage (as root):\n\t%s -s server -c ca_file -U username [-P password] [OPTIONS+]\n"
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
#if defined __linux__
	  "Linux",
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
int getpassword(const char* prompt)
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
void parse_options (sstp_config* cfg, int argc, char** argv)
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
void check_required_arg(char* argument)
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
void check_default_arg(char** argument, char* default_value)
{
  if ((*argument) == NULL)
    {
      xlog(LOG_WARNING, "Using default value: %s\n", default_value);
      *argument = default_value;
    }
}


/**
 * Initiates TCP connection to hostname on port port
 *
 * @return a socket (fd > 2) on success, a negative value on failure
 */
sock_t init_tcp()
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
  
  xlog(LOG_INFO, "Connecting to %s:%s ", cfg->server, cfg->port);

  if (cfg->proxy)
    {
      xlog(LOG_INFO, "through proxy %s:%s ", cfg->proxy, cfg->proxy_port);
      host = cfg->proxy;
      port = cfg->proxy_port;
    }
  else 
    {
      host = cfg->server;
      port = cfg->port;
    }
  xlog(LOG_INFO, "\n");

  if (getaddrinfo(host, port, &hostinfo, &res) < 0)
    {
      xlog(LOG_INFO, "getaddrinfo failed\n");
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
      xlog(LOG_INFO, "Connected\n");
      
      if (cfg->verbose > 2)
	xlog(LOG_DEBUG, "Using fd %ld\n", sock);
    }
  
  freeaddrinfo(res);
 
  return sock;
}


/**
 * Establishes proxy CONNECT request to SSTP server. 
 *
 * @param sockfd
 * @return 0 if succeeded in connecting through proxy, negative otherwise
 */
int proxy_connect(int sockfd) 
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
 * Wrapper socket in a GnuTLS session. There is no server certificate validation.
 *
 * @return 0 on success, or -1 on error.
 */
int init_tls_session()
{
  int retcode;
  const char* err;
  
  gnutls_global_init();
  gnutls_init(&tls, GNUTLS_CLIENT);

  retcode = gnutls_priority_set_direct (tls, "SECURE256", &err);  
  if (retcode != GNUTLS_E_SUCCESS)
    {
      if (retcode == GNUTLS_E_INVALID_REQUEST)
	xlog(LOG_ERROR, (char*)err);
      else
	xlog(LOG_ERROR, "init_tls_session: gnutls_priority_set_direct: %s\n",
	     gnutls_strerror(retcode));	
      return -1;
    }

  retcode = gnutls_certificate_allocate_credentials (&creds);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      xlog(LOG_ERROR, "init_tls_session: gnutls_certificate_allocate_credentials: %s\n",
	   gnutls_strerror(retcode));
      return -1;
    }

  retcode = gnutls_certificate_set_x509_trust_file (creds, cfg->ca_file, GNUTLS_X509_FMT_PEM);
  if (retcode < 1 )
    {
      xlog(LOG_ERROR, "init_tls_session: gnutls_certificate_set_x509_trust_file: %s\n",
	   gnutls_strerror(retcode));
      return -1;
    }

  retcode = gnutls_credentials_set (tls, GNUTLS_CRD_CERTIFICATE, &creds);
  if (retcode != GNUTLS_E_SUCCESS )
    {
      xlog(LOG_ERROR, "init_tls_session: tls_credentials_set: %s",
	   gnutls_strerror(retcode));
      return -1;
    }
  
  gnutls_transport_set_ptr (tls, (gnutls_transport_ptr_t) sockfd);

  /* all ok, proceed with handshake */
  retcode = gnutls_handshake (tls);
  if (retcode != GNUTLS_E_SUCCESS)
    {
      xlog(LOG_ERROR, "init_tls_session: gnutls_handshake: %s\n",
	   gnutls_strerror(retcode));
      return -1;
    }
  
  retcode = check_tls_session();
  if (retcode < 0 )
    return -1;

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

  if (cfg->verbose)
    xlog(LOG_INFO, "End of TLS connection, reason: %s.\n", reason ? "Failure" : "Success");
}


/**
 * Checks if process has a capability.
 *
 * @param flag: capability flag (man 7 capabilities)
 * @return: TRUE if process has capability, FALSE otherwise, -1 in case of
 * error
 */
int is_cap(cap_value_t flag)
{
  cap_t caps = NULL;
  cap_flag_value_t cap_status = 0;
  
  caps = cap_get_proc();

  if (!caps)
    {
      xlog(LOG_ERROR, "Error while getting caps\n");
      return -1;
    }

  if (cap_get_flag(caps, flag, CAP_EFFECTIVE , &cap_status) == -1) 
    {
      xlog(LOG_ERROR, "Failed to get flag\n");
      return -1;
    }

  switch (cap_status) 
    {
    case CAP_SET:
      if (cfg->verbose > 1)
	xlog(LOG_INFO, "CAP_KILL capability set\n");
      return TRUE;
      
    case CAP_CLEAR:
      if (cfg->verbose > 1)
	xlog(LOG_INFO, "CAP_KILL capability not set\n");
      return FALSE;
     }
  
  if (cap_free(caps) == -1)
    {
      xlog(LOG_ERROR, "Fail to free caps\n");
      return -1;
    }

  return -1;
}


/**
 * Give process capability
 *
 * @param flag: capability flag to set (man 7 capabilities)
 * @return: 0 if process acquired capability, -1 in case of error
 */
int set_cap(cap_value_t flag)
{
  cap_t caps = NULL;
    
  caps = cap_get_proc();

  if (!caps)
    {
      xlog(LOG_ERROR, "Error while getting caps\n");
      return -1;
    }

  if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &flag, CAP_SET) == -1)
    {
      xlog(LOG_ERROR, "Error while settting flag\n");
      return -1;
    }

  if (cap_set_proc(caps) == -1) 
    {
      xlog(LOG_ERROR, "Error while applying caps\n");
      return -1;
    }

  if (cap_free(caps) == -1)
    {
      xlog(LOG_ERROR, "Fail to free caps\n");
      return -1;
    }

  return 0;
}


/**
 * Unset capability
 *
 * @param flag: capability flag to unset (man 7 capabilities)
 * @return: 0 if capability was removed, -1 in case of error
 */
int unset_cap(cap_value_t flags)
{
  cap_t caps = NULL;
    
  caps = cap_get_proc();

  if (!caps)
    {
      xlog(LOG_ERROR,  "Error while getting caps\n");
      return -1;
    }

  if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &flags, CAP_CLEAR) == -1)
    {
      xlog(LOG_ERROR, "failed to change cap\n");
      return -1;
    }

  if (cap_set_proc(caps) == -1) 
    {
      xlog(LOG_ERROR, "Error while applying caps\n");
      return -1;
    }

  if (cap_free(caps) == -1)
    {
      xlog(LOG_ERROR, "Fail to free caps\n");
      return -1;
    }

  return 0;  
}


/**
 * Checks certificate list
 *
 * @return 0 if all is good, -1 if not.
 */
int check_tls_session()
{
  const gnutls_datum_t *certificate_list;
  unsigned int certificate_list_size;
  int retcode, i;
   
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
 * @param final: if TRUE, it won't be possible to re-gain root privs
 * @return 0 if all good, -1 otherwise
 */
int change_user(char* user, int final) 
{
  struct passwd* pw_entry;
  int retcode = 0;
  int (*DROP)();
  
  pw_entry = getpwnam(user);
  if (cfg->verbose)
    xlog(LOG_INFO, "Switch user to '%s'\n", user);
  
  if (!pw_entry)
    {
      xlog(LOG_ERROR, "Failed to get user '%s': %s\n",
	   user, strerror(errno));
      return -1;     
    }

  if (final)
    DROP = &setuid;
  else
    DROP = &seteuid;
  
  retcode = DROP(pw_entry->pw_uid);
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "Failed to drop privilege, exit\n");
      xlog(LOG_ERROR, "%s\n", strerror(errno));
      return -1;
    }

  return 0;
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
 * @return EXIT_SUCCESS in a perfect world, EXIT_FAILURE otherwise
 */
int main (int argc, char** argv, char** envp)
{
  struct sigaction saction;
  int retcode;

  
#if !defined  __linux__
  xlog (LOG_ERROR, "Operating system not supported\n");
  return EXIT_FAILURE;
#endif

  /* check  */
  if (getuid()) 
    {
      xlog (LOG_ERROR, "pppd requires %s to be executed with root privileges.\n", argv[0]);
      usage(argv[0], EXIT_FAILURE);
    }
  
  cfg = (sstp_config*) xmalloc(sizeof(sstp_config));
    
  parse_options(cfg, argc, argv);
  
  check_required_arg(cfg->server);
  check_required_arg(cfg->username);
  check_required_arg(cfg->ca_file);
  
  retcode = access (cfg->ca_file, R_OK);
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "%s is not readable.\n", cfg->ca_file);
      goto end;
    }

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
    xlog(LOG_INFO, "No PROXYHOST specified for PROXYPORT '%s'. Dropping.\n", cfg->proxy_port);
  
  retcode = access (cfg->pppd_path, X_OK);
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "Failed to access ppp binary.\n");
      goto end;
      xfree(cfg);
      return EXIT_FAILURE;
    }

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
      if (cfg->verbose)
	xlog(LOG_INFO, "Starting daemon (send SIGINT to close properly)\n");

      if (daemon(0, 0) < 0)
	{
	  xlog(LOG_ERROR, "daemon failed: %s\n", strerror(errno));
	  goto end;
	}
    }
  
  if (cfg->verbose)
    xlog (LOG_INFO, "Starting %s as %d\n", argv[0], getpid());

  sockfd = init_tcp(); 
  if (sockfd < 0) 
    {
      xlog(LOG_ERROR, "TCP socket has failed, leaving...\n");
      goto end;
    }

  if (cfg->proxy != NULL) 
    {
      retcode = proxy_connect(sockfd);
  
      if (retcode < 0)
	goto end;
    }
  
  retcode = init_tls_session(sockfd, &tls); 
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "TLS session initialization has failed, leaving.\n");
      goto disco;
    }

  
  /* create forked pppd process and suspend it */
  pid_t pid = sstp_fork();
  if (pid <= 0)
    {
      xlog(LOG_ERROR, "Cannot create pppd process, leaving.\n");
      retcode = -1 ;
      goto disco;
    }
  
  if (cfg->verbose)
    xlog (LOG_INFO, "'%s' forked with PID %d\n", cfg->pppd_path, pid);
  

  /* drop sstoper privileges */
  retcode = chdir(NO_PRIV_DIR);
  if (cfg->verbose)
    xlog(LOG_INFO, "chdir-ed '%s'\n", NO_PRIV_DIR);
  
  if (retcode)
    {
      xlog(LOG_ERROR, "%s\n", strerror(errno));
      retcode = -1;
      goto disco;
    }
  
  retcode = change_user(NO_PRIV_USER, FALSE);
  if (retcode < 0) 
    goto disco;

  
  /* acquire CAP_SETUID to be able to drop privs later */ 
  retcode = set_cap(CAP_SETUID);
  if (retcode < 0)
    goto disco;

  
  /* acquire CAP_KILL to send USR1 once negociation is done */ 
  retcode = is_cap(CAP_KILL);
  switch(retcode)
    {
    case FALSE:
      retcode = set_cap(CAP_KILL);
      if (retcode < 0)
	goto disco;

      retcode = is_cap(CAP_KILL);
      if (retcode != TRUE)
	{
	  xlog(LOG_ERROR, "Failed to position CAP_KILL flags\n");
	  retcode = -1;
	  goto disco;
	}
      
      break;

    case TRUE:
      if (cfg->verbose > 1)
	xlog(LOG_INFO, "Process is already capable\n");
      break;

    default:
      xlog(LOG_ERROR, "Failed to get capabilities flags\n");
      retcode = -1;
      goto disco;
    }

  
  /* sstoper here has no privilege (nobody) but CAP_KILL cap */
  
  
  if (cfg->verbose)
    xlog(LOG_INFO, "Initiating HTTPS negociation\n");
  
  retcode = https_session_negociation();  
  if (retcode < 0)
    {
      xlog(LOG_ERROR, "An error occured in HTTPS negociation, leaving.\n");
      goto disco;
    }
    
      
  if (cfg->verbose)
    xlog(LOG_INFO, "Initiating SSTP negociation\n");
  
  sstp_loop(pid);

  
 disco:
  retcode = !retcode ? EXIT_SUCCESS : EXIT_FAILURE; 
  end_tls_session(retcode);
  
 end :
  xfree(cfg);
  return retcode;
}

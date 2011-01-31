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


#ifdef __GNUC__
#define UNUSED __attribute__ ((unused))
#else
#define UNUSED
#endif

#ifdef __x86_64
typedef long sock_t;
#else
typedef int sock_t;
#endif

#define assert(x) {\
    fprintf(stderr, "-----------------------\n"	\
	    "Assertion failed.\n"		\
	    "File: %s\nLine: %d\n"		\
	    "Assertion: %s\n\n",		\
	    __FILE__, __LINE__, #x);		\
    exit(1);					\
  }

#ifndef SIZE_MAX
#define SIZE_MAX ~((size_t)1)
#endif

enum 
  {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
  };

typedef struct 
{
  int verbose;
  int daemon;
  char* server;
  char* port;  
  char* ca_file;
  char* username;
  char* password;
  char* logfile;
  char* pppd_path;
  char* domain;
  char* proxy;
  char* proxy_port;
} sstp_config;

gnutls_session_t tls;
gnutls_x509_crt_t certificate;
gnutls_certificate_credentials_t creds;
sock_t sockfd;
sstp_config *cfg;
int do_loop;


extern int snprintf (char *__restrict __s, size_t __maxlen, __const char *__restrict __format, ...);

void xlog(int type, const char* fmt, ...); 
void* xmalloc(size_t size);
void xfree(void*);

sock_t init_tcp();
int init_tls_session();
int check_tls_session();
void end_tls_session(int);
int getpassword( const char*);
int change_user(char*, int);


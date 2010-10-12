#ifdef __GNUC__
#define UNUSED __attribute__ ((unused))
#else
#define UNUSED
#endif

/* structure definition */
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
    LOG_ERROR
  };

typedef struct 
{
  int verbose;
  char* server;
  char* port;  
  char* ca_file;
  char* username;
  char* password;
  char* logfile;
  char* pppd_path;
  char* domain;  
} sstp_config;

gnutls_session_t tls;
gnutls_x509_crt_t certificate;
sock_t sockfd;
sstp_config *cfg;


/* compat ansi */
extern int snprintf (char *__restrict __s, size_t __maxlen, __const char *__restrict __format, ...);


/* functions declaration */
void xlog(int type, const char* fmt, ...); 
void* xmalloc(size_t size);

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
	    "Assertion: %s\n\n"			\
	    ,__FILE__,__LINE__,#x);		\
    exit(1);					\
  }

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
  char* crt_file;
  char* key_file;
} sstp_config;


gnutls_session_t* tls;
sock_t sockfd;
sstp_config *cfg;


/* functions declaration */
void* xmalloc(size_t);
void xlog(int, const char*, ...);
void end_tls_session(int);


/* compat ansi */
extern int snprintf (char *__restrict __s, size_t __maxlen, __const char *__restrict __format, ...);

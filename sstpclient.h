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


/* functions declaration */
void xlog(int, const char*, ...);
sock_t init_tcp(char*, char*);
gnutls_session_t* init_tls_session(sock_t, sstp_config*);
void tls_session_loop(gnutls_session_t*, sstp_config*);
void end_tls_session(gnutls_session_t*, sock_t, int);
void usage(char*, FILE*, int);
void parse_options (sstp_config*, int, char**);

/* compat ansi */
extern int snprintf (char *__restrict __s, size_t __maxlen, __const char *__restrict __format, ...);

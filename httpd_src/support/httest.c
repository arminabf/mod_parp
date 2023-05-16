/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. 
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file
 *
 * @Author christian liesch <liesch@gmx.ch>
 *
 * Implementation of the HTTP Test Tool.
 */
#define HTT_VERSION "0.12.0a"

/* affects include files on Solaris */
#define BSD_COMP

/************************************************************************
 * Includes
 ***********************************************************************/

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#define USE_SSL
#define SK_NUM(x) sk_X509_num(x)
#define SK_VALUE(x,y) sk_X509_value(x,y)
typedef STACK_OF(X509) X509_STACK_TYPE;

#include <pcre.h>

#include <apr.h>
#include <apr_signal.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_file_io.h>
#include <apr_time.h>
#include <apr_getopt.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_thread_proc.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
#include <apr_support.h>
#include <apr_hash.h>
#include <apr_base64.h>
#include <apr_env.h>
#include <unistd.h>             /* for getpid() */

/************************************************************************
 * Defines 
 ***********************************************************************/
#define min(a,b) ((a)<(b))?(a):(b)
#define max(a,b) ((a)>(b))?(a):(b)

#ifndef POSIX_MALLOC_THRESHOLD
#define POSIX_MALLOC_THRESHOLD (10)
#endif

#ifndef DEFAULT_THREAD_STACKSIZE
#define DEFAULT_THREAD_STACKSIZE 262144 
#endif

#define VAR_ALLOWED_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
#define RSA_SERVER_CERT "server.cert.pem"
#define RSA_SERVER_KEY "server.key.pem"

#define LISTENBACKLOG_DEFAULT 511
	
#define COMMAND_NEED_ARG(err_text) \
{ \
  int i = 0; \
  while (data[i] == ' ') { \
    ++i; \
  } \
  if(!data[i]) { \
    worker_log(worker, LOG_ERR, err_text); \
    return APR_EGENERAL; \
  } \
  copy = apr_pstrdup(worker->ptmp, &data[i]); \
  copy = worker_replace_vars(worker, copy); \
  worker_log(worker, LOG_INFO, "%s %s", self->name, copy); \
}

#define COMMAND_OPTIONAL_ARG \
{ \
  int i = 0; \
  while (data[i] == ' ') { \
    ++i; \
  } \
  copy = apr_pstrdup(worker->ptmp, &data[i]); \
  copy = worker_replace_vars(worker, copy); \
  worker_log(worker, LOG_INFO, "%s %s", self->name, copy); \
}

#define COMMAND_NO_ARG \
  worker_log(worker, LOG_INFO, "%s", self->name)
			
/************************************************************************
 * Structurs
 ***********************************************************************/
#define BLOCK_MAX 8192
     typedef struct bufreader_s {
       apr_pool_t *pool;
       apr_file_t *fp;
       apr_size_t i;
       apr_size_t len;
       char buf[BLOCK_MAX + 1];
     } bufreader_t;

    typedef struct socket_s {
       apr_socket_t *socket;
#define SOCKET_CLOSED 0
#define SOCKET_CONNECTED 1
       int socket_state;
#ifdef USE_SSL
       int is_ssl;
       SSL *ssl;
#endif
       apr_size_t peeklen;
       char peek[32];
    } socket_t;

     typedef struct sockreader_s {
       apr_pool_t *pool;
       apr_socket_t *socket;
#ifdef USE_SSL
       SSL *ssl;
#endif
       apr_size_t i;
       apr_size_t len;
       char buf[BLOCK_MAX + 1];
     } sockreader_t;

     typedef struct worker_s {
       /* this is the pool where the structure lives */
       apr_pool_t *heartbeat;
       /* dies on END */
       apr_pool_t *pool;
       /* dies on every _REQ/_RES */
       apr_pool_t *ptmp;
       const char *filename;
#define FLAGS_NONE          0x00000000
#define FLAGS_PIPE          0x00000001
#define FLAGS_CHUNKED       0x00000002
#define FLAGS_IGNORE_ERRORS 0x00000004
#define FLAGS_PIPE_IN       0x00000008
       int flags;
       apr_proc_t proc;
       int cmd;
       int which;
       char *name;
       char *prefix;
       char *additional;
       char *file_and_line;
       int chunksize;
       apr_time_t socktmo;
       apr_thread_t *mythread;
       apr_thread_cond_t *sync_cond;
       apr_thread_mutex_t *sync_mutex;
       apr_table_t *lines;
       apr_table_t *cache;
       apr_table_t *expect_error;
       apr_table_t *expect_dot;
       apr_table_t *match_headers;
       apr_table_t *match_body;
       apr_table_t *match_error;
       apr_table_t *headers_allow;
       apr_table_t *headers_filter;
       apr_table_t *vars;
       apr_hash_t *blocks;
       apr_hash_t *sockets;
       apr_socket_t *listener;
       socket_t *socket;
       int listener_port;
#define LOG_NONE 0
#define LOG_ERR 1
#define LOG_WARN 2
#define LOG_INFO 3
#define LOG_DEBUG 4
       int log_mode;
#ifdef USE_SSL
       int is_ssl;
       SSL_CTX *ssl_ctx;
       SSL_METHOD *meth;
       BIO *bio_out;
       BIO *bio_err;
       char *ssl_info;
#endif
     } worker_t;

     typedef struct global_s {
       apr_pool_t *pool;
       const char *filename;
       apr_table_t *vars;
       apr_hash_t *blocks;
       int log_mode;
       apr_table_t *threads;
       int CLTs; 
       int SRVs; 
       apr_thread_cond_t *cond; 
       apr_thread_mutex_t *mutex;
       int line_nr;
#define GLOBAL_STATE_NONE   0
#define GLOBAL_STATE_CLIENT 1
#define GLOBAL_STATE_SERVER 2
#define GLOBAL_STATE_BLOCK  3
#define GLOBAL_STATE_DAEMON  4
       int state;
       int socktmo;
       char *prefix;
       worker_t *worker;
       apr_threadattr_t *tattr;
       int recursiv;
     } global_t;

     typedef struct {
       int match;
       void *re_pcre;
       apr_size_t re_nsub;
       apr_size_t re_erroffset;
     } regex_t;

     typedef struct {
       int rm_so;
       int rm_eo;
     } regmatch_t;

     typedef struct command_s command_t;
     typedef apr_status_t(*command_f) (command_t * self,
                                       void * type, char *data);

     struct command_s {
       char *name;
       command_f func;
       char *syntax;
       char *help;
     };

/************************************************************************
 * Globals 
 ***********************************************************************/

     static apr_status_t command_REQ(command_t * self, worker_t * worker,
                                     char *data);
     static apr_status_t command_RES(command_t * self, worker_t * worker,
                                     char *data);
     static apr_status_t command_WAIT(command_t * self, worker_t * worker,
                                      char *data);
     static apr_status_t command_SLEEP(command_t * self,
                                       worker_t * worker, char *data);
     static apr_status_t command_EXPECT(command_t * self,
                                        worker_t * worker, char *data);
     static apr_status_t command_CLOSE(command_t * self,
                                       worker_t * worker, char *data);
     static apr_status_t command_TIMEOUT(command_t * self,
                                         worker_t * worker, char *data);
     static apr_status_t command_MATCH(command_t * self,
                                       worker_t * worker, char *data);
     static apr_status_t command_SET(command_t * self, worker_t * worker,
                                     char *data);
     static apr_status_t command_IF(command_t * self, worker_t * worker,
                                    char *data);
     static apr_status_t command_DATA(command_t * self, worker_t * worker,
                                      char *data);
     static apr_status_t command_FLUSH(command_t * self, worker_t * worker,
                                       char *data);
     static apr_status_t command_CHUNK(command_t * self, worker_t * worker,
                                       char *data);
     static apr_status_t command_EXEC(command_t * self, worker_t * worker,
                                      char *data);
     static apr_status_t command_PIPE(command_t * self, worker_t * worker,
                                       char *data);
     static apr_status_t command_NOCRLF(command_t * self, worker_t * worker,
                                        char *data);
     static apr_status_t command_SOCKSTATE(command_t * self, worker_t * worker,
                                           char *data);
     static apr_status_t command_IGNORE_ERR(command_t * self, worker_t * worker,
                                               char *data);
     static apr_status_t command_EXIT(command_t * self, worker_t * worker,
                                      char *data);
     static apr_status_t command_HEADER(command_t *self, worker_t *worker, 
	                                char *data);
     static apr_status_t command_LOOP(command_t *self, worker_t *worker, 
	                              char *data);
     static apr_status_t command_RAND(command_t *self, worker_t *worker, 
	                              char *data);
     static apr_status_t command_DEBUG(command_t *self, worker_t *worker, 
	                               char *data);
     static apr_status_t command_UP(command_t *self, worker_t *worker, 
	                            char *data);
     static apr_status_t command_DOWN(command_t *self, worker_t *worker, 
	                              char *data);
     static apr_status_t command_TIME(command_t *self, worker_t *worker, 
	                              char *data);
     static apr_status_t command_CALL(command_t *self, worker_t *worker,
	                              char *data);
     static apr_status_t command_LOG_LEVEL(command_t *self, worker_t *worker,
	                                   char *data);
     static apr_status_t command_SYNC(command_t *self, worker_t *worker,
	                              char *data);
     static apr_status_t command_RECV(command_t * self, worker_t * worker,
                                      char *data);
     static apr_status_t command_OP(command_t * self, worker_t * worker,
                                    char *data);
     static apr_status_t command_WHICH(command_t * self, worker_t * worker,
                                       char *data);
     static apr_status_t command_CERT(command_t * self, worker_t * worker,
                                      char *data);

     static apr_status_t global_GO(command_t *self, global_t *global, 
	                           char *data); 
     static apr_status_t global_END(command_t *self, global_t *global, 
	                            char *data); 
     static apr_status_t global_DAEMON(command_t *self, global_t *global, 
	                               char *data); 
     static apr_status_t global_BLOCK(command_t *self, global_t *global,
	                              char *data);
     static apr_status_t global_CLIENT(command_t *self, global_t *global, 
	                               char *data); 
     static apr_status_t global_SERVER(command_t *self, global_t *global, 
	                               char *data); 
     static apr_status_t global_EXEC(command_t *self, global_t *global, 
	                             char *data); 
     static apr_status_t global_SET(command_t *self, global_t *global, 
	                            char *data); 
     static apr_status_t global_INCLUDE(command_t *self, global_t *global, 
	                                char *data); 
     static apr_status_t global_TIMEOUT(command_t *self, global_t *global, 
	                                char *data); 

     command_t global_commands[] = {
       {"END", (command_f )global_END, "", 
	"Close CLIENT|SERVER body"},
       {"CLIENT", (command_f )global_CLIENT, "[<number of concurrent clients>]", 
	"Client body start, close it with END and a newline"},
       {"SERVER", (command_f )global_SERVER, "[<SSL>:]<port> [<number of concurrent servers>]", 
	"Server body start, close it with END and a newline,\n"
        "number of concurrent servers could be -1 for unlimited,\n"
        "<SSL>: SSL, SSL2, SSL3, TLS"},
       {"EXEC", (command_f )global_EXEC, "<shell command>", 
	"Execute a shell command, attention executes will not join CLIENT/SERVER"},
       {"SET", (command_f )global_SET, "<variable>=<value>", 
	"Store a value in a global variable"},
       {"INCLUDE", (command_f )global_INCLUDE, "<include file>", 
	"Load and execute defined include file,\n"
	"current path is taken the callers current path"},
       {"TIMEOUT", (command_f )global_TIMEOUT, "<timeout in ms>", 
	"Defines global socket timeout"},
       {"GO", (command_f )global_GO, "", 
	"Starts all client in sync mode"},
       {"BLOCK", (command_f )global_BLOCK, "<name>", 
	"Store a block of commands to call it from a CLIENT/SERVER/BLOCK"},
       {"DAEMON", (command_f )global_DAEMON, "", 
	"Daemon body start, close it with END and a newline. \n"
        "A daemon will not join CLIENT/SERVER and could therefore be used\n"
        "for supervisor jobs" },
       {NULL, NULL, NULL,
	NULL }
     };

     command_t local_commands[] = {
       {"__", (command_f )command_DATA, "<string>", 
	"Send <string> to the socket with a CRLF at the end of line"},
       {"_-", (command_f )command_NOCRLF, "<string>", 
	"Same like __ but no CRLF at the end of line"},
       {"_FLUSH", (command_f )command_FLUSH, "", 
	"Flush the cached lines, \n"
	"the AUTO Content-Length calculation will take place here"},
       {"_CHUNK", (command_f )command_CHUNK, "", 
	"Mark the end of a chunk block, all data after last _FLUSH are counted,\n"
	"does automatic add chunk info"},
       {"_REQ", (command_f )command_REQ, "<host> [<SSL>:]<port>[:<tag>] [<client-cert> <client-key>]", 
	"Start a request to defined host:port, with SSL support.\n"
	"Does only open a new connection if we are in connection state CLOSED\n"
        "<SSL>: SSL, SSL2, SSL3, TLS"},
       {"_RES", (command_f )command_RES, "", 
	"Wait for a connection accept"},
       {"_WAIT", (command_f )command_WAIT, "[<amount of bytes>]", 
	"Wait for data and receive them.\n"
        "Optional you could receive a specific amount of bytes" },
       {"_CLOSE", (command_f )command_CLOSE, "", 
	"Close the connection and set the connection state to CLOSED"},
       {"_EXPECT", (command_f )command_EXPECT, ". \"[!]<regex>\"", 
	"Define what data we do or do not expect on a WAIT command.\n"
        "Negation with a leading '!' in the <regex>"},
       {"_MATCH", (command_f )command_MATCH, "(header|body) \"<regex>\" <variable>", 
	 "Define a regex with a match which should be stored in <variable>"},
       {"_IF", (command_f )command_IF, "\"<expression>\" MATCH \"[!]<regex>\"", 
	"Test if variable do or do not match the regex, close body with _END IF,\n"
        "negation with a leading '!' in the <regex>,\n"
	"<expression> must not be empty"},
       {"_LOOP", (command_f )command_LOOP, "<n>", 
	"Loop body start end with _END do loop the body <n> times,\n"
	"close body with _END LOOP"},
       {"_SLEEP", (command_f )command_SLEEP, "<milisecond>", 
	 "Sleep for defined amount of time"},
       {"_TIMEOUT", (command_f )command_TIMEOUT, "<milisecond", 
	 "Set socket timeout"},
       {"_SET", (command_f )command_SET, "<variable>=<value>", 
	"Store a value in a local variable"},
       {"_EXEC", (command_f )command_EXEC, "<shell command>", 
	"Execute a shell command, _EXEC| will pipe the incoming stream on the\n"
        "socket in to the called shell command"},
       {"_PIPE", (command_f )command_PIPE, "[chunked [<chunk_size>]]", 
	"Start a pipe for stream the output of EXEC to the socket stream,\n" 
	"wiht optional chunk support"},
       {"_SOCKSTATE", (command_f )command_SOCKSTATE, "<variable>", 
	"Stores connection state CLOSED or CONNECTED in the <variable>"},
       {"_IGNORE_ERR", (command_f )command_IGNORE_ERR, "<regex>", 
	"Ignores errors specified in <regex>, \n"
	"i.e. \".*\" would ignore all errors"},
       {"_EXIT", (command_f )command_EXIT, "[OK|FAILED]", 
	"Exits with OK or FAILED default is FAILED"},
       {"_HEADER", (command_f )command_HEADER, "ALLOW|FILTER <header name>", 
	"Defines allowed headers or headers to filter,\n"
	"default all headers are allowed and no headers are filtered.\n"
	"Filter only for receive mechanisme"},
       {"_RAND", (command_f )command_RAND, "<start> <end>", 
	"Generates a number between <start> and <end>"},
       {"_DEBUG", (command_f )command_DEBUG, "<string>", 
	"Prints to stderr for debugging reasons"},
       {"_UP", (command_f )command_UP, "", 
	"Setup listener"},
       {"_DOWN", (command_f )command_DOWN, "", 
	"Shutdown listener"},
       {"_TIME", (command_f )command_TIME, "<variable>", 
	"Store time in variable [ms]"},
       {"_CALL", (command_f )command_CALL, "<name of block>", 
	"Call a defined block"},
       {"_LOG_LEVEL", (command_f )command_LOG_LEVEL, "<level>", 
	"Level is a number 0-4"},
       {"_SYNC", (command_f )command_SYNC, "", 
	"Synchronise to the next full second"},
       {"_RECV", (command_f )command_RECV, "<bytes>", 
	"Receive an amount of bytes"},
       {"_OP", (command_f )command_OP, "<left> ADD|SUB|DIV|MUL <right> <variable>", 
	"Store evaluated expression"},
       {"_WHICH", (command_f )command_WHICH, "<variable>", 
	"Stores the concurrency number of current thread"},
       {"_CERT", (command_f )command_CERT, "<cert-file> <key-file>", 
	"Sets cert for the current ssl connection, mainly used for server cert"},
       {NULL, NULL, NULL, 
	NULL},
     };

     int success = 1;
     
/************************************************************************
 * Private 
 ***********************************************************************/

static apr_status_t worker_flush(worker_t * self);
static apr_status_t worker_clone(worker_t ** self, worker_t * orig); 
static apr_status_t worker_body(worker_t **body, worker_t *worker, char *end); 
static void worker_body_end(worker_t *body, worker_t *worker); 
static void worker_destroy(worker_t * self); 
static apr_status_t worker_interpret(worker_t * self, worker_t * parent); 
static void worker_finally(worker_t *self, apr_status_t status); 

/****
 * Utils
 ****/
/*
 * Similar to standard strstr() but we ignore case in this version.
 * Based on the strstr() implementation further below.
 * 
 * @param s1 IN string to lookin in
 * @param s2 IN string to look for
 *
 * @return pointer to found substring or NULL
 */
char *my_strcasestr(const char *s1, const char *s2) {
  char *p1, *p2;
  if (*s2 == '\0') {
    /* an empty s2 */
    return((char *)s1);
  }
  while(1) {
    for ( ; (*s1 != '\0') && (apr_tolower(*s1) != apr_tolower(*s2)); s1++);
      if (*s1 == '\0') {
	return(NULL);
      }
      /* found first character of s2, see if the rest matches */
      p1 = (char *)s1;
      p2 = (char *)s2;
      for (++p1, ++p2; apr_tolower(*p1) == apr_tolower(*p2); ++p1, ++p2) {
	if (*p1 == '\0') {
	  /* both strings ended together */
	  return((char *)s1);
	}
      }
      if (*p2 == '\0') {
	/* second string ended, a match */
	break;
      }
      /* didn't find a match here, try starting at next character in s1 */
      s1++;
  }
  return((char *)s1);
}

/**
 * get a string starting/ending with a char, unescape this char if found as an 
 * escape sequence.
 *
 * @param string IN <char><string with escaped <char>><char>
 * @param last OUT pointer to next char after cutted string
 *
 * @return <string with unescaped <char>>
 * @note: Example: "foo bar \"hallo velo\"" -> foo bar "hallo velo"
 */
static char *unescape(char *string, char **last) {
  char *result;
  char enclose;
  apr_size_t i;
  apr_size_t j;
  apr_size_t len;

  if (!string) {
    return string;
  }
  
  len = strlen(string);
  
  enclose = string[0];
  result = string;
  for (i = 1, j = 0; i < len; i++, j++) {
    /* check if we have an escape char */
    if (string[i] == '\\') {
      /* lookahead */
      ++i;
      /* if lookahead is not \ or " store the \ too, else skip */
      if (string[i] != '\\' && string[i] != enclose) {
	result[j] = '\\';
	++j;
      }
    }
    /* break if we got the first char unescaped */
    else if (string[i] == enclose) {
      ++i;
      break;
    }
    /* store char in result */
    result[j] = string[i];
  }
  result[j] = 0;
  *last = &string[i]; 
  return result;
}

/**
 * realloc memory in pool
 *
 * @param p IN pool
 * @param mem_old IN old memory
 * @param size_old IN old memory size
 * @param size_new IN new memory size
 *
 * @return new memory
 */
static void *my_realloc(apr_pool_t *p, void *mem_old, apr_size_t size_old, 
                        apr_size_t size_new) {
  void *mem_new;

  mem_new = apr_palloc(p, size_new);
  if (mem_old != NULL) {
    memcpy(mem_new, mem_old, size_old < size_new ? size_old : size_new);
  }

  return mem_new;
}

/**
 * Deep table copy
 *
 * @param p IN pool
 * @param orig IN orig table
 *
 * @return copy of orig
 */
static apr_table_t *my_table_deep_copy(apr_pool_t *p, apr_table_t *orig) {
  apr_table_entry_t *e;
  apr_table_t *dest;
  int i;
  apr_size_t size;

  if (!orig) {
    dest = apr_table_make(p, 5);
    return dest;
  }

  size  = apr_table_elts(orig)->nelts;

  if (size < 5) {
    size = 5;
  }
  dest = apr_table_make(p, size);
  e = (apr_table_entry_t *) apr_table_elts(orig)->elts;
  for (i = 0; i < apr_table_elts(orig)->nelts; ++i) {
    apr_table_add(dest, e[i].key, e[i].val);
  }

  return dest;
}

/**
 * Swallow table copy
 *
 * @param p IN pool
 * @param orig IN orig table
 *
 * @return copy of orig
 */
static apr_table_t *my_table_swallow_copy(apr_pool_t *p, apr_table_t *orig) {
  apr_table_entry_t *e;
  apr_table_t *dest;
  int i;
  apr_size_t size;
    
  if (!orig) {
    dest = apr_table_make(p, 5);
    return dest;
  }

  size  = apr_table_elts(orig)->nelts;

  if (size < 5) {
    size = 5;
  }
  dest = apr_table_make(p, size);
  e = (apr_table_entry_t *) apr_table_elts(orig)->elts;
  for (i = 0; i < apr_table_elts(orig)->nelts; ++i) {
    apr_table_addn(dest, apr_pstrdup(p, e[i].key), e[i].val);
  }

  return dest;
}

/**
 * Unset global success
 *
 * @param self IN thread data object
 */
static void worker_set_global_error(worker_t *self) {
  if (apr_thread_mutex_lock(self->sync_mutex) != APR_SUCCESS) {
    return;
  }
  success = 0;
  if (apr_thread_mutex_unlock(self->sync_mutex) != APR_SUCCESS) {
    return;
  }
}

/**
 * a simple log mechanisme
 *
 * @param self IN thread data object
 * @param log_mode IN log mode
 *                    LOG_DEBUG for a lot of infos
 *                    LOG_INFO for much infos
 *                    LOG_ERR for only very few infos
 * @param fmt IN printf format string
 * @param ... IN params for format strings
 */
static void worker_log(worker_t * self, int log_mode, char *fmt, ...) {
  char *tmp;
  va_list va;

  va_start(va, fmt);
  if (self->log_mode >= log_mode) {
    if (log_mode == LOG_ERR) {
      tmp = apr_pvsprintf(self->ptmp, fmt, va);
      fprintf(stderr, "\n%-84s", tmp);
      fflush(stderr);
    }
    else {
      fprintf(stdout, "\n%s", self->prefix);
      vfprintf(stdout, fmt, va);
      fflush(stdout);
    }
  }
  va_end(va);
}

/**
 * a simple error log mechanisme
 *
 * @param self IN thread data object
 * @param fmt IN printf format string
 * @param ... IN params for format strings
 */
static void worker_log_error(worker_t * self, char *fmt, ...) {
  char *tmp;
  va_list va;

  va_start(va, fmt);
  if (self->log_mode >= LOG_ERR) {
    tmp = apr_pvsprintf(self->ptmp, fmt, va);
    tmp = apr_psprintf(self->ptmp, "%s: error: %s", self->file_and_line,
	               tmp);
    fprintf(stderr, "\n%s", tmp);
    fflush(stderr);
  }
}

/**
 * a simple log buf mechanisme
 *
 * @param self IN thread data object
 * @param log_mode IN log mode
 *                    LOG_DEBUG for a lot of infos
 *                    LOG_INFO for much infos
 *                    LOG_ERR for only very few infos
 * @param buf IN buf to print (binary data allowed)
 * @param prefix IN prefix before buf
 * @param len IN buf len
 */
static void worker_log_buf(worker_t * self, int log_mode, char *buf,
                           char *prefix, int len) {
  int i;
  char *null="<null>";

  FILE *fd = stdout;

  if (!buf) {
    buf = null;
    len = strlen(buf);
  }
  
  if (log_mode == LOG_ERR) {
    fd = stderr;
  }
  if (self->log_mode >= log_mode) {
    i = 0;
    while (i < len) {
      fprintf(fd, "\n%s%s", self->prefix, prefix);
      while (i < len && buf[i] != '\r' && buf[i] != '\n') {
	if (buf[i] >= 0x20) {
	  fprintf(fd, "%c", buf[i]);
	}
	else {
	  fprintf(fd, "0x%02x ", (unsigned char)buf[i]);
	}
        i++;
      }
      while (buf[i] == '\r' || buf[i] == '\n') {
        i++;
      }
      fflush(fd);
    }
  }
}

/**
 * get the status string
 *
 * @param p IN pool
 * @param rc IN status to print
 *
 * @return status string
 */
static char *get_status_str(apr_pool_t * p, apr_status_t rc) {
  char *text = apr_pcalloc(p, 201);
  apr_strerror(rc, text, 200);
  return text;
}

#ifdef USE_SSL
#ifndef RAND_MAX
#include <limits.h>
#define RAND_MAX INT_MAX
#endif

/**
 * To ensure thread-safetyness in OpenSSL - work in progress
 */
static apr_thread_mutex_t **lock_cs;
static int lock_num_locks;

/**
 * This is a SSL lock call back
 *
 * @param mode IN lock mode
 * @param type IN lock type
 * @param file IN unused
 * @param line IN unused
 */
static void ssl_util_thr_lock(int mode, int type, const char *file, int line) {
  apr_status_t status;

  if (type < lock_num_locks) {
    if (mode & CRYPTO_LOCK) {
      if ((status = apr_thread_mutex_lock(lock_cs[type])) != APR_SUCCESS) {
	fprintf(stderr, "Fatal error could not lock");
	exit(status);
      }
    }
    else {
      if ((status = apr_thread_mutex_unlock(lock_cs[type])) != APR_SUCCESS) {
	fprintf(stderr, "Fatal error could not unlock");
	exit(status);
      }
    }
  }
}

/**
 * @return current thread id (SSL call back)
 */
static unsigned long ssl_util_thr_id(void) {
  /* OpenSSL needs this to return an unsigned long.  On OS/390, the pthread
   * id is a structure twice that big.  Use the TCB pointer instead as a
   * unique unsigned long.
   */
#ifdef __MVS__
  struct PSA {
    char unmapped[540];
    unsigned long PSATOLD;
  }  *psaptr = 0;

  return psaptr->PSATOLD;
#else
  return (unsigned long) apr_os_thread_current();
#endif
}

/**
 * Thread clean up function (SSL call back)
 *
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
static apr_status_t ssl_util_thread_cleanup(void *data) {
  CRYPTO_set_locking_callback(NULL);
  CRYPTO_set_id_callback(NULL);

  /* Let the registered mutex cleanups do their own thing
   */
  return APR_SUCCESS;
}

/**
 * Thread setup (SSL call back)
 *
 * @param p IN pool
 */
void ssl_util_thread_setup(apr_pool_t * p) {
  int i;

  lock_num_locks = CRYPTO_num_locks();
  lock_cs = apr_palloc(p, lock_num_locks * sizeof(*lock_cs));

  for (i = 0; i < lock_num_locks; i++) {
    apr_thread_mutex_create(&(lock_cs[i]), APR_THREAD_MUTEX_DEFAULT, p);
  }

  CRYPTO_set_id_callback(ssl_util_thr_id);

  CRYPTO_set_locking_callback(ssl_util_thr_lock);

  apr_pool_cleanup_register(p, NULL, ssl_util_thread_cleanup,
                            apr_pool_cleanup_null);
}

/**
 * Rand between low and high
 *
 * @param l IN bottom
 * @param h IN top value
 *
 * @return something between l and h
 */
static int ssl_rand_choosenum(int l, int h) {
  int i;
  char buf[50];

  srand((unsigned int) time(NULL));
  apr_snprintf(buf, sizeof(buf), "%.0f",
               (((double) (rand() % RAND_MAX) / RAND_MAX) * (h - l)));
  i = atoi(buf) + 1;
  if (i < l)
    i = l;
  if (i > h)
    i = h;
  return i;
}

/**
 * Do a seed
 */
static void ssl_rand_seed(void) {
  int nDone = 0;
  int n, l;
  time_t t;
  pid_t pid;
  unsigned char stackdata[256];

  /*
   * seed in the current time (usually just 4 bytes)
   */
  t = time(NULL);
  l = sizeof(time_t);
  RAND_seed((unsigned char *) &t, l);
  nDone += l;

  /*
   * seed in the current process id (usually just 4 bytes)
   */
  pid = getpid();
  l = sizeof(pid_t);
  RAND_seed((unsigned char *) &pid, l);
  nDone += l;

  /*
   * seed in some current state of the run-time stack (128 bytes)
   */
  n = ssl_rand_choosenum(0, sizeof(stackdata) - 128 - 1);
  RAND_seed(stackdata + n, 128);
  nDone += 128;
}

/**
 * SSL call back for printing infos
 */
static long ssl_print_cb(BIO * bio, int cmd, const char *argp, int argi,
                         long argl, long ret) {
  BIO *out;

  out = (BIO *) BIO_get_callback_arg(bio);
  if (out == NULL)
    return (ret);

  if (cmd == (BIO_CB_READ | BIO_CB_RETURN)) {
    BIO_printf(out, "\nread from %p [%p] (%d bytes => %ld (0x%lX))",
               bio, argp, argi, ret, ret);
    BIO_dump(out, (char *) argp, (int) ret);
    return (ret);
  }
  else if (cmd == (BIO_CB_WRITE | BIO_CB_RETURN)) {
    BIO_printf(out, "\nwrite to %p [%p] (%d bytes => %ld (0x%lX))",
               bio, argp, argi, ret, ret);
    BIO_dump(out, (char *) argp, (int) ret);
  }
  return ret;
}

/**
 * worker ssl handshake client site
 *
 * @param worker IN thread data object
 *
 * @return apr status
 */
static apr_status_t worker_ssl_handshake(worker_t * worker) {
  apr_status_t status = APR_SUCCESS;
  int do_next = 1;

  while (do_next) {
    int ret, ecode;

    apr_sleep(1);
    
    ret = SSL_do_handshake(worker->socket->ssl);
    ecode = SSL_get_error(worker->socket->ssl, ret);

    switch (ecode) {
    case SSL_ERROR_NONE:
      if (worker->ssl_info == NULL) {
        SSL_CIPHER *ci;
        X509 *cert;
        int sk_bits, pk_bits, swork;

        ci = SSL_get_current_cipher(worker->socket->ssl);
        sk_bits = SSL_CIPHER_get_bits(ci, &swork);
        cert = SSL_get_peer_certificate(worker->socket->ssl);
        if (cert) {
          pk_bits = EVP_PKEY_bits(X509_get_pubkey(cert));
        }
        else {
          pk_bits = 0;          /* Anon DH */
        }

        worker->ssl_info = apr_pcalloc(worker->pool, 129);
        apr_snprintf(worker->ssl_info, 128, "%s,%s,%d,%d",
                     SSL_CIPHER_get_version(ci),
                     SSL_CIPHER_get_name(ci), pk_bits, sk_bits);
      }
      status = APR_SUCCESS;
      do_next = 0;
      break;
    case SSL_ERROR_WANT_READ:
      worker_log(worker, LOG_DEBUG, "SSL handshake SSL_ERROR_WANT_READ.");
      /* Try again */
      do_next = 1;
      break;
    case SSL_ERROR_WANT_WRITE:
      /* Try again */
      worker_log(worker, LOG_DEBUG, "SSL handshake SSL_ERROR_WANT_WRITE.");
      do_next = 1;
      break;
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
      worker_log(worker, LOG_ERR, "SSL handshake failed %d.", ecode);
      status = APR_ECONNREFUSED;
      do_next = 0;
      break;
    }
  }
  return status;
}

/**
 * Get server ctx with loaded cert and key file
 *
 * @param self IN thread object data
 *
 * @return APR_SUCCESS or APR_ECONNABORTED
 */
static apr_status_t worker_ssl_ctx(worker_t * self, char *certfile, char *keyfile) {
  if (self->is_ssl && !self->ssl_ctx) {
    if (!(self->ssl_ctx = SSL_CTX_new(self->meth))) {
      worker_log(self, LOG_ERR, "Could not initialize SSL Context.");
    }
  }
  if (self->is_ssl && self->ssl_ctx) {
    if (SSL_CTX_use_certificate_file(self->ssl_ctx, certfile, 
	SSL_FILETYPE_PEM) <= 0) { 
      worker_log(self, LOG_ERR, "Could not load RSA server certifacte \"%s\"",
	         RSA_SERVER_CERT);
      return APR_ECONNABORTED;
    }
    if (SSL_CTX_use_PrivateKey_file(self->ssl_ctx, keyfile, 
	SSL_FILETYPE_PEM) <= 0) {
      worker_log(self, LOG_ERR, "Could not load RSA server private key \"%s\"",
	         RSA_SERVER_KEY);
      return APR_ECONNABORTED;
    }
    if (!SSL_CTX_check_private_key(self->ssl_ctx)) {
      worker_log(self, LOG_ERR, "Private key does not match the certificate public key");
      return APR_ECONNABORTED;
    }
  }
  return APR_SUCCESS;
}

/**
 * Do a ssl accept
 *
 * @param worker IN thread data object
 *
 * @return APR_SUCCESS
 */
static apr_status_t worker_ssl_accept(worker_t * worker) {
  apr_status_t status;
  int rc;
  int err;

  if (worker->socket->is_ssl) {
    if (!worker->socket->ssl) {
      BIO *bio;
      apr_os_sock_t fd;

      if ((worker->socket->ssl = SSL_new(worker->ssl_ctx)) == NULL) {
	worker_log(worker, LOG_ERR, "SSL_new failed.");
	status = APR_ECONNREFUSED;
      }
      SSL_set_ssl_method(worker->socket->ssl, worker->meth);
      ssl_rand_seed();
      apr_os_sock_get(&fd, worker->socket->socket);
      bio = BIO_new_socket(fd, BIO_NOCLOSE);
      SSL_set_bio(worker->socket->ssl, bio, bio);

      if (worker->log_mode >= LOG_DEBUG) {
	BIO_set_callback(bio, ssl_print_cb);
	BIO_set_callback_arg(bio, (void *) worker->bio_err);
      }
    }
    else {
      return APR_SUCCESS;
    }
  }
  else {
    return APR_SUCCESS;
  }

tryagain:
  apr_sleep(1);
  if (SSL_is_init_finished(worker->socket->ssl)) {
    return APR_SUCCESS;
  }

  if ((rc = SSL_accept(worker->socket->ssl)) <= 0) {
    err = SSL_get_error(worker->socket->ssl, rc);

    if (err == SSL_ERROR_ZERO_RETURN) {
      worker_log(worker, LOG_ERR, 
	         "SSL accept connection closed"); 
      return APR_ECONNABORTED;
    }
    else if (err == SSL_ERROR_WANT_READ) {
      worker_log(worker, LOG_DEBUG, "SSL accept SSL_ERROR_WANT_READ.");
      goto tryagain;
    }
    else if (ERR_GET_LIB(ERR_peek_error()) == ERR_LIB_SSL &&
	     ERR_GET_REASON(ERR_peek_error()) == SSL_R_HTTP_REQUEST) {
      /*
       * The case where OpenSSL has recognized a HTTP request:
       * This means the client speaks plain HTTP on our HTTPS port.
       * ssl_io_filter_error will disable the ssl filters when it
       * sees this status code.
       */
      worker_log(worker, LOG_ERR, 
	         "SSL accept client speaks plain HTTP"); 
      return APR_ENOTSOCK;
    }
    else if (err == SSL_ERROR_SYSCALL) {
       worker_log(worker, LOG_ERR,
                  "SSL accept interrupted by system "
                  "[Hint: Stop button pressed in browser?!]");
    }
    else /* if (ssl_err == SSL_ERROR_SSL) */ {
	 /*
	  * Log SSL errors and any unexpected conditions.
          */
      worker_log(worker, LOG_ERR,
		 "SSL library error %d in accept", err);
      return APR_ECONNABORTED;
    }
  }
  
  return APR_SUCCESS;
}
#endif

/**
 * replace vars in given line 
 *
 * @param p IN pool
 * @param line IN line where to replace the vars with values
 * @param vars IN table of key value pairs
 *
 * @return new line
 */
static char *replace_vars(apr_pool_t * p, char *line, apr_table_t * vars) {
  int i;
  int start;
  int line_end;
  char *var_name;
  char *new_line;
  const char *val;
  char *env;

  new_line = line;

once_again:
  i = 0;
  while (line[i] != 0) {
    if (line[i] == '$') {
      line_end = i;
      ++i;
      if (line[i] == '{') {
        ++i;
      }
      start = i;
      while (line[i] != 0 && strchr(VAR_ALLOWED_CHARS, line[i])) {
        ++i;
      }
      var_name = apr_pstrndup(p, &line[start], i - start);
      val = apr_table_get(vars, var_name);
      if (!val) {
        if (apr_env_get(&env, var_name, p) == APR_SUCCESS) {
	  val = env;
	}
      }
      if (val) {
        line[line_end] = 0;
        if (line[i] == '}') {
          ++i;
        }
        new_line = apr_pstrcat(p, line, val, &line[i], NULL);
        line = new_line;
        goto once_again;
      }
    }
    ++i;
  }

  return new_line;
}

/****
 * Regular expression object
 ****/

/**
 * Free a regular expression
 *
 * @param preg IN compiled regular expression
 */
void regfree(regex_t * preg) {
  pcre_free(preg->re_pcre);
}

/**
 * Clean up function for pool cleanup
 *
 * @preg IN compiled regular expression
 *
 * @return APR_SUCCESS
 */
static apr_status_t regex_cleanup(void *preg) {
  pcre_free(((regex_t *) preg)->re_pcre);
  return APR_SUCCESS;
}

/**
 * Compile a pattern to a regular expression
 *
 * @param p IN pool
 * @param pattern IN pattern to compile
 * @param error IN error string
 * @param erroff IN offset into pattern wherer compilation fails
 *
 * @return regular express on success else NULL
 */
static regex_t *pregcomp(apr_pool_t * p, const char *pattern,
                         const char **error, int *erroff) {
  regex_t *preg = apr_palloc(p, sizeof *preg);

  preg->match = 0;

  preg->re_pcre = pcre_compile(pattern, 0, error, erroff, NULL);
  preg->re_erroffset = *erroff;

  if (preg->re_pcre == NULL)
    return NULL;

  preg->re_nsub = pcre_info((const pcre *) preg->re_pcre, NULL, NULL);

  apr_pool_cleanup_register(p, (void *) preg, regex_cleanup,
                            apr_pool_cleanup_null);

  return preg;
}

/**
 * Execute a string on a compiled regular expression
 *
 * @param preg IN regular expression
 * @param string IN string to parse
 * @param nmatch IN number of matches
 * @param pmatch IN offest of matched substrings
 * @param eflags IN extended flags see pcre.h
 *
 * @return 0 on success
 */
int regexec(regex_t * preg, const char *string,
            apr_size_t nmatch, regmatch_t pmatch[], int eflags) {
  int rc;
  int options = 0;
  int *ovector = NULL;
  int small_ovector[POSIX_MALLOC_THRESHOLD * 3];
  int allocated_ovector = 0;

  ((regex_t *) preg)->re_erroffset = (apr_size_t) (-1); /* Only has meaning after compile */

  if (nmatch > 0) {
    if (nmatch <= POSIX_MALLOC_THRESHOLD) {
      ovector = &(small_ovector[0]);
    }
    else {
      ovector = (int *) malloc(sizeof(int) * nmatch * 3);
      allocated_ovector = 1;
    }
  }

  rc = pcre_exec((const pcre *) preg->re_pcre, NULL, string,
                 (int) strlen(string), 0, options, ovector, nmatch * 3);

  if (rc == 0)
    rc = nmatch;                /* All captured slots were filled in */

  if (rc >= 0) {
    apr_size_t i;
    for (i = 0; i < (apr_size_t) rc; i++) {
      pmatch[i].rm_so = ovector[i * 2];
      pmatch[i].rm_eo = ovector[i * 2 + 1];
    }
    if (allocated_ovector)
      free(ovector);
    for (; i < nmatch; i++)
      pmatch[i].rm_so = pmatch[i].rm_eo = -1;
    ++preg->match;
    return 0;
  }
  else {
    if (allocated_ovector)
      free(ovector);
    return rc;
  }
}

/**
 * returns number of matches on this regular expression
 *
 * @param preg IN regular expression
 *
 * @return number of matches
 */
static int regdidmatch(regex_t * preg) {
  return preg->match;
}

/**
 * Test socket state
 *
 * @param worker IN thread data object
 *
 * @return APR_SUCCESS or APR_ECONNABORTED
 */
static apr_status_t worker_sockstate(worker_t * worker) {
  apr_status_t status;
  apr_size_t len;

  len = 1;

  if (!worker->socket || !worker->socket->socket) {
    return APR_ENOSOCKET;
  }
  
  if ((status = apr_socket_timeout_set(worker->socket->socket, 0)) 
      != APR_SUCCESS) {
    return status;
  }

#ifdef USE_SSL
  if (worker->socket->ssl) {
    status = SSL_read(worker->socket->ssl, &worker->socket->peek[worker->socket->peeklen], len);
    if (status <= 0) {
      int scode = SSL_get_error(worker->socket->ssl, status);

      if (scode == SSL_ERROR_ZERO_RETURN) {
        return APR_ECONNABORTED; 
      }
      else if (scode != SSL_ERROR_WANT_WRITE && scode != SSL_ERROR_WANT_READ) {
        return APR_ECONNABORTED; 
      }
      else {
	++worker->socket->peeklen;
	goto go_out;
      }
    }
    else {
      goto go_out;
    }
  }
  else
#endif
  {
    status = apr_socket_recv(worker->socket->socket, 
	                     &worker->socket->peek[worker->socket->peeklen], &len);
    if (status == APR_EOF) {
      return APR_ECONNABORTED; 
    }
    else {
      ++worker->socket->peeklen;
      goto go_out;
    }
  }

go_out:
  if ((status = apr_socket_timeout_set(worker->socket->socket, worker->socktmo)) 
      != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/****
 * Object sockreader 
 ****/

/**
 * fill up our buf of 8K
 *
 * @param self IN sockreader object
 *
 * @param APR_SUCCESS else an APR error
 */
static apr_status_t sockreader_fill(sockreader_t * self) {
  apr_status_t status;

  self->i = 0;
  self->len = BLOCK_MAX;

  if (!self->socket) {
    return APR_ENOSOCKET;
  }
  
#ifdef USE_SSL
  if (self->ssl) {
  tryagain:
    apr_sleep(1);
    status = SSL_read(self->ssl, self->buf, self->len);
    if (status <= 0) {
      int scode = SSL_get_error(self->ssl, status);

      if (scode == SSL_ERROR_ZERO_RETURN) {
	self->len = 0;
        return APR_EOF;
      }
      else if (scode != SSL_ERROR_WANT_WRITE && scode != SSL_ERROR_WANT_READ) {
	self->len = 0;
        return APR_ECONNABORTED;
      }
      else {
        goto tryagain;
      }
    }
    else {
      self->len = status;
      return APR_SUCCESS;
    }
  }
  else
#endif
  {
    status = apr_socket_recv(self->socket, self->buf, &self->len);
    if (status == APR_EOF && self->len == 0) {
      return APR_EOF;
    }
    else {
      return status;
    }
  }
}

/**
 * read line
 *
 * @param self IN sockreader object
 * @param line OUT read line
 *
 * @return APR_SUCCESS else an APR error
 */
static apr_status_t sockreader_read_line(sockreader_t * self, char **line) {
  apr_status_t status;
  char c;
  apr_size_t i;
  apr_size_t size;
  char *new_size_line;

  *line = NULL;
  size = 0;

  i = 0;
  c = 0;
  while (c != '\n') {
    if (i >= size) {
      size += 512;
      new_size_line = apr_palloc(self->pool, size + 1);
      if (*line != NULL) {
        memcpy(new_size_line, *line, size - 512);
      }
      *line = new_size_line;
    }
    if (self->i >= self->len) {
      if ((status = sockreader_fill(self)) != APR_SUCCESS) {
        return status;
      }
    }

    if (self->i < self->len) {
      c = self->buf[self->i];
      (*line)[i] = c;
      self->i++;
      i++;
    }
  }
  if (i) {
    (*line)[i - 1] = 0;
  }
  if (i > 1 && (*line)[i - 2] == '\r') {
    (*line)[i - 2] = 0;
  }
  else {
    (*line)[i] = 0;
  }
  return APR_SUCCESS;
}

/**
 * Read specifed block
 *
 * @param self IN sockreader object
 * @param block IN a block to fill up
 * @param length INOUT length of block, on return length of filled bytes
 *
 * @return APR_SUCCESS else APR error
 */
static apr_status_t sockreader_read_block(sockreader_t * self, char *block,
                                          apr_size_t *length) {
  apr_status_t status;
  int i;
  int len = *length;

  status = APR_SUCCESS;
  i = 0;
  while (i < len) {
    if (self->i >= self->len) {
      if ((status = sockreader_fill(self)) != APR_SUCCESS) {
        break;
      }
    }

    block[i] = self->buf[self->i];
    ++i;
    ++self->i;
  }

  /* on eof we like to get the bytes recvieved so far */
  while (i < len && self->i < self->len) {
    block[i] = self->buf[self->i];
    ++i;
    ++self->i;
  }

  *length = i;

  return status;
}

/**
 * Create a new sockreader object
 *
 * @param sockreader OUT new sockreader object
 * @param socket IN connected socket
 * @param p IN pool
 *
 * @return APR_SUCCESS else an APR error
 */
static apr_status_t sockreader_new(sockreader_t ** sockreader,
                                   apr_socket_t * socket,
#ifdef USE_SSL
                                   SSL * ssl,
#endif
                                   apr_pool_t * p) {
  apr_status_t status;

  *sockreader = apr_pcalloc(p, sizeof(sockreader_t));

  (*sockreader)->socket = socket;
#ifdef USE_SSL
  (*sockreader)->ssl = ssl;
#endif
  (*sockreader)->pool = p;

  if ((status = sockreader_fill((*sockreader))) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/****
 * Http helper based on sockreader
 ****/

/**
 * content length reader 
 *
 * @param sockreader IN sockreader object
 * @param buf OUT content buffer
 * @param ct IN content length
 *
 * @return APR_SUCCESS else an APR error
 */
static apr_status_t content_length_reader(sockreader_t * sockreader,
                                          char **buf, apr_size_t *ct, const char *val) {
  apr_size_t len = *ct;
  char *read;

  read = apr_pcalloc(sockreader->pool, len + 1);
  sockreader_read_block(sockreader, read, &len);
  read[len] = 0;
  *buf = read;
  *ct = len;

  return APR_SUCCESS;
}

/**
 * Transfer encoding reader (only chunked implemented) 
 *
 * @param sockreader IN sockreader object
 * @param buf OUT content buffer
 * @param val IN type of encoding 
 *
 * @return APR_SUCCESS else an APR error
 */
static apr_status_t transfer_enc_reader(sockreader_t * sockreader,
                                        char **buf, apr_size_t *len, const char *val) {
  apr_status_t status;
  char *end;
  char *line;
  int chunk;
  char *read;
  apr_size_t cur_len;
  apr_size_t chunk_cur;
  apr_size_t chunk_len;

  *buf = NULL;
  (*len) = 0;
  read = apr_pcalloc(sockreader->pool, 1);
  cur_len = 0;
  if (my_strcasestr(val, "chunked")) {
    while (1) {
      while (sockreader_read_line(sockreader, &line) == APR_SUCCESS &&
             line[0] == 0);
      chunk = apr_strtoi64(line, &end, 16);
      if (chunk == 0) {
	break;
      }
      read = my_realloc(sockreader->pool, read, cur_len, cur_len + chunk + 1);
      chunk_len = 0;
      while (chunk_len < chunk) {
	chunk_cur = chunk - chunk_len;
	status = sockreader_read_block(sockreader, &read[cur_len + chunk_len], &chunk_cur);
	if (status != APR_SUCCESS && (status != APR_EOF || chunk_cur == 0)) {
	  break;
	}
	chunk_len += chunk_cur;
      }
      cur_len += chunk;
    }
  }
  else {
    return APR_ENOTIMPL;
  }

  read[cur_len] = 0;
  *buf = read;
  *len = cur_len;

  return APR_SUCCESS;
}

/**
 * Connection close reader 
 *
 * @param sockreader IN sockreader object
 * @param buf OUT content buffer
 *
 * @return APR_SUCCESS else an APR error
 */
static apr_status_t eof_reader(sockreader_t * sockreader, char **buf,
                               apr_size_t *len, const char *val) {
  apr_status_t status;
  char *read;
  apr_size_t l;

  if (my_strcasestr(val, "close")) {
    *len = 0;
    *buf = NULL;
    read = apr_palloc(sockreader->pool, BLOCK_MAX + 1);
    do {
      l = BLOCK_MAX;
      status = sockreader_read_block(sockreader, read, &l);
      *len += l;
      if (!*buf) {
        *buf = read;
        (*buf)[l] = 0;
        read = apr_palloc(sockreader->pool, BLOCK_MAX + 1);
      }
    } while (status == APR_SUCCESS);


    if (APR_STATUS_IS_EOF(status)) {
      return APR_SUCCESS;
    }
    else {
      return status;
    }
  }
  else {
    return APR_SUCCESS;
  }
}

/**
 * Encapsulated reader for ICAP messages
 *
 * @param sockreader IN sockreader object
 * @param buf OUT content buffer
 *
 * @return APR_SUCCESS else an APR error
 */
static apr_status_t encapsulated_reader(sockreader_t * sockreader, char **buf,
                                        apr_size_t *len, const char *enc_info) {
  char *read;
  char *read2;
  char *last;
  char *cur;
  char *key;
  char *val;
  char *tmp;
  apr_status_t status;
  apr_size_t size;
  apr_size_t size2;
  
  tmp = apr_pstrdup(sockreader->pool, enc_info);
  cur = apr_strtok(tmp, ",", &last);
  val = cur;
  while (cur) {
    val = cur;
    cur = apr_strtok(NULL, ", ", &last);
  }
 
  if (!val) {
    return APR_EINVAL;
  }

  key = apr_strtok(val, "=", &last);
  val = apr_strtok(NULL, "=", &last);

  if (!key || !val) {
    return APR_EINVAL;
  }
  
  size = apr_atoi64(val);

  if (size == 0) {
    return APR_SUCCESS;
  }
  
  read = apr_pcalloc(sockreader->pool, size + 1);
  sockreader_read_block(sockreader, read, &size);
  read[size] = 0;

  if (strcasecmp(key, "null-body") != 0) {
    if ((status = transfer_enc_reader(sockreader, &read2, &size2, "chunked")) 
	!= APR_SUCCESS) {
      return status;
    }
    *buf = apr_pcalloc(sockreader->pool, size + size2);
    memcpy(*buf, read, size);
    memcpy(&(*buf)[size], read2, size2);
    *len = size + size2;
  }
  else {
    *len = size;
    *buf = read;
  }

  return APR_SUCCESS;
}

/**
 * replace variables in a line
 *
 * @param worker IN thread data object
 * @param line IN line to replace in
 *
 * @return new line 
 */
static char * worker_replace_vars(worker_t * worker, char *line) {
  char *new_line;

  /* replace all parameters if any */
  new_line = replace_vars(worker->ptmp, line, worker->vars); 

  return new_line;
}

/**
 * gets values from data and store it in the variable table
 *
 * @param worker IN thread data object
 * @param regexs IN table of regular expressions to get the values from data
 * @param data IN data to match
 *
 * @return APR_SUCCESS
 */
static apr_status_t worker_match(worker_t * worker,
                                 apr_table_t * regexs, char *data) {
  int rc;
  apr_table_entry_t *e;
  apr_table_entry_t *v;
  regmatch_t regmatch[11];
  int i;
  int j;
  char *val;
  char *last;
  char *var;
  char *tmp;
  apr_table_t *vtbl;
  int n;

  if (!data) {
    return APR_SUCCESS;
  }

  vtbl = apr_table_make(worker->ptmp, 2);
  
  e = (apr_table_entry_t *) apr_table_elts(regexs)->elts;
  for (i = 0; i < apr_table_elts(regexs)->nelts; ++i) {
    /* prepare vars if multiple */
    apr_table_clear(vtbl);
    tmp = apr_pstrdup(worker->ptmp, e[i].key);
    var = apr_strtok(tmp, " ", &last);
    while (var) {
      apr_table_set(vtbl, var, var);
      var = apr_strtok(NULL, " ", &last);
    }

    n = apr_table_elts(vtbl)->nelts;
    if (n > 10) {
      worker_log(worker, LOG_ERR, "Too many vars defined for _MATCH statement, max 10 vars allowed");
      return APR_EINVAL;
    }
    
    if (e[i].val
        && (rc =
            regexec((regex_t *) e[i].val, data, n + 1, regmatch,
                    PCRE_MULTILINE)) == 0) {
      v = (apr_table_entry_t *) apr_table_elts(vtbl)->elts;
      for (j = 0; j < n; j++) {
	val =
	  apr_pstrndup(worker->pool, &data[regmatch[j + 1].rm_so],
		       regmatch[j + 1].rm_eo - regmatch[j + 1].rm_so);
	apr_table_set(worker->vars, v[j].key, val);
      }
    }
  }

  return APR_SUCCESS;
}

/**
 * checks if data contains a given pattern
 *
 * @param self IN thread data object
 * @param regexs IN table of regular expressions
 * @param data IN data to check
 *
 * @return APR_SUCCESS
 */
static apr_status_t worker_expect(worker_t * self,
                                  apr_table_t * regexs, char *data) {
  int rc;
  apr_table_entry_t *e;
  int i;

  if (!data) {
    return APR_SUCCESS;
  }

  e = (apr_table_entry_t *) apr_table_elts(regexs)->elts;
  for (i = 0; i < apr_table_elts(regexs)->nelts; ++i) {
    if (e[i].val
        && (rc =
            regexec((regex_t *) e[i].val, data, 0, NULL,
                    PCRE_MULTILINE)) == 0) {
    }
  }

  return APR_SUCCESS;
}

/**
 * Do check for if all defined expects are handled 
 *
 * @param self IN worker thread object
 * @param status IN current status
 *
 * @return current status or APR_EINVAL if there are unhandled expects
 */
static apr_status_t worker_check_expect(worker_t * self, apr_status_t status) {
  apr_table_entry_t *e;
  int i;

  e = (apr_table_entry_t *) apr_table_elts(self->match_headers)->elts;
  for (i = 0; i < apr_table_elts(self->match_headers)->nelts; ++i) {
    if (!regdidmatch((regex_t *) e[i].val)) {
      worker_log(self, LOG_ERR, "MATCH headers: Did expect %s", e[i].key);
      status = APR_EINVAL;
    }
  }
  apr_table_clear(self->match_headers);

  e = (apr_table_entry_t *) apr_table_elts(self->match_body)->elts;
  for (i = 0; i < apr_table_elts(self->match_body)->nelts; ++i) {
    if (!regdidmatch((regex_t *) e[i].val)) {
      worker_log(self, LOG_ERR, "MATCH body: Did expect %s", e[i].key);
      status = APR_EINVAL;
    }
  }
  apr_table_clear(self->match_body);

  e = (apr_table_entry_t *) apr_table_elts(self->expect_dot)->elts;
  for (i = 0; i < apr_table_elts(self->expect_dot)->nelts; ++i) {
    if (e[i].key[0] != '!' && !regdidmatch((regex_t *) e[i].val)) {
      worker_log(self, LOG_ERR, "EXPECT: Did expect \"%s\"", e[i].key);
      status = APR_EINVAL;
    }
    if (e[i].key[0] == '!' && regdidmatch((regex_t *) e[i].val)) {
      worker_log(self, LOG_ERR, "EXPECT: Did not expect \"%s\"", e[i].key);
      status = APR_EINVAL;
    }
  }
  apr_table_clear(self->expect_dot);

  return status;
}

/**
 * Check for error expects handling
 *
 * @param self IN worker thread object
 * @param status IN current status
 *
 * @return current status or APR_INVAL
 */
static apr_status_t worker_check_error(worker_t *self, apr_status_t status) {
  char *error;
  apr_table_entry_t *e;
  int i;

  if (status == APR_SUCCESS) {
    return status;
  }
  
  error = apr_psprintf(self->pool, "%s(%d)",
		     get_status_str(self->pool, status), status);
  worker_log_error(self, "%s %s", self->name, error);

  worker_expect(self, self->expect_error, error);
  worker_match(self, self->match_error, error);

  if (apr_table_elts(self->expect_error)->nelts) {
    status = APR_SUCCESS;
    e = (apr_table_entry_t *) apr_table_elts(self->expect_error)->elts;
    for (i = 0; i < apr_table_elts(self->expect_error)->nelts; ++i) {
      if (e[i].key[0] != '!' && !regdidmatch((regex_t *) e[i].val)) {
	worker_log(self, LOG_ERR, "EXPECT: Did expect error \"%s\"", e[i].key);
	status = APR_EINVAL;
	goto error;
      }
      if (e[i].key[0] == '!' && regdidmatch((regex_t *) e[i].val)) {
	worker_log(self, LOG_ERR, "EXPECT: Did not expect error \"%s\"", e[i].key);
	status = APR_EINVAL;
	goto error;
      }
    }
    apr_table_clear(self->expect_error);
  }
 
  if (apr_table_elts(self->match_error)->nelts) {
    status = APR_SUCCESS;
    e = (apr_table_entry_t *) apr_table_elts(self->match_error)->elts;
    for (i = 0; i < apr_table_elts(self->match_error)->nelts; ++i) {
      if (!regdidmatch((regex_t *) e[i].val)) {
	worker_log(self, LOG_ERR, "MATCH headers: Did expect %s", e[i].key);
	status = APR_EINVAL;
      }
    }
    apr_table_clear(self->match_error);
  }

error:
  return status;
}

/**
 * Test for unused expects and matchs
 *
 * @param self IN thread data object
 *
 * @return APR_SUCCESS or APR_EGENERAL
 */
static apr_status_t worker_test_unused(worker_t * self) {
  if (apr_table_elts(self->match_headers)->nelts) {
    worker_log(self, LOG_ERR, "There are unused MATCH headers");
    return APR_EGENERAL;
  }
  if (apr_table_elts(self->match_body)->nelts) {
    worker_log(self, LOG_ERR, "There are unused MATCH Body");
    return APR_EGENERAL;
  }
  if (apr_table_elts(self->expect_dot)->nelts) {
    worker_log(self, LOG_ERR, "There are unused EXPECT .");
    return APR_EGENERAL;
  }

  return APR_SUCCESS;
}

/**
 * Test for unused expects errors and matchs
 *
 * @param self IN thread data object
 *
 * @return APR_SUCCESS or APR_EGENERAL
 */
static apr_status_t worker_test_unused_errors(worker_t * self) {
  if (apr_table_elts(self->expect_error)->nelts) { 
    worker_log(self, LOG_ERR, "There are unused EXPECT ERROR");
    return APR_EGENERAL;
  }

  if (apr_table_elts(self->match_error)->nelts) {
    worker_log(self, LOG_ERR, "There are unused MATCH ERROR");
    return APR_EGENERAL;
  }
 
  apr_pool_clear(self->ptmp);

  return APR_SUCCESS;
}

/**
 * Close current socket
 *
 * @param self IN thread data object
 *
 * @return apr status
 */
static apr_status_t worker_conn_close(worker_t * self) {
  apr_status_t status;
#ifdef USE_SSL
  int i;
#endif

#ifdef USE_SSL
  if (self->socket->is_ssl) {
    if (self->socket->ssl) {
      for (i = 0; i < 4; i++) {
	if (SSL_shutdown(self->socket->ssl) != 0) {
	  break;
	}
      }
      SSL_free(self->socket->ssl);
      self->socket->ssl = NULL;
    }
    self->socket->is_ssl = 0;
  }
#endif
  if (self->socket && self->socket->socket) {
    if ((status = apr_socket_close(self->socket->socket)) != APR_SUCCESS) {
      return status;
    }
    self->socket->socket_state = SOCKET_CLOSED;
    self->socket->socket = NULL;
  }

  return APR_SUCCESS;
}

/**
 * Close all sockets for this worker
 *
 * @param self IN thread data object
 *
 * @return apr status
 */
static void worker_conn_close_all(worker_t *self) {
  apr_hash_index_t *hi;
  void *s;
  
  socket_t *cur = self->socket;

  for (hi = apr_hash_first(self->ptmp, self->sockets); hi; hi = apr_hash_next(hi)) {
    apr_hash_this(hi, NULL, NULL, &s);
    self->socket = s;
    worker_conn_close(self);
  }
  self->socket = cur;
  if (self->listener) {
    apr_socket_close(self->listener);
  }
}

/**
 * Receive data from socket in http style
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN aditional data
 *
 * @return an apr status
 */
static apr_status_t command_recv(command_t * self, worker_t * worker,
                                 char *data) {
  int matches;
  int expects;
  char *line;
  char *buf;
  apr_status_t status;
  sockreader_t *sockreader;
  apr_table_t *headers;
  apr_pool_t *pool;
  char *last;
  char *key;
  const char *val = "";
  apr_size_t len;
  apr_ssize_t recv_len = -1;
  int i;
  apr_exit_why_e exitwhy;
  int exitcode;
  apr_size_t inlen;

  buf = NULL;
  i = 0;
  len = 0;
  matches = 0;
  expects = 0;

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
    return status;
  }

  while (*data == ' ') ++data;

  if (apr_isdigit(data[0])) {
    recv_len = apr_atoi64(data);
  }
  else {
    recv_len = -1;
  }

  apr_pool_create(&pool, NULL);

  if ((status = sockreader_new(&sockreader, worker->socket->socket,
#ifdef USE_SSL
                               worker->socket->is_ssl ? worker->socket->ssl : NULL,
#endif
                               pool)) != APR_SUCCESS) {
    goto out_err;
  }

  headers = apr_table_make(pool, 10);

  while (sockreader_read_line(sockreader, &line) == APR_SUCCESS) {
    worker_log(worker, LOG_INFO, "<%s", line);
    fflush(stdout);
    if (line[0] == 0) {
      /* if recv len is specified use this */
      if (recv_len != -1) {
        if ((status =
             content_length_reader(sockreader, &buf, &len, val)) != APR_SUCCESS) {
	  break;
	}
      }
      /* else get transfer type */
      else if ((val = apr_table_get(headers, "Content-Length"))) {
        len = apr_atoi64(val);
        if ((status =
             content_length_reader(sockreader, &buf, &len, val)) != APR_SUCCESS) {
          break;
        }
      }
      else if ((val = apr_table_get(headers, "Transfer-Encoding"))) {
	if ((status =
	     transfer_enc_reader(sockreader, &buf, &len, val)) != APR_SUCCESS) {
	  break;
	}
      }
      else if ((val = apr_table_get(headers, "Encapsulated"))) {
        if ((status = encapsulated_reader(sockreader, &buf, &len, val)) != APR_SUCCESS) {
          break;
        }
      }
      else if ((val = apr_table_get(headers, "Connection"))) {
        if ((status = eof_reader(sockreader, &buf, &len, val)) != APR_SUCCESS) {
          break;
        }
      }
      if (buf) {
        worker_log_buf(worker, LOG_INFO, buf, "<", len);
        worker_match(worker, worker->match_body, buf);
        worker_expect(worker, worker->expect_dot, buf);
	if (worker->flags & FLAGS_PIPE_IN) {
	  worker->flags &= ~FLAGS_PIPE_IN;
	  inlen = len;
	  if ((status = apr_file_write(worker->proc.in, buf, &inlen))
	      != APR_SUCCESS) {
	    goto out_err;
	  }
	  apr_file_close(worker->proc.in);
          apr_proc_wait(&worker->proc, &exitcode, &exitwhy, APR_WAIT);
          if (exitcode != 0) {
	    status = APR_EGENERAL;
	    goto out_err;
          }
	}
      }
      break;
    }
    else {
      /* before splitting do a match */
      worker_match(worker, worker->match_headers, line);
      worker_expect(worker, worker->expect_dot, line);

      /* headers */
      key = apr_strtok(line, ":", &last);
      val = apr_strtok(NULL, ":", &last);
      if (i > 0 && worker->headers_allow) {
	if (!apr_table_get(worker->headers_allow, key)) {
	  worker_log(worker, LOG_ERR, "%s header not allowed", key);
	  status = APR_EGENERAL;
	  goto out_err;
	}
      }
      if (i > 0 && worker->headers_filter) {
	if (!apr_table_get(worker->headers_filter, key)) {
          apr_table_add(headers, key, val);
	}
      }
      else {
        apr_table_add(headers, key, val);
      }
    }
    ++i;
  }

out_err:
  status = worker_check_expect(worker, status);

  apr_pool_destroy(pool);
  return status;
}

/****
 * Scriptable commands 
 ****/

/**
 * Get socket from hash or add a new one
 *
 * @param self IN thread data object
 * @param hostname IN host name
 * @param portname IN port as ascii string
 *
 */
static void worker_get_socket(worker_t *self, const char *hostname, 
                              const char *portname, const char *tag) {
  socket_t *socket;

  socket = 
    apr_hash_get(self->sockets, apr_pstrcat(self->ptmp, hostname, portname, 
	                                    tag, NULL),
	         APR_HASH_KEY_STRING);

  if (!socket) {
    socket = apr_pcalloc(self->pool, sizeof(*socket));
    socket->socket_state = SOCKET_CLOSED;
    apr_hash_set(self->sockets, apr_pstrcat(self->pool, hostname, portname,
	                                    tag, NULL),
	         APR_HASH_KEY_STRING, socket);
  }

  self->socket = socket;
}

/**
 * Setup a connection to host
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN aditional data
 *
 * @return an apr status
 */
static apr_status_t command_REQ(command_t * self, worker_t * worker,
                                char *data) {
  apr_status_t status;
  apr_sockaddr_t *remote_addr;
  char *portname;
  char *hostname;
  char *filename;
  char *tag;
  char *last;
  int port;
  char *copy;
  int is_ssl;

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
    return status;
  }

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    return status;
  }

  COMMAND_NEED_ARG("Need hostname and port");

  hostname = apr_strtok(copy, " ", &last);
  portname = apr_strtok(NULL, " ", &last);

  if (!hostname) {
    worker_log(worker, LOG_ERR, "no host name specified");
    return APR_EGENERAL;
  }
  
  if (!portname) {
    worker_log(worker, LOG_ERR, "no portname name specified");
    return APR_EGENERAL;
  }

#ifdef USE_SSL
  is_ssl = 0;
  if (strncmp(portname, "SSL:", 4) == 0) {
    is_ssl = 1;
    worker->meth = SSLv23_client_method();
    portname += 4;
  }
#ifndef OPENSSL_NO_SSL2
  else if (strncmp(portname, "SSL2:", 4) == 0) {
    is_ssl = 1;
    worker->meth = SSLv2_client_method();
    portname += 5;
  }
#endif
  else if (strncmp(portname, "SSL3:", 4) == 0) {
    is_ssl = 1;
    worker->meth = SSLv3_client_method();
    portname += 5;
  }
  else if (strncmp(portname, "TLS1:", 4) == 0) {
    is_ssl = 1;
    worker->meth = TLSv1_client_method();
    portname += 5;
  }
#endif

  portname = apr_strtok(portname, ":", &tag);
  port = apr_atoi64(portname);

  worker_get_socket(worker, hostname, portname, tag);
  
  worker->socket->is_ssl = is_ssl;

  if (worker->socket->socket_state == SOCKET_CLOSED) {
#ifdef USE_SSL
    if (worker->socket->is_ssl) {
      if (!worker->ssl_ctx && !(worker->ssl_ctx = SSL_CTX_new(worker->meth))) {
        worker_log(worker, LOG_ERR, "Could not initialize SSL Context.");
      }
      SSL_CTX_set_options(worker->ssl_ctx, SSL_OP_ALL);
      SSL_CTX_set_options(worker->ssl_ctx, SSL_OP_SINGLE_DH_USE);
      /* get cert file if any is specified */
      filename = apr_strtok(NULL, " ", &last);
      if (filename && SSL_CTX_use_certificate_file(worker->ssl_ctx, filename, 
				       SSL_FILETYPE_PEM) <= 0) { 
	worker_log(worker, LOG_ERR, "Could not load RSA certifacte \"%s\"", 
	           filename);
        return APR_ECONNABORTED;
      }

      /* get key file if any is specified */
      filename = apr_strtok(NULL, " ", &last);
      if (filename && SSL_CTX_use_PrivateKey_file(worker->ssl_ctx, filename, 
	                              SSL_FILETYPE_PEM) <= 0) {
	worker_log(worker, LOG_ERR, "Could not load RSA private key \"%s\"", 
	           filename);
	return APR_EINVAL;
      }

    }
#endif

    if ((status = apr_socket_create(&worker->socket->socket, APR_INET, 
	                            SOCK_STREAM, APR_PROTO_TCP,
                                    worker->pool)) != APR_SUCCESS) {
      worker->socket->socket = NULL;
      return status;
    }

    if ((status =
         apr_socket_opt_set(worker->socket->socket, APR_TCP_NODELAY,
                            1)) != APR_SUCCESS) {
      return status;
    }

    if ((status =
         apr_socket_timeout_set(worker->socket->socket, worker->socktmo)) != APR_SUCCESS) {
      return status;
    }

#ifdef USE_SSL
    if (worker->socket->is_ssl) {
      BIO *bio;
      apr_os_sock_t fd;

      if ((worker->socket->ssl = SSL_new(worker->ssl_ctx)) == NULL) {
        worker_log(worker, LOG_ERR, "SSL_new failed.");
        status = APR_ECONNREFUSED;
      }
      SSL_set_ssl_method(worker->socket->ssl, worker->meth);
      ssl_rand_seed();
      apr_os_sock_get(&fd, worker->socket->socket);
      bio = BIO_new_socket(fd, BIO_NOCLOSE);
      SSL_set_bio(worker->socket->ssl, bio, bio);
      SSL_set_connect_state(worker->socket->ssl);

      if (worker->log_mode >= LOG_DEBUG) {
        BIO_set_callback(bio, ssl_print_cb);
        BIO_set_callback_arg(bio, (void *) worker->bio_err);
      }
    }
#endif

    if ((status =
         apr_sockaddr_info_get(&remote_addr, hostname, AF_UNSPEC, port,
                               APR_IPV4_ADDR_OK, worker->pool))
        != APR_SUCCESS) {
      return status;
    }

    if ((status =
         apr_socket_connect(worker->socket->socket, remote_addr)) 
	!= APR_SUCCESS) {
      return status;
    }

    if ((status =
         apr_socket_opt_set(worker->socket->socket, APR_SO_KEEPALIVE,
                            1)) != APR_SUCCESS) {
      return status;
    }

    worker->socket->socket_state = SOCKET_CONNECTED;
#ifdef USE_SSL
    if (worker->socket->is_ssl) {
      if ((status = worker_ssl_handshake(worker)) != APR_SUCCESS) {
	return status;
      }
    }
#endif
  }

  /* reset the matcher tables */
  apr_table_clear(worker->match_headers);
  apr_table_clear(worker->match_body);
  apr_table_clear(worker->expect_dot);
  apr_table_clear(worker->expect_error);
  apr_table_clear(worker->match_error);

  return APR_SUCCESS;
}

/**
 * Setup a connection to host
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN unused 
 *
 * @return an apr status
 */
static apr_status_t command_RES(command_t * self, worker_t * worker,
                                char *data) {
  apr_status_t status;

  COMMAND_NO_ARG;

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
    return status;
  }

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    return status;
  }

  worker_get_socket(worker, "Default", "0", NULL);
  worker->socket->is_ssl = worker->is_ssl;

  if (worker->socket->socket_state == SOCKET_CLOSED) {
    worker_log(worker, LOG_DEBUG, "--- accept");
    if (!worker->listener) {
      worker_log_error(worker, "Server down");
      return APR_EGENERAL;
    }

    if ((status =
         apr_socket_accept(&worker->socket->socket, worker->listener,
                           worker->pool)) != APR_SUCCESS) {
      worker->socket->socket = NULL;
      return status;
    }
    if ((status =
           apr_socket_timeout_set(worker->socket->socket, worker->socktmo)) 
	!= APR_SUCCESS) {
      return status;
    }
#ifdef USE_SSL
    if ((status = worker_ssl_accept(worker)) != APR_SUCCESS) {
      return status;
    }
#endif
    worker->socket->socket_state = SOCKET_CONNECTED;
  }

  apr_table_clear(worker->match_headers);
  apr_table_clear(worker->match_body);
  apr_table_clear(worker->expect_dot);
  apr_table_clear(worker->expect_error);
  apr_table_clear(worker->match_error);

  return APR_SUCCESS;
}

/**
 * Wait for data (same as command_recv)
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN unused 
 *
 * @return an apr status
 */
static apr_status_t command_WAIT(command_t * self, worker_t * worker,
                                 char *data) {
  char *copy;

  COMMAND_OPTIONAL_ARG;

  return command_recv(self, worker, copy);
}

/**
 * Sleep for a given time (ms)
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN time to wait in ms
 *
 * @return an apr status
 */
static apr_status_t command_SLEEP(command_t * self, worker_t * worker,
                                  char *data) {
  apr_status_t status;
  char *copy;

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
    return status;
  }

  COMMAND_NEED_ARG("Time not specified");
 
  apr_sleep(apr_atoi64(copy) * 1000);
  return APR_SUCCESS;
}

/**
 * Define an expect
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN "%s %s" type match 
 *
 * @return an apr status
 */
static apr_status_t command_EXPECT(command_t * self, worker_t * worker,
                                   char *data) {
  char *last;
  char *type;
  char *match;
  regex_t *compiled;
  const char *err;
  int off;
  char *copy;
  char *interm;

  COMMAND_NEED_ARG("Type and regex not specified");

  type = apr_strtok(copy, " ", &last);
  
  match = unescape(last, &last);

  if (!type) {
    worker_log(worker, LOG_ERR, "Type not specified");
    return APR_EGENERAL;
  }
  
  if (!match) {
    worker_log(worker, LOG_ERR, "Regex not specified");
    return APR_EGENERAL;
  }

  interm = apr_pstrdup(worker->ptmp, match);

  if (interm[0] == '!') {
    ++interm;
  }

  if (!(compiled = pregcomp(worker->ptmp, interm, &err, &off))) {
    worker_log(worker, LOG_ERR, "EXPECT regcomp failed: \"%s\"", last);
    return APR_EINVAL;
  }

  if (strcmp(type, ".") == 0) {
    apr_table_addn(worker->expect_dot, match, (char *) compiled);
  }
  else if (strcmp(type, "ERROR") == 0) {
    apr_table_addn(worker->expect_error, match, (char *) compiled);
  }
  else {
    worker_log(worker, LOG_ERR, "EXPECT type \"%s\" unknown", type);
    return APR_EINVAL;
  }

  return APR_SUCCESS;
}

/**
 * Close socket
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return an apr status
 */
static apr_status_t command_CLOSE(command_t * self, worker_t * worker,
                                  char *data) {
  apr_status_t status;

  COMMAND_NO_ARG;

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
    worker_conn_close(worker);
    return status;
  }

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    worker_conn_close(worker);
    return status;
  }

  if ((status = worker_conn_close(worker)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * Specify a timeout for socket operations (ms) 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN time in ms 
 *
 * @return an apr status
 */
static apr_status_t command_TIMEOUT(command_t * self, worker_t * worker,
                                    char *data) {
  apr_time_t tmo;
  char *copy;

  COMMAND_NEED_ARG("Time not specified");

  tmo = apr_atoi64(copy);
  worker->socktmo = tmo * 1000;

  return APR_SUCCESS;
}

/**
 * Define an expect
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN "%s %s %s" type match variable
 *
 * @return an apr status
 */
static apr_status_t command_MATCH(command_t * self, worker_t * worker,
                                  char *data) {
  char *last;
  char *type;
  char *match;
  char *vars;
  regex_t *compiled;
  const char *err;
  int off;
  char *copy;

  COMMAND_NEED_ARG("Type, regex and variable not specified");

  type = apr_strtok(copy, " ", &last);
  
  match = unescape(last, &last);
  
  vars = apr_strtok(NULL, "", &last);

  if (!type) {
    worker_log(worker, LOG_ERR, "Type not specified");
    return APR_EGENERAL;
  }

  if (!match) {
    worker_log(worker, LOG_ERR, "Regex not specified");
    return APR_EGENERAL;
  }

  if (!vars) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }

  if (vars) {
    ++vars;
    //apr_collapse_spaces(vars, vars);
  }

  if (!vars) {
    return APR_EINVAL;
  }

  if (!(compiled = pregcomp(worker->ptmp, match, &err, &off))) {
    worker_log(worker, LOG_ERR, "MATCH regcomp failed: %s", last);
    return APR_EINVAL;
  }
  if (strcasecmp(type, "Headers") == 0) {
    apr_table_addn(worker->match_headers, vars, (char *) compiled);
  }
  else if (strcasecmp(type, "Body") == 0) {
    apr_table_addn(worker->match_body, vars, (char *) compiled);
  }
  else if (strcasecmp(type, "ERROR") == 0) {
    apr_table_addn(worker->match_error, vars, (char *) compiled);
  }
  else {
    worker_log(worker, LOG_ERR, "Match type %s do not exist", type);
    return APR_ENOENT;
  }

  return APR_SUCCESS;
}

/**
 * set command
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN key=value 
 *
 * @return an apr status
 */
static apr_status_t command_SET(command_t * self, worker_t * worker,
                                char *data) {
  char *vars_last;
  const char *vars_key;
  const char *vars_val;
  char *copy;

  COMMAND_NEED_ARG("Variable and value not specified");
  
  vars_key = apr_strtok(copy, "=", &vars_last);
  vars_val = apr_strtok(NULL, "", &vars_last);

  if (!vars_key) {
    worker_log(worker, LOG_ERR, "Key not specified");
    return APR_EGENERAL;
  }

  if (!vars_val) {
    worker_log(worker, LOG_ERR, "Value not specified");
    return APR_EGENERAL;
  }
  
  apr_table_set(worker->vars, vars_key, vars_val);

  return APR_SUCCESS;
}

/**
 * If statement (not implemented yet)
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN expression 
 *
 * @return an apr status
 */
static apr_status_t command_IF(command_t * self, worker_t * worker,
                               char *data) {
  char *copy;
  char *left;
  char *right;
  char *middle;
  char *last;
  const char *err;
  int off;
  int not;
  regex_t *compiled;
  apr_status_t status;
  worker_t *body;

 
  COMMAND_NEED_ARG("Need left operant right parameters");
  
  ++copy;
  left = apr_strtok(copy, "\"", &last);
  middle = apr_strtok(NULL, " ", &last);
  right = apr_strtok(NULL, "\"", &last);
 
  if (!left || !middle || !right) {
    worker_log(worker, LOG_ERR, "%s: Syntax error '%s'", self->name, data);
    return APR_EGENERAL;
  }
  
  if (right[0] == '!') {
    not = 1;
    ++right;
  }
  else {
    not = 0;
  }
 
  if (strcmp(middle, "MATCH") == 0) {
    if (!(compiled = pregcomp(worker->ptmp, right, &err, &off))) {
      worker_log(worker, LOG_ERR, "IF MATCH regcomp failed: %s", right);
      return APR_EINVAL;
    }
  }
  else {
    return APR_ENOTIMPL;
  }

  if ((status = worker_body(&body, worker, "IF")) != APR_SUCCESS) {
    return status;
  }

  if ((regexec(compiled, left, 0, NULL, PCRE_MULTILINE) == 0 && !not) ||
      (regexec(compiled, left, 0, NULL, PCRE_MULTILINE) != 0 && not)) {
    status = worker_interpret(body, worker);
  }

  worker_log(worker, LOG_INFO, "_END IF");

  worker_body_end(body, worker);
 
  return status;
}

/**
 * Send data 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN data to send
 *
 * @return an apr status
 */
static apr_status_t command_DATA(command_t * self, worker_t * worker,
                                 char *data) {
  char *copy;

  if (!worker->socket || !worker->socket->socket) {
    return APR_ENOSOCKET;
  }
    
  copy = apr_pstrdup(worker->ptmp, data); 
  copy = worker_replace_vars(worker, copy);
  worker_log(worker, LOG_INFO, "%s%s", self->name, copy); 

  if (strncasecmp(copy, "Content-Length: AUTO", 20) == 0) {
    apr_table_add(worker->cache, "Content-Length", "Content-Length");
  }
  else {
    apr_table_addn(worker->cache, "TRUE", copy);
  }

  return APR_SUCCESS;
}

/**
 * Flush data 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return an apr status
 */
static apr_status_t command_FLUSH(command_t * self, worker_t * worker,
                                  char *data) {
  apr_status_t status;

  COMMAND_NO_ARG;

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * Chunk info 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return an apr status
 */
static apr_status_t command_CHUNK(command_t * self, worker_t * worker,
                                  char *data) {
  apr_status_t status;

  COMMAND_NO_ARG;

  apr_table_add(worker->cache, "CHUNKED", "CHUNKED");

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * Execute an external program 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN external program call with arguments 
 *
 * @return an apr status
 */
static apr_status_t command_EXEC(command_t * self, worker_t * worker,
                                 char *data) {
  char *copy;
  apr_status_t status;
  apr_procattr_t *attr;
  apr_table_t *table;
  apr_table_entry_t *e;
  const char *progname;
  const char **args;
  apr_exit_why_e exitwhy;
  int exitcode;
  char *last;
  char *val;
  int i;
  char *buf;
  apr_size_t len;
  int flags;

  COMMAND_NEED_ARG("Need a shell command");

  flags = worker->flags;
  worker->flags &= ~FLAGS_PIPE;
  worker->flags &= ~FLAGS_CHUNKED;
  worker->flags &= ~FLAGS_PIPE_IN;
  if (copy[0] == '|') {
    ++copy;
    worker->flags |= FLAGS_PIPE_IN;
  }
  
  table = apr_table_make(worker->ptmp, 5);
  progname = apr_strtok(copy, " ", &last);

  if (!progname) {
    worker_log(worker, LOG_ERR, "No program name specified");
    return APR_EGENERAL;
  }
  
  apr_table_addn(table, progname, "TRUE");

  while ((val = apr_strtok(NULL, " ", &last))) {
    apr_table_addn(table, val, "TRUE");
  }

  args = apr_pcalloc(worker->ptmp,
                     (apr_table_elts(table)->nelts + 1) * sizeof(const char *));

  e = (apr_table_entry_t *) apr_table_elts(table)->elts;
  for (i = 0; i < apr_table_elts(table)->nelts; i++) {
    args[i] = e[i].key;
  }
  args[i] = NULL;

  if ((status = apr_procattr_create(&attr, worker->ptmp)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_procattr_cmdtype_set(attr, APR_SHELLCMD)) != APR_SUCCESS) {
    return status;
  }

  if (flags & FLAGS_PIPE) {
    if ((status = apr_procattr_io_set(attr,  APR_NO_PIPE, APR_FULL_BLOCK,
				      APR_NO_PIPE))
	!= APR_SUCCESS) {
      return status;
    }
  }

  if (worker->flags & FLAGS_PIPE_IN) {
    if ((status = apr_procattr_io_set(attr, APR_FULL_BLOCK, APR_NO_PIPE,
				      APR_NO_PIPE))
	!= APR_SUCCESS) {
      return status;
    }
  }

  if ((status = apr_proc_create(&worker->proc, progname, args, NULL, attr,
                                worker->ptmp)) != APR_SUCCESS) {
    return status;
  }

  if (flags & FLAGS_PIPE) {
    while (1) {
      if (flags & FLAGS_CHUNKED) {
	len = worker->chunksize;
      }
      else {
	len = BLOCK_MAX;
      }
      buf = apr_pcalloc(worker->ptmp, len + 1);
      if ((status = apr_file_read(worker->proc.out, buf, &len)) != APR_SUCCESS) {
	break;
      }
      buf[len] = 0;
      apr_table_addn(worker->cache, 
	             apr_psprintf(worker->ptmp, "NOCRLF:%d", len), buf);
      if (flags & FLAGS_CHUNKED) {
	worker_log(worker, LOG_DEBUG, "--- chunk size: %d", len);
        apr_table_add(worker->cache, "CHUNKED", "CHUNKED");
	if ((status = worker_flush(worker)) != APR_SUCCESS) {
	  return status;
	}
      }
    }
  }
  
  if (!(worker->flags & FLAGS_PIPE_IN)) {
    apr_proc_wait(&worker->proc, &exitcode, &exitwhy, APR_WAIT);

    if (worker->flags & FLAGS_PIPE) {
      apr_file_close(worker->proc.out);
    }

    if (exitcode != 0) {
      return APR_EGENERAL;
    }
  }

  return APR_SUCCESS;
}

/**
 * Declare a pipe
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN not used
 *
 * @return an apr status
 */
static apr_status_t command_PIPE(command_t * self, worker_t * worker,
                                 char *data) {
  char *copy;
  char *last;
  char *add;
  char *val;

  COMMAND_OPTIONAL_ARG;

  add = apr_strtok(copy, " ", &last);
  if (add) {
    val = apr_strtok(NULL, " ", &last);
  }
  else {
    val = NULL;
  }
  
  worker_log(worker, LOG_DEBUG, "additional: %s, value: %s", add, val);
  
  if (add && strncasecmp(add, "chunked", 7) == 0) {
    worker->chunksize = val ? apr_atoi64(val) : BLOCK_MAX;
    worker->flags |= FLAGS_CHUNKED;
  }
  
  worker->flags |= FLAGS_PIPE;

  return APR_SUCCESS;
}

/**
 * Send data without a CRLF
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN data to send
 *
 * @return an apr status
 */
static apr_status_t command_NOCRLF(command_t * self, worker_t * worker,
                                   char *data) {
  char *copy;

  copy = apr_pstrdup(worker->ptmp, data); 
  copy = worker_replace_vars(worker, copy);
  worker_log(worker, LOG_INFO, "%s%s", self->name, copy); 

  apr_table_addn(worker->cache, "NOCRLF", copy);

  return APR_SUCCESS;
}

/**
 * Send data without a CRLF
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN data to send
 *
 * @return an apr status
 */
static apr_status_t command_SOCKSTATE(command_t * self, worker_t * worker,
                                      char *data) {
  char *copy;

  COMMAND_NEED_ARG("Need a variable name");

  if (worker_sockstate(worker) == APR_SUCCESS) {
    apr_table_set(worker->vars, copy, "CONNECTED");
  }
  else {
    apr_table_set(worker->vars, copy, "CLOSED");
  }

  return APR_SUCCESS;
}

/**
 * Ignores errors specified.
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN regex 
 *
 * @return an apr status
 */
static apr_status_t command_IGNORE_ERR(command_t * self, worker_t * worker,
                                       char *data) {
  char *copy;

  COMMAND_NEED_ARG("Need a regex");

  /* TODO: only .* is implemented */
  worker->flags |= FLAGS_IGNORE_ERRORS;
  
  return APR_SUCCESS;
}

/**
 * Exit program with OK|FAILED 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN OK|FAILED|<empty> 
 *
 * @return never reached
 */
static apr_status_t command_EXIT(command_t * self, worker_t * worker, 
                                 char *data) {
  char *copy;

  COMMAND_OPTIONAL_ARG;

  if (strcmp(copy, "OK") == 0) {
    worker_destroy(worker);
    exit(0);
  }
  else {
    worker_set_global_error(worker);
    worker_destroy(worker);
    exit(-1);
  }

  /* just make the compiler happy, never reach this point */
  return APR_SUCCESS;
}

/**
 * HEADER command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN header name (spaces are possible) 
 *
 * @return APR_SUCCESS
 */
static apr_status_t command_HEADER(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *method;
  char *header;
  char *last;

  COMMAND_NEED_ARG("Need method ALLOW or FILTER and a header name");

  method = apr_strtok(copy, " ", &last);
  header = apr_strtok(NULL, " ", &last);
  
  if (strcasecmp(method, "ALLOW") == 0) {
    if (!worker->headers_allow) {
      worker->headers_allow = apr_table_make(worker->pool, 10);
    }
    apr_table_add(worker->headers_allow, header, method);
  }
  else if (strcasecmp(method, "FILTER") == 0) {
    if (!worker->headers_filter) {
      worker->headers_filter = apr_table_make(worker->pool, 5);
    }
    apr_table_add(worker->headers_filter, header, method);
  }
  else {
    return APR_ENOTIMPL;
  }

  return APR_SUCCESS;
}

/**
 * LOOP command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN header name (spaces are possible) 
 *
 * @return APR_SUCCESS
 */
static apr_status_t command_LOOP(command_t *self, worker_t *worker, char *data) {
  apr_status_t status;
  worker_t *body;
  char *copy;
  int loop;
  int i;

  COMMAND_NEED_ARG("Need a number"); 
 
  if (strncmp(copy, "FOREVER", 7) == 0) {
    loop = -1;
  }
  else {
    loop = apr_atoi64(copy);
  }
  
  /* create a new worker body */
  if ((status = worker_body(&body, worker, "LOOP")) != APR_SUCCESS) {
    return status;
  }
  
  /* loop */
  for (i = 0; loop == -1 || i < loop; i++) {
    /* interpret */
    if ((status = worker_interpret(body, worker)) != APR_SUCCESS) {
      break;
    }
  }
  
  worker_log(worker, LOG_INFO, "_END LOOP");
  
  worker_body_end(body, worker);
  
  return status;
}

/**
 * RAND command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN header name (spaces are possible) 
 *
 * @return APR_SUCCESS
 */
static apr_status_t command_RAND(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *val;
  char *last;
  int start;
  int end;
  int result;

  COMMAND_NEED_ARG("Need a start and end number and a variable"); 
  
  val = apr_strtok(copy, " ", &last);
  start = apr_atoi64(val);
  val = apr_strtok(NULL, " ", &last);
  end = apr_atoi64(val);
  val = apr_strtok(NULL, " ", &last);

  if (val == NULL) {
    worker_log(worker, LOG_ERR, "No variable name specified");
    return APR_EINVAL;
  }
  
  result = start + (rand() % (end - start)); 

  apr_table_set(worker->vars, val, apr_itoa(worker->ptmp, result));

  return APR_SUCCESS;
}

/**
 * DEBUG command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN string to print on stderr
 *
 * @return APR_SUCCESS
 */
static apr_status_t command_DEBUG(command_t *self, worker_t *worker, char *data) {
  char *copy;
  
  COMMAND_OPTIONAL_ARG;

  worker_log(worker, LOG_ERR, "%s", copy);

  return APR_SUCCESS;
}

/**
 * Setup listener
 *
 * @param worker IN thread data object
 *
 * @return APR_SUCCESS
 */
static apr_status_t worker_listener_up(worker_t *worker) {
  apr_sockaddr_t *local_addr;

  apr_status_t status = APR_SUCCESS;

  worker_get_socket(worker, "Default", "0", NULL);
  
  if (worker->listener) {
    worker_log_error(worker, "Server allready up");
    return APR_EGENERAL;
  }
  
  if ((status = apr_sockaddr_info_get(&local_addr, APR_ANYADDR, APR_UNSPEC,
                                      worker->listener_port, APR_IPV4_ADDR_OK, worker->pool))
      != APR_SUCCESS) {
    goto error;
  }

  if ((status = apr_socket_create(&worker->listener, APR_INET, SOCK_STREAM,
                                  APR_PROTO_TCP, worker->pool)) != APR_SUCCESS)
  {
    worker->listener = NULL;
    goto error;
  }

  status = apr_socket_opt_set(worker->listener, APR_SO_REUSEADDR, 1);
  if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
    goto error;
  }
  
  worker_log(worker, LOG_DEBUG, "--- bind");
  if ((status = apr_socket_bind(worker->listener, local_addr)) != APR_SUCCESS) {
    goto error;
  }

  worker_log(worker, LOG_DEBUG, "--- listen");
  if ((status = apr_socket_listen(worker->listener, LISTENBACKLOG_DEFAULT)) != APR_SUCCESS) {
    goto error;
  }

  worker->socket->socket_state = SOCKET_CLOSED;

error:
  return status;
}

/**
 * UP command bind a listener socket
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
static apr_status_t command_UP(command_t *self, worker_t *worker, char *data) {
  COMMAND_NO_ARG;

  return worker_listener_up(worker);
}

/**
 * DOWN command shuts down listener
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
static apr_status_t command_DOWN(command_t *self, worker_t *worker, char *data) {
  apr_status_t status;

  COMMAND_NO_ARG;

  if (!worker->listener) {
    worker_log_error(worker, "Server allready down", self->name);
    return APR_EGENERAL;
  }
  
  if ((status = apr_socket_close(worker->listener)) != APR_SUCCESS) {
    return status;
  }
  worker->listener = NULL;
  return status;
}

/**
 * TIME command stores time in a variable [ms]
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN variable name 
 *
 * @return APR_SUCCESS
 */
static apr_status_t command_TIME(command_t *self, worker_t *worker, char *data) {
  char *copy;

  COMMAND_NEED_ARG("Need a variable name to store time");
  
  apr_table_set(worker->vars, copy, apr_psprintf(worker->ptmp, "%llu", apr_time_as_msec(apr_time_now())));

  return APR_SUCCESS;
}

/**
 * CALL command calls a defined block
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN name of calling block 
 *
 * @return block status or APR_EINVAL 
 */
static apr_status_t command_CALL(command_t *self, worker_t *worker, char *data) {
  apr_status_t status;
  apr_status_t mutex_status;
  char *copy;
  char *block_name;
  char *last;
  worker_t *block, *call;
  apr_table_t *lines;
  int cmd;
  apr_pool_t *call_pool;

  COMMAND_NEED_ARG("Need a block name: <block> (<name> => <value>)*");

  block_name = apr_strtok(copy, " ", &last);

  /* CR BEGIN */
  if ((mutex_status = apr_thread_mutex_lock(worker->sync_mutex)) != APR_SUCCESS) {
    return mutex_status;
  }
  if (!(block = apr_hash_get(worker->blocks, block_name, APR_HASH_KEY_STRING))) {
    worker_log_error(worker, "Could not find block %s", block_name);
    /* CR END */
    if ((mutex_status = apr_thread_mutex_unlock(worker->sync_mutex)) != APR_SUCCESS) {
      return mutex_status;
    }
    return APR_EINVAL;
  }
  else { 
    apr_pool_create(&call_pool, worker->ptmp);
    lines = my_table_deep_copy(call_pool, block->lines);
    if ((mutex_status = apr_thread_mutex_unlock(worker->sync_mutex)) != APR_SUCCESS) {
      return mutex_status;
    }
    /* CR END */
    call = apr_pcalloc(call_pool, sizeof(worker_t));
    memcpy(call, worker, sizeof(worker_t));
    /* lines in block */
    call->lines = lines;
    status = worker_interpret(call, worker);
    cmd = worker->cmd;
    lines = worker->lines;
    memcpy(worker, call, sizeof(worker_t));
    worker->lines = lines;
    worker->cmd = cmd;

    return status;
  }
}

/**
 * LOG_LEVEL command sets log level 
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN number 0-4 
 *
 * @return APR_SUCCESS
 */
static apr_status_t command_LOG_LEVEL(command_t *self, worker_t *worker, char *data) {
  char *copy;

  COMMAND_NEED_ARG("Need a number between 0 and 4");

  worker->log_mode = apr_atoi64(copy);

  return APR_SUCCESS;
}

/**
 * SYNC command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
static apr_status_t command_SYNC(command_t *self, worker_t *worker, char *data) {
  apr_time_t sec;
  apr_time_t nxt_sec;
  apr_time_t now;

  COMMAND_NO_ARG;

  /* get current time */
  now = apr_time_now();
  /* get next second */
  sec = apr_time_sec(now) + 1;
  /* next second in us */
  nxt_sec = apr_time_from_sec(sec);
  /* sleep until next sec */
  apr_sleep(nxt_sec - now);
  
  return APR_SUCCESS;
}

/**
 * RECV command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
static apr_status_t command_RECV(command_t *self, worker_t *worker, char *data) {
  char *copy;
  apr_pool_t *pool;
  apr_status_t status;
  apr_size_t recv_len;
  sockreader_t *sockreader;
  char *buf;
  char *last;
  char *val;

  COMMAND_NEED_ARG("Need a number or POLL");

  /* get first value, can be either POLL or a number */
  val = apr_strtok(copy, " ", &last);
  if (strcmp(val, "POLL") == 0) {
    /* recv_len to max and timeout to min */
    recv_len = BLOCK_MAX;
    /* set timout to specified socket tmo */
    if ((status =
           apr_socket_timeout_set(worker->socket->socket, worker->socktmo)) 
	!= APR_SUCCESS) {
      return status;
    }
  }
  else {
    /* must be a number */
    recv_len = apr_atoi64(val);
  }

  apr_pool_create(&pool, NULL);

  if ((status = sockreader_new(&sockreader, worker->socket->socket,
#ifdef USE_SSL
                               worker->socket->is_ssl ? worker->socket->ssl : NULL,
#endif
                               pool)) != APR_SUCCESS) {
    goto out_err;
  }

  if ((status = content_length_reader(sockreader, &buf, &recv_len, "")) != APR_SUCCESS) {
    goto out_err;
  }

  if (buf) {
    worker_log_buf(worker, LOG_INFO, buf, "<", recv_len);
    worker_match(worker, worker->match_body, buf);
    worker_expect(worker, worker->expect_dot, buf);
  }

out_err:
  status = worker_check_expect(worker, status);
  apr_pool_destroy(pool);

  return status;
}

/**
 * OP command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN left op right var
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t command_OP(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *last;
  char *left;
  char *op;
  char *right;
  char *var;
  int ileft;
  int iright;
  int result;

  COMMAND_NEED_ARG("<left> ADD|SUB|MUL|DIV <right> <variable> expected");

  /* split into left, op, right, var */
  left = apr_strtok(copy, " ", &last);
  op = apr_strtok(NULL, " ", &last);
  right = apr_strtok(NULL, " ", &last);
  var = apr_strtok(NULL, " ", &last);

  /* do checks */
  if (!left || !op || !right || !var) {
    worker_log(worker, LOG_ERR, "<left> ADD|SUB|MUL|DIV <right> <variable> expected", copy);
    return APR_EINVAL;
  }

  /* get integer value */
  ileft = apr_atoi64(left);
  iright = apr_atoi64(right);

  /* do operation */
  if (strcasecmp(op, "ADD") == 0) {
    result = ileft + iright;
  }
  else if (strcasecmp(op, "SUB") == 0) {
    result = ileft - iright;
  }
  else if (strcasecmp(op, "MUL") == 0) {
    result = ileft * iright;
  }
  else if (strcasecmp(op, "DIV") == 0) {
    if (iright == 0) {
      worker_log(worker, LOG_ERR, "Division by zero");
      return APR_EINVAL;
    }
    result = ileft / iright;
  }
  else {
    worker_log(worker, LOG_ERR, "Unknown operant %s", op);
    return APR_ENOTIMPL;
  }

  /* store it do var */
  apr_table_set(worker->vars, var, apr_psprintf(worker->ptmp, "%d", result));
  
  return APR_SUCCESS;
}

/**
 * WHICH command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN varname
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t command_WHICH(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *result;

  COMMAND_NEED_ARG("<variable> expected");
 
  result  = apr_psprintf(worker->ptmp, "%d", worker->which);
  apr_table_set(worker->vars, copy, result);
  
  return APR_SUCCESS;
}

/**
 * CERT command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN cert key
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t command_CERT(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *last;
  char *cert;
  char *key;

  COMMAND_NEED_ARG("<cert-file> <key-file>");
  
  cert = apr_strtok(copy, " ", &last);
  key = apr_strtok(NULL, " ", &last);
  worker_ssl_ctx(worker, cert, key);
  
  return APR_SUCCESS;
}

/**
 * Object bufreader 
 */

/**
 * Fill up buffer with data from file 
 *
 * @param self IN bufreader object
 *
 * @return an apr status
 */
static apr_status_t bufreader_fill(bufreader_t * self) {
  self->i = 0;
  self->len = BLOCK_MAX;

  return apr_file_read(self->fp, self->buf, &self->len);
}

/**
 * read line from file 
 *
 * @param self IN bufreader object
 * @param line OUT read line
 *
 * @return an apr status
 */
static apr_status_t bufreader_read_line(bufreader_t * self, char **line) {
  apr_status_t status;
  char c;
  apr_size_t i;
  apr_size_t size;
  char *new_size_line;

  *line = NULL;
  size = 0;

  i = 0;
  c = 0;
  while (c != '\r' && c != '\n' && apr_file_eof(self->fp) != APR_EOF) {
    if (i >= size) {
      size += 512;
      new_size_line = apr_palloc(self->pool, size + 1);
      if (*line != NULL) {
        memcpy(new_size_line, *line, size - 512);
      }
      *line = new_size_line;
    }
    if (self->i >= self->len) {
      if ((status = bufreader_fill(self)) != APR_SUCCESS) {
        return status;
      }
    }

    c = self->buf[self->i];
    (*line)[i] = c;
    self->i++;
    i++;
  }
  if (i) {
    (*line)[i - 1] = 0;
  }
  else {
    (*line)[i] = 0;
  }
  while (**line == ' ') {
    ++*line;
  }
  if (apr_file_eof(self->fp) == APR_EOF) {
    return APR_EOF;
  }
  else {
    return APR_SUCCESS;
  }
}

/**
 * New bufreader object 
 *
 * @param self OUT bufreader object
 * @param fp IN an open file to read
 * @param p IN pool
 *
 * @return an apr status
 */
static apr_status_t bufreader_new(bufreader_t ** bufreader, apr_file_t * fp,
                                  apr_pool_t * p) {
  apr_status_t status;

  *bufreader = apr_pcalloc(p, sizeof(bufreader_t));

  (*bufreader)->fp = fp;
  (*bufreader)->pool = p;

  if ((status = bufreader_fill((*bufreader))) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * Object thread data
 */

/**
 * New thread data object 
 *
 * @param self OUT thread data object
 * @param log_mode IN log mode  
 *
 * @return an apr status
 */
static apr_status_t worker_new(worker_t ** self, char *additional,
                               int log_mode, char *prefix,
                               apr_thread_cond_t * sync_cond,
                               apr_thread_mutex_t * sync_mutex,
			       apr_time_t socktmo, apr_hash_t *blocks) {
  apr_pool_t *p;
  apr_pool_t *ptmp;

  apr_pool_create(&p, NULL);
  (*self) = apr_pcalloc(p, sizeof(worker_t));
  (*self)->heartbeat = p;
  apr_pool_create(&p, (*self)->heartbeat);
  (*self)->pool = p;
  apr_pool_create(&ptmp, p);
  (*self)->ptmp = ptmp;
  (*self)->filename = apr_pstrdup(p, "<none>");
  (*self)->socktmo = socktmo;
  (*self)->prefix = apr_pstrdup(p, prefix);
  (*self)->additional = apr_pstrdup(p, additional);
  (*self)->sync_cond = sync_cond;
  (*self)->sync_mutex = sync_mutex;
  (*self)->lines = apr_table_make(p, 20);
  (*self)->cache = apr_table_make(p, 20);
  (*self)->expect_dot = apr_table_make(p, 2);
  (*self)->expect_error = apr_table_make(p, 2);
  (*self)->match_headers = apr_table_make(p, 2);
  (*self)->match_body = apr_table_make(p, 2);
  (*self)->match_error = apr_table_make(p, 2);
  (*self)->sockets = apr_hash_make(p);
  (*self)->headers_allow = NULL;
  (*self)->headers_filter = NULL;
  (*self)->vars = apr_table_make(p, 4);
  (*self)->blocks = blocks;
  (*self)->log_mode = log_mode;
#ifdef USE_SSL
  (*self)->bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
  (*self)->bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
#endif

  worker_log(*self, LOG_DEBUG, "worker_new: pool: %p, ptmp: %p\n", (*self)->pool, (*self)->ptmp);
  return APR_SUCCESS;
}

/**
 * Clone thread data object 
 *
 * @param self OUT thread data object
 * @param orig IN thread data object to copy from 
 *
 * @return an apr status
 */
static apr_status_t worker_clone(worker_t ** self, worker_t * orig) {
  apr_pool_t *p;
  apr_pool_t *ptmp;

  apr_pool_create(&p, NULL);
  (*self) = apr_pcalloc(p, sizeof(worker_t));
  memcpy(*self, orig, sizeof(worker_t));
  (*self)->heartbeat = p;
  apr_pool_create(&p, (*self)->heartbeat);
  (*self)->pool = p;
  apr_pool_create(&ptmp, p);
  (*self)->ptmp = ptmp;
  (*self)->prefix = apr_pstrdup(p, orig->prefix);
  (*self)->additional = apr_pstrdup(p, orig->additional);
  (*self)->lines = my_table_deep_copy(p, orig->lines);
  (*self)->cache = my_table_deep_copy(p, orig->cache);
  (*self)->expect_dot = my_table_swallow_copy(p, orig->expect_dot);
  (*self)->expect_error = my_table_swallow_copy(p, orig->expect_error);
  (*self)->match_headers = my_table_swallow_copy(p, orig->match_headers);
  (*self)->match_body = my_table_swallow_copy(p, orig->match_body);
  (*self)->match_error = my_table_swallow_copy(p, orig->match_error);
  (*self)->listener = NULL;
  (*self)->sockets = apr_hash_make(p);
  if (orig->headers_allow) {
    (*self)->headers_allow = my_table_deep_copy(p, orig->headers_allow);
  }
  if (orig->headers_filter) {
    (*self)->headers_filter = my_table_deep_copy(p, orig->headers_filter);
  }
  (*self)->vars = my_table_deep_copy(p, orig->vars);
#ifdef USE_SSL
  (*self)->bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
  (*self)->bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
#endif

  worker_log(*self, LOG_DEBUG, "worker_clone: pool: %p, ptmp: %p\n", (*self)->pool, (*self)->ptmp);
  return APR_SUCCESS;
}
 
/**
 * Clone and copy a body of lines
 *
 * @param body OUT body which has been copied
 * @param worker IN  worker from which we copy the lines for body
 * @param end IN this bodys terminate string
 *
 * @return APR_SUCCESS
 */
static apr_status_t worker_body(worker_t **body, worker_t *worker, char *command) {
  char *file_and_line;
  char *line = "";
  apr_table_entry_t *e; 
  apr_pool_t *p;
  char *end;
  char *kind;
  int ends;
  int end_len;
  int kind_len;

  /* create body */
  apr_pool_create(&p, NULL);
  end = apr_pstrcat(p, "_END ", command, NULL);
  end_len = strlen(end);
  kind = apr_pstrcat(p, "_", command, NULL);
  kind_len = strlen(kind);
  ends = 1;
  (*body) = apr_pcalloc(p, sizeof(worker_t));
  memcpy(*body, worker, sizeof(worker_t));
  /* give it an own heartbeat :) */
  (*body)->heartbeat = p;

  /* fill lines */
  (*body)->lines = apr_table_make(p, 20);
  e = (apr_table_entry_t *) apr_table_elts(worker->lines)->elts;
  for (worker->cmd += 1; worker->cmd < apr_table_elts(worker->lines)->nelts; worker->cmd++) {
    file_and_line = e[worker->cmd].key;
    line = e[worker->cmd].val;
    /* count numbers of same kinds to include all their ends */
    if (strlen(line) >= kind_len && strncmp(line, kind, kind_len) == 0) {
      ++ends;
      worker_log(worker, LOG_DEBUG, "Increment loops: %d for line %s", ends, line);
    }
    /* check end and if it is our end */
    if (strlen(line) >= end_len && strncmp(line, end, end_len) == 0 && ends == 1) {
      break;
    }
    /* no is not our end, decrement ends */
    else if (strlen(line) >= end_len && strncmp(line, end, end_len) == 0) {
      --ends;
      worker_log(worker, LOG_DEBUG, "Decrement loops: %d for line %s", ends, line);
    }
    apr_table_addn((*body)->lines, file_and_line, line);
  }
  /* check for end */
  if (strlen(line) < end_len || strncmp(line, end, end_len) != 0) {
    worker_log(worker, LOG_ERR, "Compilation failed: no %s found", end);
    return APR_EGENERAL;
  }

  return APR_SUCCESS;
}
 
/**
 * Close a body 
 *
 * @param body IN body which has been copied
 * @param worker IN  worker from which we copy the lines for body
 */
static void worker_body_end(worker_t *body, worker_t *worker) {
  /* write back sockets and state */
  worker->socket = body->socket;
  worker->listener = body->listener;

  /* destroy body */
  worker_destroy(body);
}

/**
 * Destroy thread data object
 *
 * @param self IN thread data object
 */
static void worker_destroy(worker_t * self) {
  worker_log(self, LOG_DEBUG, "worker_destroy: %p, ptmp: %p", self->pool, self->ptmp);
  apr_pool_destroy(self->heartbeat);
}

/**
 * Clone thread data object 
 *
 * @param self IN thread data object
 * @param line IN command line
 *
 * @return an apr status
 */
static apr_status_t worker_add_line(worker_t * self, const char *file_and_line,
                                    char *line) {
  apr_table_add(self->lines, file_and_line, line);
  return APR_SUCCESS;
}

/**
 * flush data 
 *
 * @param self IN thread data object
 *
 * @return an apr status
 */
static apr_status_t worker_flush(worker_t * self) {
  apr_size_t len;
  int i;
  int start;
  char *chunked;

  apr_status_t status = APR_SUCCESS;
  apr_table_entry_t *e =
    (apr_table_entry_t *) apr_table_elts(self->cache)->elts;

  if (!self->socket || !self->socket->socket) {
    goto error;
  }
  
  chunked = NULL;
  if (apr_table_get(self->cache, "Content-Length")) {
    /* calculate body len */
    start = 0;
    len = 0;
    for (i = 0; i < apr_table_elts(self->cache)->nelts; ++i) {
      if (!start && !e[i].val[0]) {
        /* start body len */
        start = 1;
      }
      else if (start) {
        /* do not forget the \r\n */
	if (strncasecmp(e[i].key, "NOCRLF", 6) != 0) {
	  len += 2;
	}
	if (strncasecmp(e[i].key, "NOCRLF:", 7) == 0) { 
	  len += apr_atoi64(&e[i].key[7]);
	}
	else {
          len += strlen(e[i].val);
	}
      }
    }

    apr_table_setn(self->cache, "Content-Length",
                   apr_psprintf(self->pool, "Content-Length: %d", len));
  }
  else if (apr_table_get(self->cache, "CHUNKED")) {
    apr_table_unset(self->cache, "CHUNKED");
    len = 0;
    for (i = 0; i < apr_table_elts(self->cache)->nelts; ++i) {
      /* do not forget the \r\n */
      if (strncasecmp(e[i].key, "NOCRLF", 6) != 0) {
	len += 2;
      }
      if (strncasecmp(e[i].key, "NOCRLF:", 7) == 0) { 
	len += apr_atoi64(&e[i].key[7]);
      }
      else {
	len += strlen(e[i].val);
      }
    }
    chunked = apr_psprintf(self->pool, "\r\n%x\r\n", len);
  }

  if (chunked) {
    worker_log(self, LOG_INFO, ">");
    worker_log(self, LOG_INFO, ">%x", len);
    worker_log(self, LOG_INFO, ">");
  }
#ifdef USE_SSL
  if (self->socket->is_ssl) {
    apr_size_t e_ssl;
    if (chunked) {
      len = strlen(chunked);
    tryagain1:
      apr_sleep(1);
      e_ssl = SSL_write(self->socket->ssl, chunked, len);
      if (e_ssl != len) {
        int scode = SSL_get_error(self->socket->ssl, e_ssl);
        if (scode == SSL_ERROR_WANT_WRITE) {
          goto tryagain1;
        }
        status = APR_ECONNABORTED;
	goto error;
      }
    }
  }
  else
#endif
  {
    if (chunked) {
      len = strlen(chunked);
      if ((status =
           apr_socket_send(self->socket->socket, chunked, &len)) 
	  != APR_SUCCESS) {
	goto error;
      }
    }
  }
  /* iterate through all cached lines and send them */
  for (i = 0; i < apr_table_elts(self->cache)->nelts; ++i) {
    if (strncasecmp(e[i].key, "NOCRLF:", 7) == 0) { 
      len = apr_atoi64(&e[i].key[7]);
      worker_log_buf(self, LOG_INFO, e[i].val, ">", len);
    }
    else {
      len = strlen(e[i].val);
      worker_log(self, LOG_INFO, ">%s %s", e[i].val, 
	         strcasecmp(e[i].key, "NOCRLF") ? "" : e[i].key);
    }

#ifdef USE_SSL
    if (self->socket->is_ssl) {
      apr_size_t e_ssl;
    tryagain2:
      apr_sleep(1);
      e_ssl = SSL_write(self->socket->ssl, e[i].val, len);
      if (e_ssl != len) {
        int scode = SSL_get_error(self->socket->ssl, e_ssl);
        if (scode == SSL_ERROR_WANT_WRITE) {
          goto tryagain2;
        }
        status = APR_ECONNABORTED;
	goto error;
      }
      if (strncasecmp(e[i].key, "NOCRLF", 6) != 0) {
        len = 2;
      tryagain3:
        apr_sleep(1);
        e_ssl = SSL_write(self->socket->ssl, "\r\n", len);
        if (e_ssl != len) {
	  int scode = SSL_get_error(self->socket->ssl, e_ssl);
	  if (scode == SSL_ERROR_WANT_WRITE) {
	    goto tryagain3;
	  }
	  status = APR_ECONNABORTED;
	  goto error;
	}
      }
    }
    else
#endif
    {
      if ((status = apr_socket_send(self->socket->socket, e[i].val, &len)) 
	  != APR_SUCCESS) {
        goto error;
      }
      if (strncasecmp(e[i].key, "NOCRLF", 6) != 0) {
	len = 2;
	if ((status =
	     apr_socket_send(self->socket->socket, "\r\n", &len)) != APR_SUCCESS) {
	  goto error;
	}
      }
    }
  }

error:
  apr_table_clear(self->cache);

  return status;
}

/**
 * Lookup function
 *
 * @param line IN line where the command resides
 *
 * @return command index
 */
static int lookup_func_index(command_t *commands, const char *line) {
  int k;
  apr_size_t len;

  k = 0;
  /* lookup command function */
  while (commands[k].name) {
    len = strlen(commands[k].name);
    if (len <= strlen(line)
	&& strncmp(line, commands[k].name, len) == 0) {
      break;
    }
    ++k;
  }

  return k;
}

/**
 * Interpreter
 *
 * @param self IN thread data object
 *
 * @return an apr status
 */
static apr_status_t worker_interpret(worker_t * self, worker_t *parent) {
  apr_status_t status;
  char *line;
  int j;
  int k;

  apr_table_entry_t *e =
    (apr_table_entry_t *) apr_table_elts(self->lines)->elts;

  /* iterate through all script line for this thread */
  for (self->cmd = 0; self->cmd < apr_table_elts(self->lines)->nelts; self->cmd++) {
    self->file_and_line = e[self->cmd].key;
    line = e[self->cmd].val;
    /* lookup function index */
    j = 0;
    k = lookup_func_index(local_commands, line);
    /* get command end test if found */
    if (local_commands[k].func) {
      j += strlen(local_commands[k].name);
      status = local_commands[k].func(&local_commands[k], self, &line[j]);
      status = worker_check_error(parent, status);
      if (status != APR_SUCCESS) {
        return status;
      }
    }
    else {
      worker_log_error(self, "%s syntax error", self->name);
      worker_set_global_error(self);
      return APR_EINVAL;
    }
  }
  return APR_SUCCESS;
}

/**
 * Call final block if exist
 *
 * @param self IN thread data object
 */
static void worker_finally(worker_t *self, apr_status_t status) {
  int k;
  int log_mode;

  k = lookup_func_index(local_commands, "_CALL FINAL");
  if (local_commands[k].func) {
    log_mode = self->log_mode;
    self->log_mode = LOG_NONE;
    local_commands[k].func(&local_commands[k], self, "FINALLY");
    self->log_mode = log_mode;
  }

  if (self->flags & FLAGS_IGNORE_ERRORS) {
    goto exodus;
  } 
  if (status != APR_SUCCESS) {
    worker_set_global_error(self);
//    worker_destroy(self);
    worker_conn_close_all(self);
    exit(status);
  }
exodus:
//  worker_destroy(self);
  worker_conn_close_all(self);
  apr_thread_exit(self->mythread, APR_SUCCESS);
}

/**
 * client thread
 *
 * @param thread IN thread object
 * @param selfv IN void pointer to thread data object
 *
 * @return an apr status
 */
static void *worker_thread_client(apr_thread_t * thread, void *selfv) {
  apr_status_t status;

  worker_t *self = selfv;
  self->mythread = thread;

  self->file_and_line = apr_psprintf(self->pool, "%s:-1", self->filename);

  worker_log(self, LOG_DEBUG, "Client sync ...");
  /* wait on server startups */
  if ((status = apr_thread_mutex_lock(self->sync_mutex)) != APR_SUCCESS) {
    goto error;
  }

  if ((status = apr_thread_cond_wait(self->sync_cond,
                                     self->sync_mutex)) != APR_SUCCESS) {
    goto error;
  }

  if ((status = apr_thread_mutex_unlock(self->sync_mutex)) != APR_SUCCESS) {
    goto error;
  }

  worker_log(self, LOG_INFO, "Client start ...");

  if ((status = worker_interpret(self, self)) != APR_SUCCESS) {
    goto error;
  }

  worker_flush(self);

  if ((status = worker_test_unused(self)) != APR_SUCCESS) {
    goto error;
  }

  if ((status = worker_test_unused_errors(self)) != APR_SUCCESS) {
    goto error;
  }

error:
  worker_finally(self, status);
  return NULL;
}

/**
 * server thread
 *
 * @param thread IN thread object
 * @param selfv IN void pointer to thread data object
 *
 * @return 
 */
static void *worker_thread_server(apr_thread_t * thread, void *selfv) {
  apr_status_t status;

  worker_t *self = selfv;
  self->mythread = thread;

  if ((status = worker_interpret(self, self)) != APR_SUCCESS) {
    goto error;
  }

  worker_flush(self);

  if ((status = worker_test_unused(self)) != APR_SUCCESS) {
    goto error;
  }

  if ((status = worker_test_unused_errors(self)) != APR_SUCCESS) {
    goto error;
  }

error:
  /* do not close listener, there may be more servers which use this 
   * listener, signal this by setting listener to NULL
   */
  self->listener = NULL;
  worker_finally(self, status);
  return NULL;
}

/**
 * listener server thread
 *
 * @param thread IN thread object
 * @param selfv IN void pointer to thread data object
 *
 * @return an apr status
 */
static void *worker_thread_listener(apr_thread_t * thread, void *selfv) {
  apr_status_t status;
  int i;
  int nolistener;
  char *last;
  char *portname;
  char *value;
  int threads = 0;
  worker_t *clone;
  apr_threadattr_t *tattr;
  apr_thread_t *thread_new;
  apr_table_t *servers;

  worker_t *self = selfv;
  self->mythread = thread;

  portname = apr_strtok(self->additional, " ", &last);

  nolistener = 0;
  value = apr_strtok(NULL, " ", &last);
  if (value && strcmp("DOWN", value) != 0) {
    threads = apr_atoi64(value);
  }
  else if (value) {
    /* do not setup listener */
    nolistener = 1;
  }
  else {
    threads = 0;
  }

#ifdef USE_SSL
  self->is_ssl = 0;
  if (strncmp(portname, "SSL:", 4) == 0) {
    self->is_ssl = 1;
    self->meth = SSLv23_server_method();
    portname += 4;
  }
#ifndef OPENSSL_NO_SSL2
  else if (strncmp(portname, "SSL2:", 4) == 0) {
    self->is_ssl = 1;
    self->meth = SSLv2_server_method();
    portname += 5;
  }
#endif
  else if (strncmp(portname, "SSL3:", 4) == 0) {
    self->is_ssl = 1;
    self->meth = SSLv3_server_method();
    portname += 5;
  }
  else if (strncmp(portname, "TLS1:", 4) == 0) {
    self->is_ssl = 1;
    self->meth = TLSv1_server_method();
    portname += 5;
  }

  if ((status = worker_ssl_ctx(self, RSA_SERVER_CERT, RSA_SERVER_KEY)) 
      != APR_SUCCESS) {
    goto error;
  }
#endif

  self->listener_port = apr_atoi64(portname);
  worker_log(self, LOG_INFO, "Start Server: %d", self->listener_port);

  if (!nolistener) {
    if ((status = worker_listener_up(self)) != APR_SUCCESS) {
      goto error;
    }
  }

  if (threads != 0) {
    i = 0;

    if ((status = apr_threadattr_create(&tattr, self->pool)) != APR_SUCCESS) {
      goto error;
    }

    if ((status = apr_threadattr_stacksize_set(tattr, DEFAULT_THREAD_STACKSIZE))
	!= APR_SUCCESS) {
      goto error;
    }

    if ((status = apr_threadattr_detach_set(tattr, 1)) != APR_SUCCESS) {
      goto error;
    }

    servers = apr_table_make(self->pool, 10);

    while(threads == -1 || i < threads) {
      if ((status = worker_clone(&clone, self)) != APR_SUCCESS) {
	worker_log(self, LOG_ERR, "Could not clone server thread data");
	goto error;
      }
      clone->listener = self->listener;
      worker_log(self, LOG_DEBUG, "--- accept");
      if (!self->listener) {
	worker_log_error(self, "Server down");
	status = APR_EGENERAL;
	goto error;
      }

      worker_get_socket(clone, "Default", "0", NULL);
      clone->socket->is_ssl = clone->is_ssl;
      
      if ((status =
	   apr_socket_accept(&clone->socket->socket, self->listener,
			     clone->pool)) != APR_SUCCESS) {
	clone->socket->socket = NULL;
	goto error;
      }
      if ((status =
             apr_socket_timeout_set(clone->socket->socket, self->socktmo)) 
	  != APR_SUCCESS) {
        goto error;
      }
#ifdef USE_SSL
      if ((status = worker_ssl_accept(clone)) != APR_SUCCESS) {
	goto error;
      }
#endif
      worker_log(self, LOG_DEBUG, "--- create thread");
      clone->socket->socket_state = SOCKET_CONNECTED;
      clone->which = i;
      if ((status =
	   apr_thread_create(&thread_new, tattr, worker_thread_server,
			     clone, self->pool)) != APR_SUCCESS) {
	goto error;
      }
      //apr_table_addn(servers, apr_pstrdup(self->pool, " "), (char *) thread_new);

      ++i;
    }

    /* wait on all started servers 
    e = (apr_table_entry_t *) apr_table_elts(servers)->elts;

    for (i = 0; i < apr_table_elts(servers)->nelts; ++i) {
      int ret;
      thread_new = (apr_thread_t *) e[i].val;
      if ((ret = apr_thread_join(&status, thread_new))) {
	status = APR_EGENERAL;
	goto error;
      }
      if (status != APR_SUCCESS) {
	goto error;
      }
    }
     */ 
  }
  else {
    if ((status = worker_interpret(self, self)) != APR_SUCCESS) {
      goto error;
    }

    worker_flush(self);

    if ((status = worker_test_unused(self)) != APR_SUCCESS) {
      goto error;
    }

    if ((status = worker_test_unused_errors(self)) != APR_SUCCESS) {
      goto error;
    }
  }

error:
  worker_finally(self, status);
  return NULL;
}

/****
 * Global object 
 ****/

/**
 * Create new global object
 *
 * @param self OUT new global object
 * @param vars IN global variable table
 * @param log_mode IN log mode
 * @param p IN pool
 *
 * @return apr status
 */
static apr_status_t global_new(global_t **self, apr_table_t *vars, 
                               int log_mode, apr_pool_t *p) {
  apr_status_t status;
  *self = apr_pcalloc(p, sizeof(global_t));

  (*self)->pool = p;
  (*self)->vars = vars;
  (*self)->log_mode = log_mode;

  (*self)->threads = apr_table_make(p, 10);
  (*self)->blocks = apr_hash_make(p);

  if ((status = apr_threadattr_create(&(*self)->tattr, (*self)->pool)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_threadattr_stacksize_set((*self)->tattr, DEFAULT_THREAD_STACKSIZE))
      != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_threadattr_detach_set((*self)->tattr, 0)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_thread_cond_create(&(*self)->cond, p)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_thread_mutex_create(&(*self)->mutex, 
	                                APR_THREAD_MUTEX_DEFAULT,
                                        p)) != APR_SUCCESS) {
    return status;
  }
 
  (*self)->state = GLOBAL_STATE_NONE;
  (*self)->socktmo = 300000000;
  (*self)->prefix = apr_pstrdup(p, "");

  return APR_SUCCESS;
}

/**
 * Global CLIENT command
 *
 * @param self IN global object
 * @param data IN additional 
 *
 * @return apr status 
 */
static apr_status_t global_END(command_t *self, global_t *global, char *data) {
  int concurrent;
  char *last;
  char *val;
  char *name;
  char *called_name;
  apr_thread_start_t thread_run;
  worker_t *clone;
  apr_thread_t *thread;
  apr_status_t status;

  /* start client server deamon */
  if (global->state == GLOBAL_STATE_CLIENT) {
    /* get number of concurrent default is 1 */
    val = apr_strtok(global->worker->additional, " ", &last);
    if (val) {
      concurrent = apr_atoi64(val);
      if (concurrent <= 0) {
	fprintf(stderr, "\nNumber of concurrent clients must be > 0");
	return EINVAL;
      }
      global->worker->additional = NULL;
    }
    else {
      concurrent = 1;
    }
    thread_run = worker_thread_client;
    name = apr_psprintf(global->pool, "CLT%d", global->CLTs);
    ++global->CLTs;
  }
  else if (global->state == GLOBAL_STATE_SERVER) {
    thread_run = worker_thread_listener;
    name = apr_psprintf(global->pool, "SRV%d", global->SRVs);
    concurrent = 1;
    ++global->SRVs;
  }
  else if (global->state == GLOBAL_STATE_BLOCK) {
    /* store block */
    apr_hash_set(global->blocks, global->worker->name, APR_HASH_KEY_STRING, 
	         global->worker);
    global->state = GLOBAL_STATE_NONE;
    return APR_SUCCESS;
  }
  else if (global->state == GLOBAL_STATE_DAEMON) {
    /* get number of concurrent default is 1 */
    concurrent = 1;
    thread_run = worker_thread_client;
    name = apr_pstrdup(global->pool, "DMN");
  }
  else {
    fprintf(stderr, "\nUnknown close of a body definition");
    return APR_ENOTIMPL;
  }
  global->worker->filename = global->filename;
  while (concurrent) {
    clone = NULL;
    --concurrent;
    called_name = apr_psprintf(global->pool, "%s-%d", name, concurrent);
    global->worker->name = called_name;
    global->worker->which = concurrent;
    if (concurrent) {
      if ((status = worker_clone(&clone, global->worker)) != APR_SUCCESS) {
	worker_log(global->worker, LOG_ERR, "Could not clone thread");
	return APR_EINVAL;
      }
    }

    if ((status =
	 apr_thread_create(&thread, global->tattr, thread_run,
			   global->worker, global->pool)) != APR_SUCCESS) {
      return status;
    }
    if (global->state != GLOBAL_STATE_DAEMON) {
      apr_table_addn(global->threads, called_name, (char *) thread);
    }
    global->worker = clone;
  }
  /* reset */
  global->state = GLOBAL_STATE_NONE;

  return APR_SUCCESS;
}

/**
 * Global worker defintion 
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN additional 
 * @param state IN CLIENT | SERVER
 *
 * @return apr status 
 */
static apr_status_t global_worker(command_t *self, global_t *global, char *data, int state) {
  apr_status_t status;

  /* Client start */
  global->state = state;
  if ((status = worker_new(&global->worker, data, global->log_mode, 
	                   global->prefix, global->cond, global->mutex, 
			   global->socktmo, global->blocks)) != APR_SUCCESS) {
    return status;
  }
  global->prefix = apr_pstrcat(global->pool, global->prefix, 
			     "                        ", NULL);
  return APR_SUCCESS;
}

/**
 * Global CLIENT command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN additional 
 *
 * @return apr status 
 */
static apr_status_t global_CLIENT(command_t *self, global_t *global, char *data) {
  return global_worker(self, global, data, GLOBAL_STATE_CLIENT);
}

/**
 * Global SERVER command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN additional 
 *
 * @return apr status 
 */
static apr_status_t global_SERVER(command_t *self, global_t *global, char *data) {
  return global_worker(self, global, data, GLOBAL_STATE_SERVER);
}

/**
 * global BLOCK command 
 *
 * @param self IN command object
 * @param worker IN global object
 * @param data IN name
 *
 * @return an apr status
 */
static apr_status_t global_BLOCK(command_t * self, global_t * global,
                                 char *data) {
  apr_status_t status;

  while (*data == ' ') ++data;
  
  /* Block start */
  global->state = GLOBAL_STATE_BLOCK;

  /* Start a new worker */
  if ((status = worker_new(&global->worker, data, global->log_mode, 
	                   global->prefix, global->cond, global->mutex, 
			   global->socktmo, global->blocks)) != APR_SUCCESS) {
    return status;
  }

  global->worker->name = data;
  
  /* A block has its callies prefix I suppose */
  global->prefix = apr_pstrcat(global->pool, global->prefix, "", NULL);

  return APR_SUCCESS;
}

/**
 * Global DAEMON command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN additional 
 *
 * @return apr status 
 */
static apr_status_t global_DAEMON(command_t *self, global_t *global, char *data) {
  return global_worker(self, global, data, GLOBAL_STATE_DAEMON);
}

/**
 * Global EXEC command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN shell command 
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_EXEC(command_t *self, global_t *global, char *data) {
  apr_status_t status;
  worker_t *worker;

  int i = 0;
  
  while (data[i] == ' ') {
    ++i;
  }

  if ((status = worker_new(&worker, &data[i], global->log_mode, "",
			   global->cond, global->mutex, global->socktmo,
			   global->blocks)) 
      != APR_SUCCESS) {
    return status;
  }
  worker_add_line(worker, apr_psprintf(global->pool, "%s:%d", global->filename,
	                               global->line_nr), 
		  apr_pstrcat(worker->pool, "_EXEC ", &data[i], NULL));
  status = worker_interpret(worker, worker);
  if (status != APR_SUCCESS) {
    worker_set_global_error(worker);
  }

  worker_destroy(worker);

  return status;
}

/**
 * Global SET command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN key=value
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_SET(command_t *self, global_t *global, char *data) {
  char *last;
  char *key;
  char *val;
  
  int i = 0;
  
  while (data[i] == ' ') {
    ++i;
  }
  key = apr_strtok(&data[i], "=", &last);
  val = apr_strtok(NULL, "", &last);
  if (val) {
    apr_table_set(global->vars, key, val);
  }
  else {
    apr_table_set(global->vars, key, "");
  }

  return APR_SUCCESS;
}

/**
 * Global INCLUDE command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN key=value
 *
 * @return APR_SUCCESS
 */
static apr_status_t interpret_recursiv(apr_file_t *fp, global_t *global); 
static apr_status_t global_INCLUDE(command_t *self, global_t *global, char *data) {
  apr_status_t status;
  apr_file_t *fp;
  const char *prev_filename;

  int i = 0;
  while (data[i] == ' ') {
    ++i;
  }
  /* open include file */
  if ((status =
       apr_file_open(&fp, &data[i], APR_READ, APR_OS_DEFAULT,
		     global->pool)) != APR_SUCCESS) {
    fprintf(stderr, "\nInclude file %s not found", &data[i]);
    return APR_ENOENT;
  }

  ++global->recursiv;
  prev_filename = global->filename;
  global->filename = &data[i];
  status = interpret_recursiv(fp, global);
  global->filename = prev_filename;

  apr_file_close(fp);

  return status;
}

/**
 * Global TIMEOUT command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN timeout (starting spaces are possible) 
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_TIMEOUT(command_t *self, global_t *global, char *data) {
  int i = 0;
  
  while (data[i] == ' ') {
    ++i;
  }

  global->socktmo = 1000 * apr_atoi64(&data[i]);

  return APR_SUCCESS;
}

/**
 * Global GO command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_GO(command_t *self, global_t *global, char *data) {
  apr_status_t status;

  while ((status = apr_thread_cond_broadcast(global->cond)) != APR_SUCCESS);

  return APR_SUCCESS;
}

/**
 * Recursiv interpreter. Can handle recursiv calls to with sub files i.e. INCLUDE.
 *
 * @param fp IN current open file
 * @param vars IN global variable table
 * @param log_mode IN log mode
 * @param p IN pool
 * @param threads IN table of running threads
 * @param CLTs IN number of current client
 * @param SRVs IN number of current server
 * @param recursiv IN recursiv level to avoid infinit recursion
 *
 * @return apr status
 */
static apr_status_t interpret_recursiv(apr_file_t *fp, global_t *global) {
  apr_status_t status;
  bufreader_t *bufreader;
  char *line;
  int k;
  int i;
  int line_nr;

  if (global->recursiv > 8) {
    fprintf(stderr, "\nRecursiv inlcudes too deep");
    exit(1);
  }

  if ((status = bufreader_new(&bufreader, fp, global->pool)) != APR_SUCCESS) {
    return status;
  }

  line_nr = 0;
  while (bufreader_read_line(bufreader, &line) == APR_SUCCESS) {
    ++line_nr;
    global->line_nr = line_nr;
    i = 0;
    if (line[i] != '#' && line[i] != 0) {
      /* replace all variables */
      line = replace_vars(global->pool, &line[i], global->vars);

      /* lets see if we can start thread */
      if (global->state != GLOBAL_STATE_NONE) {
        if ((strlen(line) >= 3 && strncmp(line, "END", 3) == 0)) { 
	  i += 3;
	  if ((status = global_END(&global_commands[0], global, &line[i])) != APR_SUCCESS) {
	    return status;
	  }
        }
        else if (line[0] == '_' && 
	         (status = worker_add_line(global->worker, 
		                           apr_psprintf(global->pool, "%s:%d", 
					                global->filename, 
							line_nr), line)) !=
                 APR_SUCCESS) {
          return status;
        }
	else if (line[0] != '_') {
          fprintf(stderr, "\n<none>:%d: Missing END", global->line_nr);
	  return APR_EGENERAL;
	}
      }
      else {
        /* lookup function index */
	i = 0;
        k = lookup_func_index(global_commands, line);
	/* found command? */
	if (global_commands[k].func) {
	  i += strlen(global_commands[k].name);
	  if ((status =
	       global_commands[k].func(&global_commands[k], global,
				       &line[i])) != APR_SUCCESS) {
	    return status;
	  }
	}
	else {
	  /* I ignore unknown commands to be able to set tags like 
	   * DECLARE_SLOW_TEST
	   */
	}
      }
    }
  }

  if (global->state != GLOBAL_STATE_NONE) {
    fprintf(stderr, "\n<none>:%d: Missing END", global->line_nr);
    return APR_EGENERAL;
  }

  return APR_SUCCESS;
}

/**
 * root interpreter
 *
 * @param fp IN open file to interpret
 * @param vars IN host and port file
 * @param log_mode IN log mode
 * @param p IN pool
 *
 * @return an apr status
 */
static apr_status_t interpret(apr_file_t * fp, apr_table_t * vars,
                              int log_mode, apr_pool_t * p) {
  apr_status_t status;
  apr_status_t retstat = APR_SUCCESS;
  apr_thread_t *thread;
  apr_table_entry_t *e;
  int i;
  const char *name;
  global_t *global;

  if ((status = global_new(&global, vars, log_mode, p)) 
      != APR_SUCCESS) {
    return status;
  }
  
  apr_file_name_get(&global->filename, fp);
  if ((status = interpret_recursiv(fp, global)) != APR_SUCCESS) {
    return status;
  }

  /* signal all */
  apr_sleep(200000);
  while ((status = apr_thread_cond_broadcast(global->cond)) != APR_SUCCESS);

  /* wait on thermination of all started threads */

  e = (apr_table_entry_t *) apr_table_elts(global->threads)->elts;

  for (i = 0; i < apr_table_elts(global->threads)->nelts; ++i) {
    thread = (apr_thread_t *) e[i].val;
    name = e[i].key;
    if ((retstat = apr_thread_join(&status, thread))) {
      return retstat;
    }
    if (status != APR_SUCCESS) {
      return status;
    }
  }

  return retstat;
}

/**
 * display copyright information
 */
static void copyright(void) {
  printf("\nThis is Http Test Tool " HTT_VERSION);
}

/** 
 * display usage information
 *
 * @progname IN name of the programm
 */
static void usage(const char *progname) {
  fprintf(stdout, "\nUsage: %s [options] scripts", progname);
  fprintf(stdout, "\nOptions are:");
  fprintf(stdout, "\n    -V      Print version number and exit");
  fprintf(stdout, "\n    -h      Display usage information (this message)");
  fprintf(stdout, "\n    -s      silent mode");
  fprintf(stdout, "\n    -e      error mode");
  fprintf(stdout, "\n    -w      warn mode");
  fprintf(stdout, "\n    -d      debug mode");
  fprintf(stdout, "\n    -L      List all available shell commands");
  fprintf(stdout, "\n    -T      Time stamp on every run");
  fprintf(stdout, "\n    -S      Shell mode");
  fprintf(stdout, "\n");
  exit(EINVAL);
}

static void show_commands(void) {
  int i;

  fprintf(stdout, "\nGlobal Commands");
  fprintf(stdout, "\n---------------");
  i = 0;
  while (global_commands[i].name) { 
    fprintf(stdout, "\n\n%s %s\n%s", global_commands[i].name, 
	    global_commands[i].syntax, global_commands[i].help);
    ++i;
  }
  fprintf(stdout, "\n\n\nLocal Commands ");
  fprintf(stdout, "\n--------------");
  i = 0;
  while (local_commands[i].name) { 
    fprintf(stdout, "\n\n%s %s\n%s", local_commands[i].name, 
	    local_commands[i].syntax, local_commands[i].help);
    ++i;
  }
  fprintf(stdout, "\n\n");
  fflush(stdout);
  exit(0);
}

static void my_exit() {
  if (!success) {
    fprintf(stderr, " FAILED\n");
    fflush(stderr);
  }
  else {
    fprintf(stdout, " OK\n");
    fflush(stdout);
  }
}

/** 
 * sort out command-line args and call test 
 *
 * @param argc IN number of arguments
 * @param argv IN argument array
 *
 * @return 0 if success
 */
int main(int argc, const char *const argv[]) {
  apr_status_t status;
  apr_getopt_t *opt;
  const char *optarg;
  char c;
  apr_pool_t *pool;
  char *cur_file;
  apr_file_t *fp;
  apr_table_t *vars_table;
  int log_mode;
#define MAIN_FLAGS_NONE 0
#define MAIN_FLAGS_PRINT_TSTAMP 1
#define MAIN_FLAGS_USE_STDIN 2
  int flags;
  apr_time_t time;
  char time_str[256];

  srand(apr_time_now()); 
  
  apr_app_initialize(&argc, &argv, NULL);
  atexit(my_exit);
  apr_pool_create(&pool, NULL);

  /* block broken pipe signal */
  apr_signal_block(SIGPIPE);
  
  /* set default */
  log_mode = LOG_INFO;
  flags = MAIN_FLAGS_NONE;

  /* get options */
  apr_getopt_init(&opt, pool, argc, argv);
  while ((status = apr_getopt(opt, "VhsewdLTS", &c, &optarg)) == APR_SUCCESS) {
    switch (c) {
    case 'h':
      usage(argv[0]);
      break;
    case 'V':
      copyright();
      return 0;
      break;
    case 's':
      log_mode = LOG_NONE;
      break;
    case 'e':
      log_mode = LOG_ERR;
      break;
    case 'd':
      log_mode = LOG_DEBUG;
      break;
    case 'w':
      log_mode = LOG_WARN;
      break;
    case 'L':
      show_commands();
      break;
    case 'T':
      flags |= MAIN_FLAGS_PRINT_TSTAMP; 
      break;
    case 'S':
      flags |= MAIN_FLAGS_USE_STDIN; 
      break;
    }
  }

  /* test for wrong options */
  if (!APR_STATUS_IS_EOF(status)) {
    usage(argv[0]);
  }

  /* test at least one file */
  if (!(flags & MAIN_FLAGS_USE_STDIN) && !(argc - opt->ind)) {
    fprintf(stderr, "\n%s: wrong number of arguments", argv[0]);
    usage(argv[0]);
  }

#ifdef USE_SSL
  /* setup ssl library */
#ifdef RSAREF
  R_malloc_init();
#else
  CRYPTO_malloc_init();
#endif
  SSL_load_error_strings();
  SSL_library_init();
  ssl_util_thread_setup(pool);
#endif

  /* do for all files (no wild card support) */
  while (flags & MAIN_FLAGS_USE_STDIN || argc - opt->ind) {
    if (flags & MAIN_FLAGS_USE_STDIN) {
      cur_file = apr_pstrdup(pool, "<stdin>");
    }
    else {
      cur_file = apr_pstrdup(pool, opt->argv[opt->ind++]);
    }

    if (flags & MAIN_FLAGS_USE_STDIN) {
      fprintf(stdout, "simple htt shell\n");
    }
    else if (flags & MAIN_FLAGS_PRINT_TSTAMP) {
      time = apr_time_now();
      if ((status = apr_ctime(time_str, time)) != APR_SUCCESS) {
	fprintf(stderr, "Could not format time: %s (%d)\n", 
	        get_status_str(pool, status), status);
	exit(status);
      }
      fprintf(stdout, "%s  run %-54s\t", time_str, cur_file);
    }
    else {
      fprintf(stdout, "run %-80s\t", cur_file);
    }
    fflush(stdout);

    /* open current file */
    if (flags & MAIN_FLAGS_USE_STDIN) {
      if ((status = apr_file_open_stdin(&fp, pool)) != APR_SUCCESS) {
	fprintf(stderr, "Could not open stdin: %s (%d)\n", 
	        get_status_str(pool, status), status);
	exit(status);
      }
    }
    else if ((status =
              apr_file_open(&fp, cur_file, APR_READ, APR_OS_DEFAULT,
                            pool)) != APR_SUCCESS) {
      fprintf(stderr, "\nCould not open %s: %s (%d)", cur_file,
	      get_status_str(pool, status), status);
      exit(status);
    }

    /* create a global vars table */
    vars_table = apr_table_make(pool, 20);

    /* interpret current file */
    if ((status = interpret(fp, vars_table, log_mode, pool)) != APR_SUCCESS) {
      exit(status);
    }

    /* close current file */
    apr_file_close(fp);

    if (flags & MAIN_FLAGS_USE_STDIN) {
      break;
    }
  }
  apr_pool_destroy(pool);

  return 0;
}


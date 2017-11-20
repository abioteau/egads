#ifndef EGADS_PLATFORM
#define EGADS_PLATFORM 1

#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifdef WIN32

#include <windows.h>

#include "egads.h.in"

#define getpid                GetCurrentProcessId

#define gettimeofday(tv, tz)  do {                                 \
                                struct _timeb tb;                  \
                                _ftime(&tb);                       \
                                (tv)->tv_sec  = tb.time;           \
                                (tv)->tv_usec = tb.millitm * 1000; \
                              } while (0)

typedef DWORD  pthread_t;
typedef HANDLE pthread_cond_t;
typedef HANDLE pthread_mutex_t;

#define PTHREAD_COND_INITIALIZER    NULL    /* CreateMutex(NULL, FALSE, NULL) */
#define PTHREAD_MUTEX_INITIALIZER   NULL    /* CreateEvent(NULL, FALSE, FALSE, NULL) */

#define pthread_mutex_lock(x)     WaitForSingleObject(*(x), INFINITE)
#define pthread_mutex_unlock(x)   ReleaseMutex(*(x))
#define pthread_cond_signal(x)    SetEvent(*(x))
#define pthread_cond_broadcast(x) PulseEvent(*(x))
#define pthread_cond_wait(x, y)   do { \
                                    pthread_mutex_unlock(y);             \
                                    WaitForSingleObject(*(x), INFINITE); \
                                    pthread_mutex_lock(y);               \
                                  } while(0)

#define pthread_cleanup_push(x, y)
#define pthread_cleanup_pop(x)

#else   /* !WIN32 */

#ifndef NO_THREADS
#include <pthread.h>
#else
#define pthread_mutex_lock(x)
#define pthread_mutex_unlock(x)
#define pthread_cond_wait(x, y)
#define pthread_cond_signal(x)
#define pthread_cond_broadcast(x)
#define pthread_cleanup_push(x, y)
#define pthread_cleanup_pop(x)
#endif

#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

/* unix/common.c */
int EGADS_read(int fd, void *buffer, int nb);
int EGADS_write(int fd, void *buffer, int nb);
int EGADS_safedir(char *dir, int write_to_file);

#include "egads.h"

#endif  /* WIN32 */

#include "byteswap.h"

#ifdef USING_SPLAT
#include "../config.h"
#include "../splat.h"

#define EGADS_ALLOC(ptr, size, secure)  splat_new(&(ptr), (size), (secure))
#define EGADS_REALLOC(ptr, size)        splat_realloc(&(ptr), (size))
#define EGADS_FREE(ptr)                 splat_free((ptr))
#define EGADS_STRDUP(str)               splat_strdup((str))
#else
#define EGADS_ALLOC(ptr, size, secure)  *((void **)(&(ptr))) = malloc((size))
#define EGADS_REALLOC(ptr, size)        *((void **)(&(ptr))) = realloc((ptr), (size))
#define EGADS_FREE(ptr)                 free((ptr))
#define EGADS_STRDUP(str)               strdup((str))
#endif

#endif  /* EGADS_PLATFORM */

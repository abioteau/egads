#ifndef EGADSPRIV_H__
#define EGADSPRIV_H__

void timestamp(int sid);
void ACCUM_start();
void ACCUM_stop();
void call_ps();
void call_df();

#define LOCK_FILE_NAME "egads.lock"
#define PID_FILE_NAME  "egads.pid"
#define SEED_FILE_NAME "egads.seed"
#define EGADS_VERSION  "0.9.5"
#define EGADS_DATE     "September 2, 2002"

#ifndef WIN32
#define NUM_SOURCES    7 
#else
#define NUM_SOURCES    3
#endif

#define SRC_SCHED      0
#define SRC_THREAD     1

#ifndef WIN32
#define SRC_TRUERAND   2
#define SRC_LOGFILE    3
#define SRC_CMDS       4
#define SRC_DEVRANDOM  5
#define SRC_EXTERNAL   6
#else
#define SRC_PDH        2
#endif

#define SCHED_ITERS    10000
#define THREAD_ITERS   100
#define TRUERAND_ITERS 8

extern int id_list [NUM_SOURCES];

#endif

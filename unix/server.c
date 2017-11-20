/* TODO:
 * Faster than a rolling 'o'.
 * Stronger than a silent 'e'.
 * Able to leap capital 'T' in a single bound.
 * It's a word... it's a plan... it's... Letterman!
 *
 * Accumulate fast until slow pool seeds, then slow down.
 * Test for security of the data dir path in the setup function.
 * Support single threaded environment.
 * error checking.  Failures on popens, etc.
 * Make sure log files are only owner-readable.
 * fstat and check perms on the stuff we open.
 * Seed file.
 * Option to collect + out n bytes.
 * Good error messages on failures.
 * Better logging infrastructure.
 * Hook up a few more commands.
 * Configuration and porting.
 * Standardize data types.
 * Big endianness.
 * Pass through lint.
 */

#include "platform.h"

#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include "eg.h"

#include "egads.h"

#define OPT_NO_FORKING    0x01
#define OPT_NO_LOGS       0x02
#define OPT_NO_CMDS       0x04
#define OPT_NO_THREADT    0x08
#define OPT_USE_TRUERAND  0x10
#define OPT_NO_SCHED      0x20
#define OPT_VERBOSE       0x40

#define TEST_FLAG(x)      (cmd_flags & (x))

#define LOG_CHUNKSZ       1024
#define ULOG_STEP         16

int id_list[NUM_SOURCES];

static int estimates[] =
{
  2,  /* sched timing */
  3,  /* Thread timing */
  2,  /* TrueRand */
  1,  /* Log entry timestamp */
  0   /* Command specific */
};

static int collect, delay = 1;
static char *data_dir;
static unsigned int cmd_flags = 0;

static int num_ulogs, *logfiles, logfiles_sz;
static char **ulogs;

static int truerand_done;
static uint32 truerand_count;

static char *logfilenames[] =
{
  "/var/log/messages",
  "/var/log/maillog",
  NULL
};

static char *lock_file_name = EGADSDATA "/" LOCK_FILE_NAME;
static char *pid_file_name = EGADSDATA "/" PID_FILE_NAME;
static char *socket_file_name = EGADSDATA "/" SOCK_FILE_NAME;
static char *seed_file_name = EGADSDATA "/" SEED_FILE_NAME;
static char *egd_file_name = NULL;

void timestamp(int sid)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);
  EG_add_entropy(id_list[sid], (unsigned char *)&tv, sizeof(tv), estimates[sid]);
}

static
uint32 diff_usec(struct timeval *start, struct timeval *end)
{
  if (end->tv_usec < start->tv_usec)
  {
    return 1000000 - start->tv_usec + end->tv_usec;
  }
  return end->tv_usec - start->tv_usec;
}

static
void *collect_devrandom(void *arg)
{
  int fd, nb;
  uint8 buffer[4];

  if ((fd = open("/dev/random", O_RDONLY)) != -1)
  {
    for (;;)
    {
      if ((nb = read(fd, buffer, sizeof(buffer))) > 0)
      {
        EG_add_entropy(id_list[SRC_DEVRANDOM], buffer, nb, nb / 8);
      }
      sleep(1);
    }
  }

  return NULL;
}

static
void sched_time(void)
{
  int i;
  uint32 diff;
  struct timeval start, end;

  gettimeofday(&start, NULL);
  for (i = 0;  i < SCHED_ITERS;  i++)
  {
    sched_yield();
  }
  gettimeofday(&end, NULL);

  diff = diff_usec(&start, &end);
  EG_add_entropy(id_list[SRC_SCHED], (unsigned char *)&diff, sizeof(diff), 0);
  timestamp(SRC_SCHED);
}

static
void *thread_stub(void *arg)
{
  return NULL;
}

static
void thread_time(void)
{
  int i;
  uint32 diff;
  pthread_t tid;
  struct timeval start, end;

  gettimeofday(&start, NULL);
  for (i = 0;  i < THREAD_ITERS;  i++)
  {
    if (!pthread_create(&tid, NULL, thread_stub, NULL))
    {
      pthread_join(tid, NULL);
    }
  }
  gettimeofday(&end, NULL);

  diff = diff_usec(&start, &end);
  EG_add_entropy(id_list[SRC_THREAD], (unsigned char *)&diff, sizeof(diff), 0);
  timestamp(SRC_THREAD);
}

static
void set_timer(void)
{
  struct itimerval it, ot;

  timerclear(&it.it_interval);
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 33333;
  setitimer(ITIMER_REAL, &it, &ot);
}

static
uint32 time_itimer(void)
{
  truerand_done = 0;
  truerand_count = 0;
  set_timer();

  while (!truerand_done)
  {
    truerand_count++;
  }
  return truerand_count;
}

static
void truerand(void)
{
  int i;
  uint32 buf[TRUERAND_ITERS];

  for (i = 0;  i < TRUERAND_ITERS;  i++)
  {
    buf[i] = time_itimer();
  }

  EG_add_entropy(id_list[SRC_TRUERAND], (unsigned char *)buf, sizeof(buf), 0);
  timestamp(SRC_TRUERAND);
}

static
void entropy_cleanup(void *arg)
{
  if (TEST_FLAG(OPT_VERBOSE))
  {
    printf("Entropy collection ended.\n");
  }
}

static
void *collect_entropy(void *arg)
{
  int firstpass = 1;
  if (TEST_FLAG(OPT_VERBOSE))
  {
    printf("Entropy collection started.\n");
  }
  pthread_cleanup_push(entropy_cleanup, NULL);
  while (collect)
  {
    if (!TEST_FLAG(OPT_NO_SCHED))
    {
      sched_time();
    }
#ifndef FBSD_THREADS
    if (!TEST_FLAG(OPT_NO_THREADT))
    {
      thread_time();
    }
#endif
    if (TEST_FLAG(OPT_USE_TRUERAND))
    {
      truerand();
    }
    if (!TEST_FLAG(OPT_NO_CMDS))
    {
      call_ps();
      call_df();
    }

    if (TEST_FLAG(OPT_VERBOSE))
    {
      printf("Entropy collected: %f\n", EG_entropy_level());
    }

    if (firstpass)
    {
        EG_startup_done();
        firstpass = 0;
    }
    if (EG_entropy_level() >= 1.0)
    {
      sleep(delay);
    }
  }
  pthread_cleanup_pop(1);

  return NULL;
}

static
int read_data(int fd, void *buffer, int len)
{
  int got, nb;

  for (got = 0;  got < len;  got += nb)
  {
    nb = EGADS_read(fd, (char *)buffer + got, len - got);
    if (nb == -1 && (errno == EAGAIN || errno == EINTR))
    {
      nb = 0;
      continue;
    }
    if (nb <= 0)
      return 0;
  }

  return 1;
}

static
int write_data(int fd, void *buffer, int len)
{
  int done, nb;

  for (done = 0;  done < len;  done += nb)
  {
    nb = EGADS_write(fd, (char *)buffer + done, len - done);
    if (nb == -1 && (errno == EAGAIN || errno == EINTR))
    {
      nb = 0;
      continue;
    }
    if (nb <= 0)
      return 0;
  }
  
  return 1;
}

/* Protocol is as follows:
 * 1 byte COMMAND, which must always be CMD_REQ_ENTROPY for right now.
 * arguments, command specific.
 * Repeat, ad nauseum.
 * Return: response, command specific.
 */

static
int process_egads_request(int fd, char cmd)
{
  int howmuch, rc;
  char *buffer;

  switch (cmd)
  {
    case ECMD_REQ_ENTROPY:
      if (!read_data(fd, &howmuch, sizeof(int)))
      {
        break;
      }

      EGADS_ALLOC(buffer, howmuch, 0);
      EG_output(buffer, howmuch, 1);
      rc = write_data(fd, buffer, howmuch);
      EGADS_FREE(buffer);
      if (!rc)
      {
        break;
      }
      EGADS_FREE(buffer);
      return 0;
  }

  return 1;
}

static
void *handle_egads_client(void *arg)
{
  int done = 0, fd = (int)arg;
  char cmd;

  pthread_detach(pthread_self());
  while (!done)
  {
    if (!read_data(fd, &cmd, 1))
    {
      done = 1;
    }
    else
    {
      done = process_egads_request(fd, cmd);
    }
  }

  close(fd);
  return NULL;
}

static
int process_egd_request(int fd, char cmd)
{
  int entropy;
  char buffer[256];
  unsigned char howmuch;

  switch (cmd)
  {
    case EGD_REQ_ENTROPY_LEVEL:
      entropy = (int)EG_entropy_level();
      if (!write_data(fd, &entropy, sizeof(entropy)))
      {
        break;
      }
      return 0;

    case EGD_REQ_ENTROPY_NB:
      if (!read_data(fd, &howmuch, 1))
      {
        break;
      }
      buffer[0] = (unsigned char)(EG_output(&(buffer[1]), howmuch, 0) & 0xff);
      if (!write_data(fd, buffer, (int)howmuch + 1))
      {
        break;
      }
      return 0;

    case EGD_REQ_ENTROPY:
      if (!read_data(fd, &howmuch, 1))
      {
        break;
      }
      if (!write_data(fd, buffer, EG_output(buffer, howmuch, 1)))
      {
        break;
      }
      return 0;

    case EGD_ADD_ENTROPY:
      if (!read_data(fd, buffer, 3))
      {
        break;
      }
      entropy = ((unsigned char)buffer[0] << 8) | (unsigned char)buffer[1];
      howmuch = (unsigned char)buffer[2];
      if (!read_data(fd, buffer, (int)howmuch))
      {
        break;
      }
      EG_add_entropy(SRC_EXTERNAL, buffer, howmuch, entropy);
      return 0;

    case EGD_REQ_PID:
      sprintf(&(buffer[1]), "%d", getpid());
      buffer[0] = (char)(strlen(buffer) & 0xff);
      if (!write_data(fd, buffer, buffer[0] + 1))
      {
        break;
      }
      return 0;
  }

  return 1;
}

static
void *handle_egd_client(void *arg)
{
  int fd = (int)arg, done = 0;
  char cmd;

  pthread_detach(pthread_self());
  while (!done)
  {
    if (!read_data(fd, &cmd, 1))
    {
      done = 1;
    }
    else
    {
      done = process_egd_request(fd, cmd);
    }
  }

  close(fd);
  return NULL;
}

struct server_arg
{
  int sfd;
  int egd;
};

static
void *server_main(void *arg)
{
  int cfd, len, egd, sfd, old;
  pthread_t tid;
  struct sockaddr_un csa;

  sfd = ((struct server_arg *)arg)->sfd;
  egd = ((struct server_arg *)arg)->egd;
  EGADS_FREE(arg);

  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old);
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old);
  for (;;)
  {
    len = sizeof(csa);
    if ((cfd = accept(sfd, (struct sockaddr *)&csa, &len)) == -1)
    {
      if (errno != EAGAIN && errno != EINTR)
      {
        perror("EGADS: run_server: accept");
      }
      continue;
    }

    /* TODO: maybe limit the number of simultaneous clients? */
    if (!egd)
    {
      pthread_create(&tid, NULL, handle_egads_client, (void *)cfd);
    }
    else
    {
      pthread_create(&tid, NULL, handle_egd_client, (void *)cfd);
    }
  }
}

static
pthread_t run_server(char *file, int egd)
{
  int rc, sfd;
  pthread_t tid;
  struct sockaddr_un ssa;
  struct server_arg *info;

  ssa.sun_family = AF_UNIX;
  strncpy(ssa.sun_path, file, sizeof(ssa.sun_path) - 1);
  ssa.sun_path[sizeof(ssa.sun_path) - 1] = '\0';

  if ((sfd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
  {
    rc = errno;
    perror("EGADS: run_server: socket");
    exit(rc);
  }

  umask(0);
  if (bind(sfd, (struct sockaddr *)&ssa, sizeof(ssa)) == -1)
  {
    if (errno == EADDRINUSE)
    {
      if (connect(sfd, (struct sockaddr *)&ssa, sizeof(ssa)) == -1)
      {
        unlink(ssa.sun_path);
      }
      if (bind(sfd, (struct sockaddr *)&ssa, sizeof(ssa)) == -1)
      {
        rc = errno;
        perror("EGADS: run_server: bind");
        exit(rc);
      }
    }
    else
    {
      rc = errno;
      perror("EGADS: run_server: bind");
      exit(rc);
    }
  }
  umask(066);

  if (listen(sfd, SOMAXCONN) == -1)
  {
    rc = errno;
    perror("EGADS: run_server: listen");
    exit(rc);
  }

  EGADS_ALLOC(info, sizeof(info), 0);
  info->sfd = sfd;
  info->egd = egd;
  if (pthread_create(&tid, NULL, server_main, info))
  {
    EGADS_FREE(info);
  }
  return tid;
}

static
int open_logfile(char *filename)
{
  int fd;

  if ((fd = open(filename, O_RDONLY | O_NONBLOCK)) == -1)
  {
    perror(filename);
    return -1;
  }

  if (lseek(fd, 0, SEEK_END) == -1)
  {
    perror("lseek");
    close(fd);
    return -1;
  }

  return fd;
}

static
void open_log_files(void)
{
  int fd, i, j, num;

  num = num_ulogs;
  if (!TEST_FLAG(OPT_NO_LOGS))
  {
    for (i = 0;  logfilenames[i];  i++);
    num += i;
  }

  j = 0;
  EGADS_ALLOC(logfiles, sizeof(int) * num, 0);
  if (!TEST_FLAG(OPT_NO_LOGS))
  {
    for (i = 0;  logfilenames[i];  i++)
    {
      if ((fd = open_logfile(logfilenames[i])) != -1)
      {
        logfiles[j++] = fd;
      }
    }
    for (i = 0;  i < num_ulogs;  i++)
    {
      if ((fd = open_logfile(ulogs[i])) != -1)
      {
        logfiles[j++] = fd;
      }
    }
  }
  logfiles_sz = j;
}

static
void add_logfile(char *file)
{
  if (!(num_ulogs % ULOG_STEP))
  {
    EGADS_REALLOC(ulogs, sizeof(char *) * (num_ulogs + ULOG_STEP));
  }
  ulogs[num_ulogs++] = file;
}

static
void read_logfiles(void)
{
  int i;
  ssize_t b;
  unsigned char rbuf[LOG_CHUNKSZ];

  for (i = 0;  i < logfiles_sz;  i++)
  {
    b = read(logfiles[i], rbuf, sizeof(rbuf));
    if (b > 0)
    {
      /* Estimate at 0; entropy estimate gets added in when we call timestamp()
       */
      EG_add_entropy(id_list[SRC_LOGFILE], rbuf, b, 0);
      while ((b = read(logfiles[i], rbuf, sizeof(rbuf))) > 0);
      timestamp(SRC_LOGFILE);
    }
  }
}

static
void *poll_logfiles(void *arg)
{
  for (;;)
  {
    sleep(1);
    read_logfiles();
  }
}

static
void display_help(char *progname)
{
  fprintf(stderr, "usage: %s [dhlpvCFLRSTV]\n\n", progname);
  fprintf(stderr, "-d <seconds>  Specify the delay between collections\n");
  fprintf(stderr, "-e <name>     Specify the name of a socket to use for EGD\n");
  fprintf(stderr, "-h            Display this list of options\n");
  fprintf(stderr, "-l <logfile>  Specify a log file to watch\n");
  fprintf(stderr, "-p <path>     Specify the data directory to use\n");
  fprintf(stderr, "-v            Specify verbose mode\n");
  fprintf(stderr, "-C            Do not include external commands in gathered data\n");
  fprintf(stderr, "-F            Do not fork\n");
  fprintf(stderr, "-L            Do not include log files in gathered data\n");
  fprintf(stderr, "-R            Use TrueRand\n");
  fprintf(stderr, "-S            Do not include scheduler timing in gathered data\n");
  fprintf(stderr, "-T            Do not include thread timing in gathered data\n");
  fprintf(stderr, "-V            Display version information\n");
}

static
void read_options(int argc, char **argv)
{
  int i;

  while ((i = getopt(argc, argv, "d:e:hl:p:vCFLRSTV?")) != -1)
  {
    switch (i)
    {
      case 'd':
        if ((delay = atoi(optarg)) < 0)
        {
          fprintf(stderr, "Negative delay not allowed.\n");
          exit(EINVAL);
        }
        break;

      case 'e':
        if (egd_file_name)
        {
          EGADS_FREE(egd_file_name);
        }
        egd_file_name = EGADS_STRDUP(optarg);
        break;

      case 'l':
        add_logfile(EGADS_STRDUP(optarg));
        break;

      case 'p':
        if (data_dir)
        {
          fprintf(stderr, "Warning: data directory specified multiple times.\n");
          EGADS_FREE(data_dir);
        }
        data_dir = EGADS_STRDUP(optarg);
        break;

      case 'v':
        cmd_flags |= OPT_VERBOSE;
        break;

      case 'C':
        cmd_flags |= OPT_NO_CMDS;
        break;

      case 'F':
        cmd_flags |= OPT_NO_FORKING;
        break;

      case 'L':
        cmd_flags |= OPT_NO_LOGS;
        break;

      case 'R':
        cmd_flags |= OPT_USE_TRUERAND;
        break;

      case 'S':
        cmd_flags |= OPT_NO_SCHED;
        break;

      case 'T':
        cmd_flags |= OPT_NO_THREADT;
        break;

      case 'V':
        fprintf(stderr, "EGADS: Entropy Gathering And Distribution System.\n");
        fprintf(stderr, "Version %s, %s.\n", EGADS_VERSION, EGADS_DATE);
        exit(0);

      case 'h':
      case '?':
        display_help(argv[0]);
        exit(0);
    }
  }

  if (optind != argc)
  {
    fprintf(stderr, "%s: extra arguments ignored.\n", argv[0]);
  }
}

#define BUILD_PATH(var, macro)  EGADS_ALLOC(var, strlen(macro) + n, 0); \
                                sprintf(var, "%s/%s", data_dir, macro)

static
void setup_file_names(void)
{
  int n;

  if (data_dir)
  {
    if (!EGADS_safedir(data_dir, 1))
    {
      fprintf(stderr, "`%s' is not a secure directory.\n", data_dir);
      exit(EPERM);
    }

    n = strlen(data_dir) + 2;
    BUILD_PATH(lock_file_name, LOCK_FILE_NAME);
    BUILD_PATH(pid_file_name, PID_FILE_NAME);
    BUILD_PATH(socket_file_name, SOCK_FILE_NAME);
    BUILD_PATH(seed_file_name, SEED_FILE_NAME);
  }
  else if (!EGADS_safedir(EGADSDATA, 1))
  {
    fprintf(stderr, "Unsafe permissions on `%s'.\n", EGADSDATA);
  }
}

static
pid_t read_pid(void)
{
  FILE *f;
  pid_t pid;

  if (!(f = fopen(pid_file_name, "r")))
  {
    return -1;
  }
  if (fscanf(f, "%d", &pid) != 1)
  {
    pid = -1;
  }
  fclose(f);
  return pid;
}

static
void write_pid(void)
{
  int fd, i, rc;
  pid_t pid;

  for (i = 0;  i < 3;  i++)
  {
    if ((fd = open(pid_file_name, O_RDWR | O_CREAT | O_EXCL, S_IRWXU)) == -1)
    {
      if (errno != EEXIST)
      {
        rc = errno;
        perror("EGADS: write_pid: open");
        exit(rc);
      }

      if ((pid = read_pid()) != -1)
      {
        if (kill(pid, SIGTERM) == -1)
        {
          if (errno != ESRCH)
          {
            rc = errno;
            perror("EGADS: write_pid: kill");
            exit(rc);
          }

          /* Process is gone, we win */
          unlink(pid_file_name);
        }
      }
    }
    else
    {
      /* No lock file, we got it */
      char tmpbuf[15];

      snprintf(tmpbuf, sizeof(tmpbuf), "%d", getpid());
      tmpbuf[sizeof(tmpbuf) - 1] = '\0';
      write(fd, tmpbuf, strlen(tmpbuf));
      close(fd);
      return;
    }

    sleep(1); /* Some buffer time */
  }

  /* If we've made it out of this loop, we've tried to kill three processes and
   * still failed to get the lock.  Time to bail out.
   */
  fprintf(stderr, "Exiting: another EGADS process is already running.\n");
  exit(EALREADY);
}

void ACCUM_start(void)
{
  collect = 1;
}

void ACCUM_stop(void)
{
  collect = 0;
}

static
pthread_t *ACCUM_init(int *count)
{
  int i;
  FILE *sfile;
  pthread_t *list;

  EG_init();
  if (!(sfile = fopen(seed_file_name, "r")))
  {
    fprintf(stderr, "Could not open seed file `%s'.\n", seed_file_name);
  }
  else
  {
    EG_restore_state(sfile);
    fclose(sfile);
  }

  for (i = 0;  i < NUM_SOURCES;  i++)
  {
    if ((id_list[i] = EG_register_source()) < 0)
    {
      fprintf(stderr, "Could not register all entropy sources.\n");
      exit(-1);
    }
  }
  ACCUM_start();

  i = 0;
  if (!TEST_FLAG(OPT_NO_LOGS) || num_ulogs)
  {
    *count = 3;
    EGADS_ALLOC(list, sizeof(pthread_t) * (*count), 0);
    pthread_create(&(list[i++]), NULL, poll_logfiles, NULL);
  }
  else
  {
    *count = 2;
    EGADS_ALLOC(list, sizeof(pthread_t) * (*count), 0);
  }

  pthread_create(&(list[i++]), NULL, collect_entropy, NULL);
  pthread_create(&(list[i++]), NULL, collect_devrandom, NULL);

  return list;
}

static
void save_me(void)
{
  FILE *f;

  if (!(f = fopen(seed_file_name, "w+")))
  {
    fprintf(stderr, "Warning: Could not save state file!\n");
  }
  else
  {
    EG_save_state(f);
    fclose(f);
  }
}

int main(int argc, char **argv)
{
  int threadc, which;
  sigset_t mask, oldmask;
  pthread_t egdtid, tid, *threadv;

  umask(066);
  read_options(argc, argv);
  setup_file_names();
  if (!(cmd_flags & OPT_NO_FORKING) && fork())
  {
    exit(0);
    return 0;
  }

  write_pid();
  open_log_files();
  threadv = ACCUM_init(&threadc);

  tid = run_server(socket_file_name, 0);
  if (egd_file_name)
  {
    egdtid = run_server(egd_file_name, 1);
  }
  else
  {
    /* cast here to avoid compiler warnings.  pthread_t is opaque so it
     * could be either an int or a pointer.
     */
    egdtid = (pthread_t)NULL;
  }

  sigemptyset(&mask);
  sigaddset(&mask, SIGHUP);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGQUIT);
  sigaddset(&mask, SIGALRM);
#if !defined(__APPLE__) || !defined(__MACH__)
  pthread_sigmask(SIG_BLOCK, &mask, &oldmask);
#else
  sigprocmask(SIG_BLOCK, &mask, &oldmask);
#endif

  do
  {
#if defined(__APPLE__) && defined(__MACH__)
    sigset_t  pending;

    sigsuspend(&oldmask);
    sigpending(&pending);
    if (!sigismember(&pending, SIGALRM))
      which = !SIGALRM;   /* who cares */
    else
    {
      which = SIGALRM;
#else
    sigwait(&mask, &which);
    if (which == SIGALRM)
    {
#endif
      if (truerand_count)
      {
        truerand_done = 1;
      }
      else
      {
        set_timer();
      }
    }
  }
  while (which == SIGALRM);

  if (egd_file_name)
  {
    pthread_cancel(egdtid);
    pthread_join(egdtid, NULL);
  }

  pthread_cancel(tid);
  pthread_join(tid, NULL);

  while (threadc--)
  {
    pthread_cancel(threadv[threadc]);
    pthread_join(threadv[threadc], NULL);
  }

  save_me();

  exit(0);
  return 0;
}

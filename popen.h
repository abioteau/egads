#ifndef POPEN_H__
#define POPEN_H__

#include <sys/types.h>
#include <stdio.h>

#define P_READ         1
#define P_WRITE        2
#define P_RW           (P_READ|P_WRITE)
#define P_PRIVD        4
#define EXITVAL        127
#define NOBODY_UID     99
#define NOBODY_GID     99

typedef struct pipe_st {
  FILE           *read_ptr;
  FILE           *write_ptr;
  pid_t           pid;
} pipe_t;

pipe_t *run_cmd(char *cmd, short flags);
pipe_t *send_file_to_cmd(FILE *f, char *cmd);
pipe_t *send_pipe_to_cmd(pipe_t *p, char *cmd);
pipe_t *priv_run_cmd(char *cmd, short flags);
pipe_t *priv_send_file_to_cmd(FILE *f, char *cmd);
pipe_t *priv_send_pipe_to_cmd(pipe_t *p, char *cmd);
FILE *pipe_get_read_file(pipe_t *p);
FILE *pipe_get_write_file(pipe_t *p);
int   pipe_close(pipe_t *p);
#endif

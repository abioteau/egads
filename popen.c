#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>

#include "popen.h"
#include "platform.h"

/* We allow double quotes and \ to escape spaces. 
 * All backslashes are "processed", despite the value
 * of the next character. (Though \\ -> \).
 * We don't care if there's a missing trailing quote,
 * even if it should really be a syntax error.
 */
static char **
to_words(char *arg) {
  char **arr;
  char  *p = arg;
  int    nw = 1;
  int    slc = 0;
  int    slm = 0;
  char   c;
  short  quote = 0;
  char  *cur;


  /* Build a rough approximation of the number of words,
   * simply so we don't malloc too low.
   */
  while((c = *p++)) {
    slc++;
    if(c == '"' || c == ' ') {
      nw++;
      if(slm < slc) slm = slc;
      slc = 0;
    }
  }
  arr = (char **)malloc(sizeof(char *)*(nw+1));
  quote = nw = slc = 0;
  p = arg;
  cur = (char *)malloc(sizeof(char)*(slm+1));
  arr[nw++] = cur;
  while((c = *p++)) {
    switch(c) {
    case '"':
      quote = !quote;
      continue;
    case ' ':
      if(quote) {
	*cur++ = c;
	slc++;
	continue;
      } else {
	if(!slc) continue;
	*cur = 0;
	cur = (char *)malloc(sizeof(char)*(slm+1));
	arr[nw++] = cur;
	slc = 0;
	continue;
      }
    case '\\':
      if(*p) {
	*cur++ = *p++;
	slc++;
	continue;
      }
    default:
      *cur++ = c;
      slc++;
      continue;
    }
  }
  *cur = 0;
  arr[nw] = 0;
  return arr;
}

static void
drop_privs() {
  int old_errno = errno;
  /* If these fail, we weren't run setuid, so no worries. */ 
  setuid(NOBODY_UID);
  setgid(NOBODY_GID);
  seteuid(NOBODY_UID);
  setegid(NOBODY_GID);
  errno = old_errno;
}

static void
free_args(char **args)
{
  int idx = 0;

  while(args[idx] != 0)
  {
    EGADS_FREE(args[idx]);
    idx++;
  }
  EGADS_FREE(args);
}

static pipe_t * 
raw_pipe_open(char *arg, int how, pipe_t *pchildread, FILE *fchildread) {
  int    prpd[2];
  int    pwpd[2];
  pid_t  pid;
  char **args;
  pipe_t  *ret;

  args = to_words(arg);

  if((how & P_READ) && pipe(prpd) < 0) {
    return 0; /* Pipe failed. */
  }

  if((how & P_WRITE) && pipe(pwpd) < 0) {
    return 0; /* Pipe failed. */
  }

  if(how & P_WRITE) {
    if(pchildread && dup2(fileno(pchildread->read_ptr), 
			  pwpd[STDIN_FILENO]) < 0) {
      return 0;
    } else {
      if(fchildread && dup2(fileno(fchildread), pwpd[STDIN_FILENO]) < 0) {
	return 0;
      }
    }
  }

  pid = fork();
  switch(pid) {
  case -1:
    if(how & P_READ) {
      close(prpd[STDIN_FILENO]);
      close(prpd[STDOUT_FILENO]);
    }
    if(how & P_WRITE) {
      close(pwpd[STDIN_FILENO]);
      close(pwpd[STDOUT_FILENO]);
    }
    free_args(args);
    return 0; /* Fork failed. */
    /* Here we can only exit on error. */
  case 0:
    /* Child...  */
    if(!(how & P_PRIVD)) {
      drop_privs();
    }
    if((how & P_WRITE) && dup2(pwpd[STDIN_FILENO], STDIN_FILENO) < 0) {
      
      exit(EXITVAL);
    }
    if((how & P_READ) && dup2(prpd[STDOUT_FILENO], STDOUT_FILENO) < 0) {
      exit(EXITVAL);
    }

    if(how & P_WRITE) {

      close(pwpd[STDIN_FILENO]);
      close(pwpd[STDOUT_FILENO]);
    }

    if(how & P_READ) {
      close(prpd[STDIN_FILENO]);
      close(prpd[STDOUT_FILENO]);
    }

    execv(args[0], args);
    exit(EXITVAL);
  default:
    ret = (pipe_t *)malloc(sizeof(pipe_t)); 
    ret->read_ptr = ret->write_ptr = 0;
    ret->pid = pid;
    if(how & P_WRITE) {
      close(pwpd[0]);
      fcntl(pwpd[1], F_SETFD, FD_CLOEXEC);
      if(!pchildread && !fchildread) {
	ret->write_ptr = fdopen(pwpd[1], "wb"); 
	if(!ret->write_ptr) {
	  int old = errno;
	  kill(pid, SIGKILL);
	  close(pwpd[1]);
	  waitpid(pid, 0, 0);
	  errno = old;
	  free(ret);
          free_args(args);
	  return 0;
	}
      } else {
	if(pchildread) {
	  ret->write_ptr   = pchildread->write_ptr;
          close(pwpd[1]);
	} else {
	ret->write_ptr = fchildread;
	}
      }
    }
    if(how & P_READ) {
      close(prpd[1]);
      fcntl(prpd[0], F_SETFD, FD_CLOEXEC);
      ret->read_ptr = fdopen(prpd[0], "rb");
      if(!ret->read_ptr) {
	int old = errno;
	kill(pid, SIGKILL);

	close(prpd[0]);
	waitpid(pid, 0, 0);
	errno = old;
	free(ret);
        free_args(args);
	return 0;
      }
    }
    free_args(args);
    return ret;
  }
}

pipe_t *
run_cmd(char *cmd, short flags) {
  if(!(flags & P_RW)) {
    flags |= P_READ;
  }
  flags &= ~P_PRIVD; /* Call priv_run_cmd instead. */
  return raw_pipe_open(cmd, flags, 0, 0);
}

pipe_t *
priv_run_cmd(char *cmd, short flags) {
  if(!(flags & P_RW)) {
    flags |= P_READ;
  }
  flags |= P_PRIVD;
  return raw_pipe_open(cmd, flags, 0, 0);
}

pipe_t *
send_file_to_cmd(FILE *f, char *cmd) {
  return raw_pipe_open(cmd, P_RW, 0, f);
}

pipe_t *
send_pipe_to_cmd(pipe_t *p, char *cmd) {
  return raw_pipe_open(cmd, P_RW, p, 0);
}

pipe_t *
priv_send_file_to_cmd(FILE *f, char *cmd) {
  return raw_pipe_open(cmd, P_PRIVD|P_RW, 0, f);
}

pipe_t *
priv_send_pipe_to_cmd(pipe_t *p, char *cmd) {
  return raw_pipe_open(cmd, P_PRIVD|P_RW, p, 0);
}

FILE *
pipe_get_read_file(pipe_t *p) {
  return p->read_ptr;
}

FILE *
pipe_get_write_file(pipe_t *p) {
  return p->write_ptr;
}

int 
pipe_close(pipe_t *p) {
  int status;

  if(!(p->read_ptr || p->write_ptr)) {
    return -1;
  } 

  if(p->read_ptr && fclose(p->read_ptr)) {
    return -1;
  }


  if(p->write_ptr && fclose(p->write_ptr)) {
    return -1;
  }
  if(waitpid(p->pid, &status, 0) != p->pid) {
    return -1;
  }
  p->read_ptr = p->write_ptr = 0; 
   
  return status;
}


#if 0
int main(int argc, char **argv) {
  char buf[1025];
  int n;
  pipe_t *p;

  p = send_pipe_to_cmd(send_pipe_to_cmd(run_cmd("/bin/ps -elf", P_READ), 
					"/bin/grep -v \"ps \\\\-elf\"" ),
		       "/bin/grep -v grep");

  while((n = fread(buf, sizeof(char), 1024, p->read_ptr))) {
    buf[n] = 0;
    fprintf(stderr, "%s", buf);
  }

  /*  fprintf(stderr, "Terminated w/ status %d.\n", pclose(f));*/
  return 0;
}
#endif

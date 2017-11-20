#include "platform.h"
#include "popen.h"
#include "procout.h"

/* TODO: Cap on # of bits per minute? */
#include "egadspriv.h"
#include "eg.h"

#ifndef min
#define min(x, y) (((x) < (y)) ? (x) : (y))
#endif

/* Returns a line, without a \n at the end. */ 

static int
df_cmp(const void *p1, const void *p2) {
  char *s1, *s2;
  s1 = *(char **)p1;
  s2 = *(char **)p2;

  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  return   strcmp(s1, s2);
}

static char **last, **cur;

static int 
df_processes_same(char *s1, char *s2) {
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s1++ != ' ');
  while(*s1 == ' ') s1++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;
  while(*s2++ != ' ');
  while(*s2 == ' ') s2++;

  return strcmp(s1, s2);
}

static void
diff_df_for_entropy() {
  unsigned int   i, j;
  unsigned char  e;
  int            c;
  struct timeval tv;

  i = j = e = 0;


  while(last[i] && cur[j]) {
    c = df_processes_same(last[i], cur[j]);
    if(!c) {
      if(strcmp(last[i], cur[j])) {
	e++;
      }
      i++, j++;
    } else if(c < 1) {
      e++, i++;
    } else {
      e++, j++;
    }
  }
  if(!last[i]) {
    while(cur[j++]) e++;
  } else if(!cur[j]) {
    while(last[i++]) e++;
  }

  gettimeofday(&tv, 0);
  EG_add_entropy(id_list[SRC_CMDS], (unsigned char *)(&tv), sizeof(tv), e/8);
}

void
call_df() {
  pipe_t  *p1;
  char **lines;
  FILE  *f;
  int    i, n;
  
  p1 = run_cmd("/bin/df -i", P_READ); 
  f = pipe_get_read_file(p1);
  if(!(lines = read_lines(f, &n))) {
    pipe_close(p1);
    return;
  }

  pipe_close(p1);

  if (!n) 
  {
    return;
  }

  for(i=1;i<n;i++) {
    EG_add_entropy(id_list[SRC_CMDS], (unsigned char *)lines[i],
		   strlen(lines[i]), 0);
  }

  qsort((void *)(&(lines[1])), n-1, sizeof(char *), df_cmp);


  /*TODO: add lines w/ 0 entropy estimates.*/
	
  if(!cur) {
    cur = lines;
    return;
  } 
  if(last) {
    i = 0;
    while(last[i]) {
      free(last[i++]);
    }
    free(last);
  }
  last = cur;
  cur = lines;

  diff_df_for_entropy();
  return;
}

#if 0
int main() {
  int i;
  for(i=0;i<10;i++)
    call_df();

  return 0;
}
#endif

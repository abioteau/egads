#include "platform.h"
#include "procout.h"

/* Returns a line, without a \n at the end. */
char           *
read_line(FILE * fp)
{
  int             n = 0;
  int             c;
  char           *ret;

  EGADS_ALLOC(ret, sizeof(char) * (BUFSIZ + 1), 0);

  while (((c = fgetc(fp)) != EOF) && (c != '\n'))
  {
    ret[n++] = (char)c;
    if (!(n % BUFSIZ))
    {
      EGADS_REALLOC(ret, sizeof(char) * (n + BUFSIZ + 1));
    }
  }
  if (!n)
  {
    EGADS_FREE(ret);
    return 0;
  }
  ret[n] = 0;
  EGADS_REALLOC(ret, sizeof(char) * (n + 1));

  return ret;
}

char          **
read_lines(FILE * fp, int *x)
{
  char          **ret;
  int             n = 0;

  EGADS_ALLOC(ret, sizeof(char *) * (BUFSIZ + 1), 0);


  while ((ret[n++] = read_line(fp)))
  {
    if (!(n % BUFSIZ))
    {
      EGADS_REALLOC(ret, sizeof(char *) * (n + BUFSIZ + 1));
    }
  }
  if (!n)
  {
    EGADS_FREE(ret);
    *x = 0;
    return 0;
  }
  EGADS_REALLOC(ret, sizeof(char *) * (n + 1));

  *x = n - 1;
  return ret;
}

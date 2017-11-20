#include <stdio.h>

#ifdef WIN32
#include <windows.h>
#include "egads.h.in"
#define EGADS_SOCKET  NULL
#else
#include "egads.h"
#define EGADS_SOCKET  "/usr/local/etc/egads.socket"
#endif

int main(int argc, char **argv)
{
  prngctx_t c;
  unsigned int myuint;
  int error, myint;
  double mydoub;
  char mystr[10];
  char mybuf[1000] = {0};
  int size = 0;

  egads_init(&c, NULL, NULL, &error);
  if (error)
  {
    printf("egads_init: failure: %d\n", error);
    return 1;
  }


 
  /* get a random integer */
  egads_randint(&c, &myuint, &error);
  if (error)
  {
    printf("egads_randint: failure: %d\n", error);
  }
  else
  {
    printf("Random unsigned integer %u\n", myuint);
  }

  /* get a random real between 0 and 1 */
  egads_randreal(&c, &mydoub, &error);
  if (error)
  {
    printf("egads_randreal: failure: %d\n", error);
  }
  else
  {
    printf("Random real %f\n", mydoub);
  }

  /* Get a random integer in a range */
  egads_randrange(&c, &myint, 50, 300, &error);
  if (error)
  {
    printf("egads_randrange: failure: %d\n", error);
  }
  else
  {
    printf("Random integer between 50 and 300 %d\n", myint);
  }

  egads_randrange(&c, &myint, -50, 1000, &error);
  if (error)
  {
    printf("egads_randrange: failure: %d\n", error);
  }
  else
  {
    printf("Random integer between -50 and 1000 %d\n", myint);
  }

  /* Rand strings */ ;
  egads_randstring(&c, mystr, 9, &error);
  if (error)
  {
    printf("egads_randstring: failure: %d\n", error);
  }
  else
  {
    printf("Random printable string %s\n", mystr);
  }

  egads_randfname(&c, mystr, 9, &error);
  if (error)
  {
    printf("egads_randfname: failure: %d\n", error);
  }
  else
  {
    printf("Random filename suitable string %s\n", mystr);
  }

  return 0;
}

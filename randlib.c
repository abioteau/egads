#include "platform.h"

#define PI 3.1415926535

static char *fnametable = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.";

extern char *gather_entropy(int howmuch, eg_t *ctx);

void
free_seedbuf(void *buf)
{
  EGADS_FREE(buf);
}

void
egads_init(prngctx_t * ctx, char *sockname, char *rfile, int *error)
{
  char *myseed = NULL;
  
  if (rfile)
  {
    strncpy(ctx->eg.randfile, rfile, sizeof(ctx->eg.randfile) - 1);
  }
  else
  {
    strncpy(ctx->eg.randfile, "/dev/random", sizeof(ctx->eg.randfile) - 1);
  }
  ctx->eg.randfile[sizeof(ctx->eg.randfile)-1] = 0;

  if (sockname)
  {
    strncpy(ctx->eg.sockname, sockname, sizeof(ctx->eg.sockname) - 1);
  }
  else 
  {
#ifndef WIN32
    strncpy(ctx->eg.sockname, EGADSDATA "/" SOCK_FILE_NAME, sizeof(ctx->eg.sockname) - 1);
#else
    strcpy(ctx->eg.sockname, EGADS_MAILSLOT_NAME);
#endif
  }

  ctx->eg.sockname[sizeof(ctx->eg.sockname)-1] = 0;

  ctx->eg.eg = gather_entropy;
  ctx->eg.egfree = free_seedbuf;
  ctx->eg.gaussstate = 0;

  myseed = gather_entropy(KEY_LEN, &(ctx->eg));
  *error = (myseed ? PRNG_init(ctx, myseed, 300, 0) : RERR_CONNFAILED);
	      
  return;
}

void
egads_destroy(prngctx_t * ctx)
{
  memset(ctx, 0, sizeof(prngctx_t));
}

void
egads_entropy(prngctx_t *ctx, char *buf, int size, int *error)
{
  char *entropy;

  *error = 0;
  if (ctx == NULL)
  {
    *error = RERR_NOHANDLE;
    return;
  }

  entropy = gather_entropy(size, &(ctx->eg));
  if (entropy == NULL)
  {
    *error = RERR_CONNFAILED;
  }
  else
  {
    memcpy(buf, entropy, size);
    EGADS_FREE(entropy);
  }
}

void
egads_randlong(prngctx_t *ctx, long *out, int *error)
{
  *error = 0;
  if (ctx == NULL)
  {
    *error = RERR_NOHANDLE;
    return;
  }

  PRNG_output(ctx, (char *)out, sizeof(long));
}

/* Get a random integer between 0 and UINT_MAX */
void
egads_randint(prngctx_t * ctx, unsigned int *out, int *error)
{
  *error = 0;
  if (ctx == NULL)
  {
    *error = RERR_NOHANDLE;
    return;
  }

  PRNG_output(ctx, (char *)out, sizeof(unsigned int));
}

/* Get a random number (double) between 0 and 1 */
void
egads_randreal(prngctx_t * ctx, double *out, int *error)
{
  unsigned int rado;

  if (ctx == NULL)
  {
    *error = RERR_NOHANDLE;
    return;
  }

  egads_randint(ctx, &rado, error); 
  *out = rado / (double)0xffffffff;
}

void egads_gauss(prngctx_t *ctx, double *out, double mu, double sigma, int *error)
{
  double g2rad, myr, x2pi, z;
  
  *error = 0;
  z = ctx->eg.gaussstate;
  ctx->eg.gaussstate = 0;
  if (!z)
  {
    egads_randreal(ctx, &myr, error);
    x2pi = myr * (PI * 2);
    egads_randreal(ctx, &myr, error);
    g2rad = sqrt(-2.0 * log(1.0 - myr)) ;
    z = cos(x2pi) * g2rad;
    ctx->eg.gaussstate = sin(x2pi) * g2rad;
  }
  *out = mu + z*sigma;
}

void egads_normalvariate(prngctx_t *ctx, double *out, double mu, double sigma, int *error)
{
  double myr1, myr2, t1, t2;
  double myconst = 1.71552776992141;
  
  for (;;)
  {
    egads_randreal(ctx, &myr1, error);
    egads_randreal(ctx, &myr2, error);
    t1 = myconst * (myr1 - 0.5) / myr2;
    t2 = t1 * t1 / 4.0;
    if (t2 <= -log(myr2))
    {
      break;
    }
  }
  *out = mu + t1 * sigma;
}

void egads_lognormalvariate(prngctx_t *ctx, double *out, double mu, double sigma, int *error)
{
  egads_normalvariate(ctx, out, mu, sigma, error);
  *out = exp(*out);
}

void egads_paretovariate(prngctx_t *ctx, double *out, double alpha, int *error)
{
  double myr;

  egads_randreal(ctx, &myr, error);
  *out = 1.0 / pow(myr, 1.0 / alpha);
}

void egads_weibullvariate(prngctx_t *ctx, double *out, double alpha, double beta, int *error)
{
  double myr;
  
  egads_randreal(ctx, &myr, error);
  *out = alpha * pow(-log(myr), 1.0 / beta);
}



/* Random double returned with exponential distribution. lambda 1.0/mean */
void
egads_expovariate(prngctx_t *ctx, double *out, double lambda, int *error)
{
  double myr;

  egads_randreal(ctx, &myr, error);
  while (myr <= 1e-7)
  {
    egads_randreal(ctx, &myr, error);
  }
  *out = (double)(-log(myr) / lambda);
}

/* Returns a range between 0 and 1. alpha > -1 and beta > -1 required */
void
egads_betavariate(prngctx_t *ctx, double *out, double alpha, double beta, int *error)
{
  double myr1, myr2;

  egads_expovariate(ctx, &myr1, alpha, error);
  egads_expovariate(ctx, &myr2, 1.0 / beta, error);
  *out = myr2 / (myr1 + myr2);
}

/* Get a random double with condition min <= out <= max */ 
void
egads_randuniform(prngctx_t *ctx, double *out, double min, double max, int *error)
{
  double myr;

  egads_randreal(ctx, &myr, error); 
  *out = min + (max - min) * myr;
  *error = 0;
  return;
}

void egads_cunifvariate(prngctx_t *ctx, double *out, double mean, double arc, int *error)
{
  double myr;

  egads_randreal(ctx, &myr, error);
  *out = (mean + arc * (myr - 0.5)) / PI;
}

/* Return an integer in [min,max]. min can be negative */
void
egads_randrange(prngctx_t * ctx, int *out, int min, int max, int *error)
{
  unsigned int rado = 0;

  do { 
    egads_randint(ctx, &rado, error);
    /* Throw out rado == UINT_MAX */
  } while(!(~(rado & ~(unsigned int)0)));
  *out = (int)(min + (double)rado *(max - min + 1) / UINT_MAX);
}

/* Generate a random string that can contain any printable character.
   (ASCII 33 through 126) out must be len+1 bytes long, in order to accomodate
   the terminating zero. Caller is responsible for allocating the buffer.
*/
void
egads_randstring(prngctx_t * ctx, char *out, int len, int *error)
{
  int i, tmp;

  *error = 0;
  if (ctx == NULL)
  {
    *error = RERR_NOHANDLE;
    return;
  }

  for (i = 0; i < len; i++)
  {
    egads_randrange(ctx, &tmp, 33, 126, error);
    if (*error)
    {
      break;
    }
    out[i] = (char)tmp;
  }
  out[len - 1] = 0;
}

/* Generate a random string in the range [a-zA-Z0-9] (safe bet for valid 
   filename generation). This function expects
   the destination to already be allocated, and be allocated with enough
   space to hold the string plus a terminating null. The function will
   add the null. (allocate len+1 bytes to the char * you pass in) */
void
egads_randfname(prngctx_t * ctx, char *out, int len, int *error)
{
  int i, tmp;

  *error = 0;
  if (ctx == NULL)
  {
    *error = RERR_NOHANDLE;
    return;
  }

  for (i = 0; i < len; i++)
  {
    egads_randrange(ctx, &tmp, 0, strlen(fnametable) - 1, error);
    if (*error)
    {
      break;
    }
    out[i] = fnametable[tmp];
  }
  out[len - 1] = 0;
}

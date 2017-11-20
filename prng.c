#include "platform.h"
#include "umac.h"

#ifndef WIN32
#include <sys/mman.h> /* mlock() */
#endif

#ifndef NO_THREADS
static pthread_mutex_t liblock = PTHREAD_MUTEX_INITIALIZER;
static struct timeval forkedat;
#endif




static void     internal_output_bytes(prngctx_t * c, char * buf, int length);

static int
lock_memory(void *ptr, size_t size)
{
#ifndef WIN32
  return !mlock(ptr, size);
#else
  return VirtualLock(ptr, size);
#endif
}

static void
self_reseed(prngctx_t * c)
{
  char          new_key[UMAC_KEY_LEN];
  uint64          new_step[2];
  int             i;
  internal_output_bytes(c, new_key, UMAC_KEY_LEN);

  aes_setup(new_key, c->cctx);
  /*umac_delete(c->cctx);
  c->cctx = umac_new(new_key);*/

  internal_output_bytes(c, (char *)new_step, 16);

  for (i = 0; i < 2; i++)
  {
    c->ectr[i] = 0;
    c->step[i] = new_step[i];
  }
}

/* Precondition; seed must be (keylen+blocklen) bytes. 
 * We do not enforce this with checks, we just read from memory.
 */
void
PRNG_rekey(prngctx_t * c, char *seed)
{
  char          new_key[UMAC_KEY_LEN];
  uint64          new_step[2];
  uint64         *stmp;
  int             i, j;

  j = 0;

  internal_output_bytes(c, new_key, UMAC_KEY_LEN);
  
  for (i = 0; i < c->keylen; i++)
  {
    stmp = (uint64 *) (&seed[8 * j++]);
    new_key[i] ^= seed[j++];
  }

  aes_setup(new_key, c->cctx);
  /*umac_delete(c->cctx);
  c->cctx = umac_new(new_key); */
  internal_output_bytes(c, (char *)new_step, 16);

  for (i = 0; i < 2; i++)
  {
    stmp = (uint64 *) (&seed[j]);
    j += 8;
    new_step[i] ^= *stmp;
  }

  for (i = 0; i < 2; i++)
  {
    c->ectr[i] = 0;
    c->step[i] = new_step[i];
  }
  c->step[1] |= long_long_swap((uint64) 1);
}

static int
poll_rekey(prngctx_t * c)
{
  struct timeval tv;

  if (!c->eg.eg)
    return 0;
  gettimeofday(&tv, 0);
  if ((tv.tv_sec > c->target.tv_sec) ||
      ((tv.tv_sec == c->target.tv_sec) && (tv.tv_usec >= c->target.tv_usec)))
  {
    return 1;
  }
  return 0;
}

/* The secret increment is a major pain.  
 * Why can't it just be 1?
 * Counter mode seems fine w/o this secret.
 * Remember, counters are "big endian"... ie, most significant 64 bits first.
 */
static void
increment_counter(prngctx_t * c)
{
  uint64          old;
  int             i, d, j;

  i = 2;
  for (j = 0; j < 2; j++)
  {

    c->ectr[j] = long_long_swap(c->ectr[j]);

    c->step[j] = long_long_swap(c->step[j]);
  }


  while (i--)
  {
    old = c->ectr[i];

    c->ectr[i] += c->step[i];

    if (old > c->ectr[i])
    {
      d = i;

      while (d--)
      {
	if (++c->ectr[d])
	  break;
      }
    }
  }

  for (j = 0; j < 2; j++)
  {

    c->ectr[j] = long_long_swap(c->ectr[j]);
    c->step[j] = long_long_swap(c->step[j]);
  }


}

static void
internal_output_bytes(prngctx_t * c, char *out, int howmuch)
{
  
  int frombuf = 0;
  int outidx = 0;
  char outtmp[AES_BLOCK_LEN] = {0};
  int leftover = 0;
  
  if (c->num_left > 0)
  {
    int ii; 
    if (c->num_left >= howmuch)
    {
      frombuf = howmuch; 
    } else {
      frombuf = c->num_left;
    }

    memcpy(out, c->lptr, frombuf);
    outidx += frombuf;
    c->num_left -= frombuf;
    c->lptr += frombuf;
    howmuch -= frombuf;
    if (c->num_left == 0)
    { 
      c->lptr = c->leftover;
    }
  }
  while (howmuch > 0)
  {
    increment_counter(c);
    c->nonce++;

    aes((char *)c->ectr, outtmp, c->cctx);
    /*umac(c->cctx, (char *)c->ectr, 16, outtmp, (char *)&c->nonce);
    umac_reset(c->cctx);*/

    if (howmuch > AES_BLOCK_LEN)
    {
      frombuf = AES_BLOCK_LEN;
    } else {
      frombuf = howmuch;
      leftover = AES_BLOCK_LEN - howmuch;
    }

      
    memcpy(&out[outidx], outtmp, frombuf);

    outidx += frombuf;
    howmuch -= frombuf;
  }
 

  if (leftover)
  {
    int i;
    memcpy(c->leftover, &outtmp[AES_BLOCK_LEN-leftover], leftover);
    c->num_left = (unsigned short)leftover;
    c->lptr = c->leftover;
  }     
    


  
  c->outputblocks++;
  if(c->outputblocks >= MAXBLOCKRESEED) 
  {
    c->outputblocks = 0;
    self_reseed(c);
  }
  return;
}

void
PRNG_output(prngctx_t * c, char *buf, uint64 size)
{

  pthread_mutex_lock(&liblock);

#ifdef THREAD_USES_NEWPID
#ifndef NO_THREADS
  if ((forkedat.tv_sec > c->seedtime.tv_sec) || ((forkedat.tv_sec == c->seedtime
.tv_sec) && (forkedat.tv_usec > c->seedtime.tv_usec)))
  {
    self_reseed(c);
    gettimeofday(&(c->seedtime), 0);
  }
#endif
#else
  if (c->mypid != getpid())
  {
  /* We've forked, let's reseed */
    self_reseed(c);
    c->mypid = getpid();
  }

#endif

  while (size > GATE_SIZE)
  {
    internal_output_bytes(c, buf, GATE_SIZE);
    buf += GATE_SIZE;
    size -= GATE_SIZE;
    self_reseed(c);
  }
  internal_output_bytes(c, buf, (int)size);
  /*self_reseed(c); */
  if (poll_rekey(c))
  {
    buf = c->eg.eg(c->keylen * 8 + c->blocklen * 8, &(c->eg));

    if (buf)
    {
      /* Not our responsibility to dealloc buf; 
       * may be statically alloced 
       */
      PRNG_rekey(c, buf);
      if (c->eg.egfree) 
      {
        c->eg.egfree(buf);
      }
    }
  }
  pthread_mutex_unlock(&liblock);
}


static void
child_forked()
{
#ifndef NO_THREADS
  gettimeofday(&forkedat, 0);
#endif
}

/* keysize and blocksize are fixed at compile time by the umac type */
int
PRNG_init(prngctx_t * c, char *seed, 
	  long sec, long usec)
{
  int             i;
  char            initial_key[UMAC_KEY_LEN] = { 0 };
  int		  bytes_over;

#ifdef WIN32
  if (!liblock)
    liblock = CreateMutex(NULL, FALSE, NULL);
#endif

  if (!lock_memory(c, sizeof(prngctx_t)))
  {
    fprintf(stderr, "Warning: Using insecure memory.\n");
  }
  pthread_mutex_lock(&liblock);

  gettimeofday(&(c->target), 0);
  c->nonce = c->target.tv_sec;

  c->keylen = UMAC_KEY_LEN; 
  c->blocklen = AES_BLOCK_LEN;
  c->outputblocks = 0;
  aes_setup(initial_key, c->cctx);

  c->rectr = malloc((sizeof(uint64)*2)+16);
  bytes_over = (int)c->rectr & (16 - 1);
  if (bytes_over != 0)
     c->ectr = c->rectr + (16 - bytes_over);
  else
     c->ectr = c->rectr;

  for (i = 0; i < 2; i++)
  {
    c->ectr[i] = 0;
    c->step[i] = 0;
  }
  /* 64-bit blocks treated in "big endian" style. */
  c->step[1] = 1;
  c->num_left = 0;
  c->sec = sec;
  c->usec = usec;

  for (i = 0; i < 2; i++)
  {
    c->ectr[i] = long_long_swap(c->ectr[i]);
    c->step[i] = long_long_swap(c->step[i]);
  }


#ifdef THREAD_USES_NEWPID
#ifndef NO_THREADS
    pthread_atfork(NULL, NULL, child_forked);
    gettimeofday(&(c->seedtime), 0);
#endif
#else
    c->mypid = getpid();
#endif

  PRNG_rekey(c, seed);
  gettimeofday(&(c->target), 0);
  c->target.tv_sec += c->sec;
  c->target.tv_usec += c->usec;
  if (c->target.tv_usec >= 1000000)
  {
	c->target.tv_usec -= 1000000;
	++c->target.tv_sec;
  }
  pthread_mutex_unlock(&liblock);
  return 0;
}

void
PRNG_destroy(prngctx_t * c)
{
  char            seed[UMAC_KEY_LEN] = { 0 };

  PRNG_init(c, seed, 0, 0);
}

#include "platform.h"
#include "umac.h"
#include "eg.h"
#include "sha1.h"

static int estimates[NUM_SOURCES];
static unsigned char umackey[UMAC_KEY_LEN];
static unsigned char outbuf[(BUFSZ*UMAC_OUTPUT_LEN)+1];
static unsigned char *oend;
static unsigned char *ohead;
static unsigned char *otail;
static int sources = 0;
static int octr = 0;
static int keyed = 0;
static umac_ctx_t eg_umac_ctx = NULL;
static uint64 msgid = 0;
static char spool[SPOOL_SIZE];
static int spoolpos = 0;
static int slowthresh = 0;
static int slowcount = 0;
static SHA_CTX shactx;



#ifndef NO_THREADS
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t entready = PTHREAD_COND_INITIALIZER;
#endif

static void
eg_zero_estimates(void)
{
  int i;

  for (i = 0;  i < NUM_SOURCES;  i++)
  {
    estimates[i] = 0;
  }
}

static void
eg_zero_spool(void)
{

  memset(spool, 0, sizeof(spool));
  slowcount = 0;
}

int
EG_register_source()
{
  int rval;

  pthread_mutex_lock(&lock);
  if (sources >= NUM_SOURCES) 
  {
    rval = -1;
  }
  else
  {
    rval = sources++;
  }
  pthread_mutex_unlock(&lock);

  return rval;
}


static void
eg_rekey_with_spool(void)
{

  umac_delete(eg_umac_ctx);
  memcpy(umackey, spool, UMAC_KEY_LEN); 
  memcpy(&msgid, &spool[UMAC_KEY_LEN], sizeof(msgid));
  eg_umac_ctx = umac_new(umackey);
  spoolpos = 0;
  slowcount = 0;
}


static void
check_spool_rekey(void)
{

  if (slowthresh > slowcount) 
    return;

  eg_rekey_with_spool();
  slowthresh *= 2;
  if (slowthresh > SPOOL_THRESH_MAX)
      slowthresh = SPOOL_THRESH_MAX;
  return;  
} 

static void
eg_out_spool(char *data, int length)
{
  int i;

  for (i = 0;  i < length;  i++)
  {
    spool[spoolpos] ^= data[i];
    spoolpos++;
    if (spoolpos >= SPOOL_SIZE)
    {
      spoolpos = 0;
    }
    
  }
  check_spool_rekey();
  slowcount++;
}
      
static int 
eg_buf_full(void)
{
  unsigned char *tmp = ohead + 7;
  unsigned char *ftmp = NULL;

  if (tmp > oend)
  {
    tmp = outbuf + (tmp - (oend + 1));
  }
  
  ftmp = otail + 1;
  if (ftmp > oend)
  {
    ftmp = outbuf;
  }
  
  return (ftmp == ohead);
}

static void
eg_out_buf(char *data, int length)
{
  int tocopy;
  unsigned char *lim;

  if (eg_buf_full())
  {
    return;
  }
  
  if (otail == oend)
  {
    otail = outbuf;
  }
  if (ohead == oend)
  {
    ohead = outbuf;
  }
  
  if (ohead > otail && ohead <= oend)
  {
    lim = ohead;
  }
  else
  {
    lim = oend;
  }

  tocopy = lim - otail;
  if (tocopy > length)
  {
    tocopy = length;
  }
  
  memcpy(otail, data, tocopy);
  otail += tocopy;
  if (otail > oend)
  {
    otail = outbuf;
  }
  
  if (!eg_buf_full() && (length - tocopy > 0))
  {
    eg_out_buf(&data[tocopy], length - tocopy);
  }

  pthread_cond_broadcast(&entready);
}

static int
entropy_available(void)
{
  if (!keyed)
      return 0;

  return (ohead != otail);
}

static int 
eg_fill_entropy(char *out, int howmuch)
{
  int tocopy;
  int ret = 0;
  unsigned char *lim;
  
  if (otail > ohead && otail <= oend) 
  {
    lim = otail;
  }
  else
  {
    lim = oend;
  }

  tocopy = lim-ohead;
  if (tocopy > howmuch)
  {
    tocopy = howmuch;
  }
  memcpy(out, ohead, tocopy);
  ohead += tocopy;
  if (ohead >= oend)
  {
    ohead = outbuf;
  }
  if (otail >= oend)
  {
    otail = outbuf;
  }
  ret += tocopy;
  if (ohead != otail && (howmuch - tocopy > 0))
  {
    ret += eg_fill_entropy(&out[tocopy], howmuch - tocopy);
  }
  return ret;
}

static void
eg_cleanup(void *arg)
{
  pthread_mutex_unlock((pthread_mutex_t *)arg);
}

int 
EG_output(char *out, int howmuch, int block)
{
  int copied = 0;

  pthread_mutex_lock(&lock);
#ifdef NO_THREADS
  if (!entropy_available())
  {
    pthread_mutex_unlock(&lock);
    return 0;
  }
  
  return eg_fill_entropy(out, howmuch);
#else
  do
  {
    if (block && !entropy_available())
    {
      pthread_cleanup_push(eg_cleanup, &lock);
      pthread_cond_wait(&entready, &lock);
      pthread_cleanup_pop(0);
    }
    copied += eg_fill_entropy(&out[copied], howmuch - copied);
  } 
  while (block && copied < howmuch);
#endif
  pthread_mutex_unlock(&lock);
  return copied;
}

static void
eg_do_output(void)
{
  char umacout[UMAC_OUTPUT_LEN];

  umac_final(eg_umac_ctx, umacout, (unsigned char *)(&msgid));
  umac_reset(eg_umac_ctx);

  octr++;
  if (octr > EPOOL_OUTD)
  {
    octr = 1;
  }


  if (!keyed || eg_buf_full() || (octr > EPOOL_OUTD-EPOOL_OUTN))
  {
    eg_out_spool(umacout, UMAC_OUTPUT_LEN);
  }
  else
  {
    eg_out_buf(umacout, UMAC_OUTPUT_LEN);
  }
  eg_zero_estimates();
  msgid++;
  
}

static int
cmpint(const void *p1, const void *p2)
{
  int i1 = *((int *)p1), i2 = *((int *)p2);

  return (i1 > i2 ? -1 : (i1 < i2 ? 1 : 0));
}

static int
eg_compute_elevel()
{
  int i;
  int estcpy[NUM_SOURCES];
  int totale = 0;

  memcpy(estcpy, estimates, NUM_SOURCES * sizeof(int));
  qsort((void *)estcpy, NUM_SOURCES, sizeof(int), cmpint);

  for (i = 0;  i < sources;  i++)
  {
    totale += estimates[i];
  }
  for (i = 0;  i < NUM_COMP_SRCS;  i++)
  {
    totale -= estcpy[i];
  }

  return totale;
}
 
static int
eg_output_ready()
{
  int totale;
  totale = eg_compute_elevel();

  return (totale > UMAC_OUTPUT_LEN * 8);
}

double
EG_entropy_level()
{
  double ret;
  int totale;

  pthread_mutex_lock(&lock);
  if (keyed && entropy_available())
  {
    ret = 1.0;
  }
  else
  {
    totale = eg_compute_elevel();
    ret = (double)totale / (UMAC_OUTPUT_LEN * 8);
  }
  pthread_mutex_unlock(&lock);
  return ret;
}

#define ROTATE(x) ((x) % EPOOLSZ)   /* Convenient abreviation */

/*
static void
eg_mix_entropy(unsigned char *entropy, size_t len)
{
  size_t i;

  for (i = 0;  i < len;  i++)
  {
    epool[pix] ^= entropy[i] ^ epool[ROTATE(pix+TAP1)] ^ 
      epool[ROTATE(pix+TAP2)] ^ epool[ROTATE(pix+TAP3)] ^
      epool[ROTATE(pix+TAP4)] ^ epool[ROTATE(pix+TAP5)];
    pix--;
    if (pix < 0)
    {
      pix = EPOOLSZ - 1;
    }
  }
}
*/

static void
eg_mix_entropy(unsigned char *entropy, size_t len)
{

    /* TODO: does this need the alignment silliness too? */
    umac_update(eg_umac_ctx, entropy, len);
}

 

void 
eg_startup_data(unsigned char *ent, size_t len)
{
    SHAUpdate(&shactx, ent, len);
}

        
void
EG_startup_done(void)
{

  unsigned char shaout[20] = {0};
  SHAUpdate(&shactx, umackey, UMAC_KEY_LEN);
  SHAFinal(shaout, &shactx);
  

  if (UMAC_KEY_LEN > 20)
  {
      memcpy(umackey, shaout, 20);
  } else {
      memcpy(umackey, shaout, UMAC_KEY_LEN);
      memcpy(&msgid, &shaout[UMAC_KEY_LEN],  20 - UMAC_KEY_LEN);
  }

  if (eg_umac_ctx != NULL)
  {
      umac_delete(eg_umac_ctx);
  }
  
  eg_umac_ctx = umac_new(umackey);
  keyed = 1;

  return;
}

int
EG_add_entropy(int srcnum, unsigned char *ent, int len,  int est)
{
  pthread_mutex_lock(&lock);
  if (srcnum < 0 || srcnum >= NUM_SOURCES)
  {
    pthread_mutex_unlock(&lock);
    return -1;
  }


  if (!keyed)  
  {
      eg_startup_data(ent, len);
      pthread_mutex_unlock(&lock);
      return 1;
  }

  estimates[srcnum] += est;
  if (estimates[srcnum] > 70)
  {
    estimates[srcnum] = 70;
  }
  eg_mix_entropy(ent, len);

  if (eg_output_ready())
  {
    eg_do_output();
  }
  pthread_mutex_unlock(&lock);
  return 1;
}

int
EG_save_state(FILE *saveto)
{

  pthread_mutex_lock(&lock);
  fwrite(umackey, sizeof(char), UMAC_KEY_LEN, saveto);
  pthread_mutex_unlock(&lock);

  return 1;
}

int
EG_restore_state(FILE *from)
{

  pthread_mutex_lock(&lock);
  fread(umackey, sizeof(char), UMAC_KEY_LEN, from);
  pthread_mutex_unlock(&lock);

  return 1;
}

int
EG_init()
{
#ifdef WIN32
  lock = CreateMutex(NULL, TRUE, NULL);
  entready = CreateEvent(NULL, TRUE, FALSE, NULL);
#else
  pthread_mutex_lock(&lock);
#endif

  sources = 0;
  keyed = 0;
  eg_zero_estimates();
  eg_umac_ctx = umac_new(umackey);
  slowthresh = SPOOL_THRESH_START;
  /* TODO: Hash based startup and such */
  oend = &outbuf[(BUFSZ * UMAC_OUTPUT_LEN)];
  ohead = outbuf;
  otail = outbuf;  
  eg_zero_spool();
  pthread_mutex_unlock(&lock);
  return 1;
}

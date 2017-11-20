#include "platform.h"

static
char *devrandom_fallback(int howmuch, eg_t* ctx)
{
  int fd, nb;
  char *path, *outbuf;

  printf("DEVRANDOM FALLBACK\n");
  path = EGADS_STRDUP((ctx->randfile ? ctx->randfile : "/dev/random"));

  if ((fd = open(path, O_RDONLY)) == -1)
  {
    EGADS_FREE(path);
    return NULL;
  }

  EGADS_ALLOC(outbuf, howmuch, 0);
  nb = EGADS_read(fd, outbuf, howmuch);
  close(fd);

  if (!nb)
  {
    EGADS_FREE(outbuf);
    return NULL;
  }
    
  return outbuf;
}

#define EGADS_SOCKET_NAME EGADSDATA "/" SOCK_FILE_NAME

char *gather_entropy(int howmuch, eg_t *ctx)
{
  int fd, nb;
  char cmdbuf[sizeof(int) + 1], *buffer;
  struct sockaddr_un sa;

  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path, (ctx->sockname ? ctx->sockname : EGADS_SOCKET_NAME),
          sizeof(sa.sun_path) - 1);
  sa.sun_path[sizeof(sa.sun_path) - 1] = '\0';

  if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
  {
    return devrandom_fallback(howmuch, ctx);
  }

  if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
  {
    close(fd);
    return devrandom_fallback(howmuch, ctx);
  }

  cmdbuf[0] = ECMD_REQ_ENTROPY;
  memcpy(&cmdbuf[1], &howmuch, sizeof(int));

  if (!EGADS_write(fd, cmdbuf, sizeof(cmdbuf)))
  {
    close(fd);
    return devrandom_fallback(howmuch, ctx);
  }

  EGADS_ALLOC(buffer, howmuch, 0);
  nb = EGADS_read(fd, buffer, howmuch);
  close(fd);

  if (!nb)
  {
    EGADS_FREE(buffer);
    return devrandom_fallback(howmuch, ctx);
  }
  return buffer;
}

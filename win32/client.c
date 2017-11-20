#include "../platform.h"

char *
gather_entropy(int howmuch, eg_t *ctx)
{
  int cbTotal;
  char name[PATH_MAX], *buffer;
  DWORD cbWritten, cbRead;
  HANDLE hMailslot, hReadPipe, hWritePipe;
  egads_request_t request;

  /* Create an anonymous pipe that'll be used for obtaining the entropy from
   * the entropy server
   */
  if (!CreatePipe(&hReadPipe, &hWritePipe, NULL, howmuch))
  {
    return NULL;
  }

  /* Establish a connection to the server's mailslot.  We'll use this IPC
   * mechanism to send our request.  Included with our request is our own
   * process id, the handle to the write pipe, the request code and how much
   * entropy we'd like.
   */
  strcpy(name, "\\\\.\\mailslot\\");
  if (ctx->sockname != NULL)
  {
    strncat(name, ctx->sockname, sizeof(name) - strlen(name) - 1);
  }
  else
  {
    strncat(name, EGADS_MAILSLOT_NAME, sizeof(name) - strlen(name) - 1);
  }
  name[sizeof(name) - 1] = '\0';

  hMailslot = CreateFile(name, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hMailslot == INVALID_HANDLE_VALUE)
  {
    CloseHandle(hWritePipe);
    CloseHandle(hReadPipe);
    return NULL;
  }

  /* Build the request packet and send it ... */
  request.cmd = ECMD_REQ_ENTROPY;
  request.howmuch = howmuch;
  request.dwProcessId = GetCurrentProcessId();
  request.hWritePipe = hWritePipe;

  if (!WriteFile(hMailslot, &request, sizeof(request), &cbWritten, NULL))
  {
    CloseHandle(hMailslot);
    CloseHandle(hWritePipe);
    CloseHandle(hReadPipe);
    return NULL;
  }

  CloseHandle(hMailslot);

  /* Now we wait for the request to be fulfilled by the server.  We'll wait
   * indefinitely, or if an error occurs we'll bail out.
   */
  EGADS_ALLOC(buffer, howmuch, 0);
  for (cbTotal = 0;  cbTotal < howmuch;  cbTotal = cbTotal + cbRead)
  {
    if (!ReadFile(hReadPipe, buffer + cbTotal, howmuch - cbTotal, &cbRead, NULL))
    {
      EGADS_FREE(buffer);
      CloseHandle(hWritePipe);
      CloseHandle(hReadPipe);
      return NULL;
    }
  }

  /* All done.  Cleanup the pipe and return the buffer */
  CloseHandle(hWritePipe);
  CloseHandle(hReadPipe);

  return buffer;
}

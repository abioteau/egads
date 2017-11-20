#include "../platform.h"
#include "../eg.h"

#define EGADS_SERVICE_NAME  TEXT("EGADS")

static HANDLE hShutdownEvent, hMutex, hAsyncEvent;
static HANDLE hEntropyThread, hMailslot = INVALID_HANDLE_VALUE;
static OVERLAPPED async;
static SERVICE_STATUS svc;
static egads_request_t request;
static SERVICE_STATUS_HANDLE hServiceHandle;

extern DWORD WINAPI EntropyThread(LPVOID lpParameter);

static
DWORD report_error(LPCTSTR fn)
{
  TCHAR buffer[1024];
  DWORD dwError;

  dwError = GetLastError();
  wsprintf(buffer, "[EGADS] %s error = %d\r\n", fn, dwError);
  OutputDebugString(buffer);

  return dwError;
}

static
DWORD EGADS_ServiceInit(DWORD argc, LPSTR *argv)
{
  char name[PATH_MAX];
  SECURITY_ATTRIBUTES attr;
  SECURITY_DESCRIPTOR desc;

  SetServiceStatus(hServiceHandle, &svc);

  if (!(hShutdownEvent = CreateEvent(NULL, FALSE, FALSE, NULL)))
  {
    return report_error(TEXT("CreateEvent (hShutdownEvent)"));
  }
  if (!(hMutex = CreateMutex(NULL, FALSE, NULL)))
  {
    return report_error(TEXT("CreateMutex"));
  }
  if (!(hAsyncEvent = CreateEvent(NULL, FALSE, FALSE, NULL)))
  {
    return report_error(TEXT("CreateEvent (hAsyncEvent)"));
  }

  lstrcpy(name, TEXT("\\\\.\\mailslot\\"));
  strncat(name, EGADS_MAILSLOT_NAME, sizeof(name) - strlen(name) - 1);
  name[sizeof(name) - 1] = '\0';

  attr.nLength = sizeof(SECURITY_ATTRIBUTES);
  attr.lpSecurityDescriptor = &desc;
  attr.bInheritHandle = FALSE;
  InitializeSecurityDescriptor(&desc, SECURITY_DESCRIPTOR_REVISION);
  SetSecurityDescriptorDacl(&desc, TRUE, NULL, FALSE);

  hMailslot = CreateMailslot(name, sizeof(egads_request_t), MAILSLOT_WAIT_FOREVER, &attr);
  if (hMailslot == INVALID_HANDLE_VALUE)
  {
    return report_error(TEXT("CreateMailslot"));
  }

  if (!(hEntropyThread = CreateThread(NULL, 0, EntropyThread, (LPVOID)hShutdownEvent, 0, NULL)))
  {
    return report_error(TEXT("CreateThread"));
  }

  return NO_ERROR;
}

static
void EGADS_ServiceCleanup(void)
{
  if (hEntropyThread)
  {
    if (svc.dwCurrentState != SERVICE_STOP_PENDING)
    {
      WaitForSingleObject(hEntropyThread, INFINITE);
      hEntropyThread = NULL;
    }
    else
    {
      DWORD dwEndCheckPoint;

      svc.dwWaitHint = 500;
      dwEndCheckPoint = svc.dwCheckPoint + 20;
      SetServiceStatus(hServiceHandle, &svc);
      while (WaitForSingleObject(hEntropyThread, 500) == WAIT_TIMEOUT)
      {
        if (svc.dwCheckPoint++ == dwEndCheckPoint)
        {
          /* Stop waiting, the thread'll get killed when the main thread
           * exits.  We can't wait forever here because the system could
           * be shutting down and we'd end up preventing that from happening
           * if the thread never actually shutdown normally.
           */
          break;
        }
        SetServiceStatus(hServiceHandle, &svc);
      }
      hEntropyThread = NULL;
    }
  }
  if (hMailslot != INVALID_HANDLE_VALUE)
  {
    CloseHandle(hMailslot);
    hMailslot = INVALID_HANDLE_VALUE;
  }
  if (hAsyncEvent)
  {
    CloseHandle(hAsyncEvent);
    hAsyncEvent = NULL;
  }
  if (hMutex)
  {
    CloseHandle(hMutex);
    hMutex = NULL;
  }
  if (hShutdownEvent)
  {
    CloseHandle(hShutdownEvent);
    hShutdownEvent = NULL;
  }

  svc.dwCurrentState = SERVICE_STOPPED;
  svc.dwCheckPoint   = 0;
  svc.dwWaitHint     = 0;

  SetServiceStatus(hServiceHandle, &svc);
}

static
void EGADS_ServiceRequest(void)
{
  int cbTotal;
  char *buffer;
  DWORD cbBytes, cbWritten;
  HANDLE hProcess, hWritePipe;

  if (!GetOverlappedResult(hMailslot, &async, &cbBytes, FALSE))
  {
    report_error("GetOverlappedResult");
    return;
  }
  if (cbBytes != sizeof(request) || request.cmd != ECMD_REQ_ENTROPY)
  {
    return;
  }

  if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, request.dwProcessId)))
  {
    report_error("OpenProcess");
    return;
  }

  if (!DuplicateHandle(hProcess, request.hWritePipe, GetCurrentProcess(),
                       &hWritePipe, 0, FALSE, DUPLICATE_SAME_ACCESS))
  {
    report_error("DuplicateHandle");
    CloseHandle(hProcess);
    return;
  }

  EGADS_ALLOC(buffer, request.howmuch, 0);
  EG_output(buffer, request.howmuch, 1);

  for (cbTotal = 0;  cbTotal < request.howmuch;  cbTotal += cbWritten)
  {
    if (!WriteFile(hWritePipe, buffer + cbTotal, request.howmuch - cbTotal,
                   &cbWritten, NULL))
    {
      report_error("WriteFile");
      break;
    }
  }

  EGADS_FREE(buffer);
  CloseHandle(hWritePipe);
  CloseHandle(hProcess);
}

static
void EGADS_ServiceRun(void)
{
  BOOL bShutdown = FALSE;

  svc.dwCurrentState = SERVICE_RUNNING;
  svc.dwCheckPoint   = 0;
  svc.dwWaitHint     = 0;

  SetServiceStatus(hServiceHandle, &svc);

  while (!bShutdown)
  {
    DWORD rc;
    HANDLE handles[] = { hShutdownEvent, hAsyncEvent };

    /* NOTE: The ordering of the event handles in the above array is important.
     * If both events are signaled before WaitForMultipleObjects() returns, the
     * lower indexed one will be returned.  We want to be able to shutdown as
     * quickly as possible, so give the shutdown event priority.
     */

    async.Internal = async.InternalHigh = 0;
    async.Offset = async.OffsetHigh = 0;
    async.hEvent = hAsyncEvent;

    ResetEvent(hAsyncEvent);
    ReadFile(hMailslot, &request, sizeof(request), NULL, &async);

    rc = WaitForMultipleObjectsEx(sizeof(handles) / sizeof(HANDLE), handles,
                                  FALSE, INFINITE, TRUE);
    if (rc == WAIT_OBJECT_0)
    {
      bShutdown = TRUE;
    }
    else if (rc == WAIT_OBJECT_0 + 1)
    {
      EGADS_ServiceRequest();
    }
  }

  WaitForSingleObject(hMutex, INFINITE);
}

static
void WINAPI EGADS_ServiceHandler(DWORD cmd)
{
  WaitForSingleObject(hMutex, INFINITE);

  switch (cmd)
  {
    case SERVICE_CONTROL_PAUSE:
      /* This command is not actually supported, it's here for completeness */
      svc.dwCurrentState = SERVICE_PAUSED;
      break;

    case SERVICE_CONTROL_CONTINUE:
      /* This command is not actually supported, it's here for completeness */
      svc.dwCurrentState = SERVICE_RUNNING;
      break;

    case SERVICE_CONTROL_SHUTDOWN:
    case SERVICE_CONTROL_STOP:
      /* FIXME: This command shuts everything down */
      svc.dwCurrentState = SERVICE_STOP_PENDING;
      svc.dwCheckPoint = 0;
      svc.dwWaitHint = 1000;
      SetEvent(hShutdownEvent);
      break;

    case SERVICE_CONTROL_INTERROGATE:
      /* This really doesn't do anything, basically just forces us to call
       * SetServiceStatus() which we'll do when we fall out of the switch.
       */
      break;
  }

  SetServiceStatus(hServiceHandle, &svc);
  ReleaseMutex(hMutex);
}

static
void WINAPI EGADS_ServiceStart(DWORD argc, LPSTR *argv)
{
  DWORD rc;

  svc.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
  svc.dwCurrentState            = SERVICE_START_PENDING;
  svc.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  svc.dwWin32ExitCode           = NO_ERROR;
  svc.dwServiceSpecificExitCode = 0;
  svc.dwCheckPoint              = 0;
  svc.dwWaitHint                = 1000;

  hServiceHandle = RegisterServiceCtrlHandler(EGADS_SERVICE_NAME, EGADS_ServiceHandler);
  if (!hServiceHandle)
  {
    report_error(TEXT("RegisterServiceCtrlHandler"));
    return;
  }

  if ((rc = EGADS_ServiceInit(argc, argv)) != NO_ERROR)
  {
    svc.dwWin32ExitCode           = ERROR_SERVICE_SPECIFIC_ERROR;
    svc.dwServiceSpecificExitCode = rc;

    EGADS_ServiceCleanup();
    return;
  }

  EGADS_ServiceRun();

  EGADS_ServiceCleanup();
}

int main(int argc, char **argv)
{
  SERVICE_TABLE_ENTRY DispatchTable[] =
  {
    { EGADS_SERVICE_NAME, EGADS_ServiceStart },
    { NULL,               NULL               }
  };

  if (!StartServiceCtrlDispatcher(DispatchTable))
  {
    report_error(TEXT("StartServiceCtrlDispatcher"));
  }

  return 0;
}

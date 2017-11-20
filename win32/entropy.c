#include "../platform.h"
#include "../eg.h"

#include <pdh.h>
#include <pdhmsg.h>

static int handlec;
static HCOUNTER *handlev;

static int id_list[NUM_SOURCES];
static int delay = 1;

static int estimates[] =
{
  2,  /* sched timing    */
  3,  /* thread timing   */
  2,  /* pdh information */
};

static
void save_handle(HCOUNTER handle)
{
  if (!(handlec % 1024))
    EGADS_REALLOC(handlev, sizeof(HCOUNTER) * (handlec + 1024));
  handlev[handlec++] = handle;
}

static
void timestamp(int sid)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);
  EG_add_entropy(id_list[sid], (unsigned char *)&tv, sizeof(tv), estimates[sid]);
}

static
uint32 diff_usec(struct timeval *start, struct timeval *end)
{
  if (end->tv_usec < start->tv_usec)
  {
    return 1000000 - start->tv_usec + end->tv_usec;
  }
  return end->tv_usec - start->tv_usec;
}

static
void SchedTiming(void)
{
  int i;
  uint32 diff;
  struct timeval start, end;

  gettimeofday(&start, NULL);
  for (i = 0;  i < SCHED_ITERS;  i++)
  {
    Sleep(0);
  }
  gettimeofday(&end, NULL);

  diff = diff_usec(&start, &end);
  EG_add_entropy(id_list[SRC_SCHED], (unsigned char *)&diff, sizeof(diff), 0);
  timestamp(SRC_SCHED);
}

static
void DestroyPdhQuery(HQUERY *hQuery)
{
  if (*hQuery != NULL)
  {
    int i;

    for (i = 0;  i < handlec;  PdhRemoveCounter(handlev[i++]));
    PdhCloseQuery(*hQuery);
    *hQuery = NULL;
  }
}

static
void CreatePdhQuery(HQUERY *hQuery)
{
  DWORD dwSize, dwCounterSize, dwInstanceSize, dwPathSize;
  LPTSTR szObject, szObjects, szCounter, szCounters, szPath;
  LPTSTR szInstance, szInstances;
  HCOUNTER hCounter;
  PDH_COUNTER_PATH_ELEMENTS e;
  PDH_STATUS rc;

  if (PdhOpenQuery(NULL, 0L, hQuery) != ERROR_SUCCESS)
  {
    *hQuery = NULL;
    return;
  }

  dwSize = 0;
  rc = PdhEnumObjects(NULL, NULL, NULL, &dwSize, PERF_DETAIL_WIZARD, FALSE);
  if (rc != ERROR_SUCCESS && rc != PDH_MORE_DATA)
  {
    DestroyPdhQuery(hQuery);
    return;
  }

  EGADS_ALLOC(szObjects, sizeof(TCHAR) * dwSize, 0);
  if (PdhEnumObjects(NULL, NULL, szObjects, &dwSize, PERF_DETAIL_WIZARD, FALSE) != ERROR_SUCCESS)
  {
    EGADS_FREE(szObjects);
    DestroyPdhQuery(hQuery);
    return;
  }

  e.szMachineName = NULL;
  e.szParentInstance = NULL;
  e.dwInstanceIndex = -1;

  for (szObject = szObjects;  *szObject;  szObject += lstrlen(szObject) + 1)
  {
    dwCounterSize = dwInstanceSize = 0;
    rc = PdhEnumObjectItems(NULL, NULL, szObject, NULL, &dwCounterSize,
                            NULL, &dwInstanceSize, PERF_DETAIL_WIZARD, 0);
    if (rc != ERROR_SUCCESS && rc != PDH_MORE_DATA)
    {
      EGADS_FREE(szObjects);
      DestroyPdhQuery(hQuery);
      return;
    }

    if (dwInstanceSize <= 0)
    {
      continue;
    }

    EGADS_ALLOC(szCounters, sizeof(TCHAR) * dwCounterSize, 0);
    EGADS_ALLOC(szInstances, sizeof(TCHAR) * dwInstanceSize, 0);
    if (PdhEnumObjectItems(NULL, NULL, szObject, szCounters, &dwCounterSize,
                           szInstances, &dwInstanceSize, PERF_DETAIL_WIZARD, 0) != ERROR_SUCCESS)
    {
      EGADS_FREE(szInstances);
      EGADS_FREE(szCounters);
      EGADS_FREE(szObjects);
      DestroyPdhQuery(hQuery);
      return;
    }

    e.szObjectName = szObject;
    for (szInstance = szInstances;  *szInstance;  szInstance += lstrlen(szInstance) + 1)
    {
      e.szInstanceName = szInstance;
      for (szCounter = szCounters;  *szCounter;  szCounter += lstrlen(szCounter) + 1)
      {
        e.szCounterName = szCounter;

        dwPathSize = 0;
        rc = PdhMakeCounterPath(&e, NULL, &dwPathSize, 0);
        if (rc != ERROR_SUCCESS && rc != PDH_MORE_DATA)
        {
          continue;
        }

        EGADS_ALLOC(szPath, sizeof(TCHAR) * dwPathSize, 0);
        if (PdhMakeCounterPath(&e, szPath, &dwPathSize, 0) != ERROR_SUCCESS)
        {
          EGADS_FREE(szPath);
          continue;
        }

        if (PdhAddCounter(*hQuery, szPath, 0, &hCounter) == ERROR_SUCCESS)
        {
          save_handle(hCounter);
        }
        EGADS_FREE(szPath);
      }
    }

    EGADS_FREE(szInstances);
    EGADS_FREE(szCounters);
  }

  EGADS_FREE(szObjects);
}

static
void CollectPdhData(HQUERY hQuery)
{
  if (hQuery != NULL && PdhCollectQueryData(hQuery) == ERROR_SUCCESS)
  {
    int i;
    PDH_RAW_COUNTER value;

    for (i = 0;  i < handlec;  i++)
    {
      if (PdhGetRawCounterValue(handlev[i], NULL, &value) == ERROR_SUCCESS)
      {
        EG_add_entropy(SRC_PDH, (unsigned char *)&(value.FirstValue),
                       sizeof(value.FirstValue), estimates[SRC_PDH]);
      }
    }

    timestamp(SRC_PDH);
  }
}

DWORD WINAPI EntropyThread(LPVOID lpParameter)
{
  int done = 0, i;
  char path[MAX_PATH];
  FILE *fd;
  DWORD dwCounter = 0;
  HANDLE hShutdownEvent = (HANDLE)lpParameter;
  HQUERY hQuery;

  /* Initialize the path of the seed file */
  GetWindowsDirectory(path, sizeof(path));
  strcat(path, "\\egads.dat");

  CreatePdhQuery(&hQuery);
  EG_init();
  if ((fd = fopen(path, "r")) != NULL)
  {
    EG_restore_state(fd);
    fclose(fd);
  }
  for (i = 0;  i < NUM_SOURCES;  i++)
  {
    id_list[i] = EG_register_source();
  }

  for (;;)
  {
    SchedTiming();
    if (!(++dwCounter % 10))
    {
      CollectPdhData(hQuery);
    }
    if (!done)
    {
      EG_startup_done();
      done = 1;
    }

    if (EG_entropy_level() >= 1.0)
    {
      if (WaitForSingleObject(hShutdownEvent, delay * 1000) != WAIT_TIMEOUT)
      {
        break;
      }
    }
  }

  if ((fd = fopen(path, "w+")) != NULL)
  {
    EG_save_state(fd);
    fclose(fd);
  }
  DestroyPdhQuery(&hQuery);

  return 0;
}

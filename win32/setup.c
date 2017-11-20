/*
 * setup.c
 * 2-Sep-2001, Matt Messier @ Secure Software, Inc.
 *
 * This is the installer for EGADS.  This single source file builds into
 * setup.exe which the user runs to install the product.  Its companion,
 * unsetup.c, is the uninstaller.
 *
 * This program is responsible for displaying the licensing agreement to the
 * user and determining agreement, prompting for an installation location,
 * copying the distribution files to their proper location, registering the
 * EGADS service, and populating the registry with uninstall information.
 */
#include <windows.h>
#include <sys/stat.h>

#include "resource.h"

#define WM_UPDATE_PATH  WM_USER + 0x0100

typedef BOOL (* LPCHANGESERVICECONFIG2)(SC_HANDLE, DWORD, LPVOID);

static TCHAR location[MAX_PATH + 1];
static HINSTANCE instance;

/* This is the list of files to install into the installation directory.
 * Note that EGADS.EXE and EGADS.DLL need to be placed into the Windows
 * installation structure, so they are not included here.  On NT 4.0
 * systems, PDH.DLL is also copied here.
 */
static LPTSTR packing_list[] =
{
  "setup.exe",    /* THIS EXECUTABLE MUST BE FIRST IN THE LIST */
  "license.txt",
  "README",
  "egads.lib",
  "egads.h",
  NULL
};

static
int messageBox(HWND hwnd, UINT textID, UINT captionID, UINT type)
{
  TCHAR caption[256], text[256];

  LoadString(instance, textID, text, sizeof(text));
  LoadString(instance, captionID, caption, sizeof(caption));
  return MessageBox(hwnd, text, caption, type);
}

static
BOOL addRemovePrograms(void)
{
  HKEY subkey, uninstall;
  DWORD dwDisposition;
  TCHAR name[256], buffer[MAX_PATH + 24];

  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"), 0, KEY_WRITE, &uninstall) != ERROR_SUCCESS)
  {
    return FALSE;
  }

  lstrcpy(name, TEXT("egads"));
  if (RegCreateKeyEx(uninstall, name, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &subkey, &dwDisposition) != ERROR_SUCCESS)
  {
    RegCloseKey(uninstall);
    return FALSE;
  }

  wsprintf(buffer, TEXT("\"%s\\setup.exe\" /uninstall"), location);

  RegSetValueEx(subkey, TEXT("DisplayName"), 0, REG_SZ, (CONST BYTE *)name, lstrlen(name) + 1);
  RegSetValueEx(subkey, TEXT("InstallLocation"), 0, REG_SZ, (CONST BYTE *)location, lstrlen(location) + 1);
  RegSetValueEx(subkey, TEXT("UninstallString"), 0, REG_SZ, (CONST BYTE *)buffer, lstrlen(buffer) + 1);

  RegCloseKey(subkey);
  RegCloseKey(uninstall);

  return TRUE;
}

static
BOOL registerService(void)
{
  DWORD dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl;
  SC_HANDLE mgr, svc;
  TCHAR description[256], path[MAX_PATH + 1];
  SERVICE_DESCRIPTION desc;
  HINSTANCE hAdvAPI;
  LPCHANGESERVICECONFIG2 ChangeServiceConfig2 = NULL;

  hAdvAPI = LoadLibrary(TEXT("advapi32.dll"));
  if (hAdvAPI)
  {
    ChangeServiceConfig2 = (LPCHANGESERVICECONFIG2)GetProcAddress(hAdvAPI, "ChangeServiceConfig2");
  }

  /* When testing is complete and everything works, dwStartType should be
   * changed to SERVICE_AUTO_START so that EGADS will start when the system
   * boots.
   */
  dwDesiredAccess = STANDARD_RIGHTS_REQUIRED | SERVICE_CHANGE_CONFIG | SERVICE_START;
  dwServiceType = SERVICE_WIN32_OWN_PROCESS;
#ifdef _DEBUG
  dwStartType = SERVICE_DEMAND_START;
#else
  dwStartType = SERVICE_AUTO_START;
#endif
  dwErrorControl = SERVICE_ERROR_NORMAL;

  GetWindowsDirectory(path, sizeof(path));
  lstrcat(path, TEXT("\\system32\\egads.exe"));

  if (!(mgr = OpenSCManager(NULL, NULL, GENERIC_WRITE)))
  {
    if (hAdvAPI)
    {
      FreeLibrary((HMODULE)hAdvAPI);
    }
    return FALSE;
  }

  if (!ChangeServiceConfig2)
  {
    LoadString(instance, IDS_SERVICE_DESCRIPTION, description, sizeof(description));
    svc = CreateService(mgr, TEXT("egads"), description, dwDesiredAccess,
                        dwServiceType, dwStartType, dwErrorControl,
                        path, NULL, NULL, NULL, NULL, NULL);
  }
  else
  {
    svc = CreateService(mgr, TEXT("egads"), TEXT("EGADS"), dwDesiredAccess,
                        dwServiceType, dwStartType, dwErrorControl,
                        path, NULL, NULL, NULL, NULL, NULL);
  }

  if (!svc)
  {
    if (hAdvAPI)
    {
      FreeLibrary((HMODULE)hAdvAPI);
    }
    CloseServiceHandle(mgr);
    return FALSE;
  }

  if (ChangeServiceConfig2)
  {
    LoadString(instance, IDS_SERVICE_DESCRIPTION, description, sizeof(description));
    desc.lpDescription = description;
    ChangeServiceConfig2(svc, SERVICE_CONFIG_DESCRIPTION, &desc);
  }
  if (hAdvAPI)
  {
    FreeLibrary(hAdvAPI);
  }

#ifndef _DEBUG
  if (StartService(svc, 0, NULL))
  {
    DWORD dwCheckPoint;
    SERVICE_STATUS status;

    if (QueryServiceStatus(svc, &status))
    {
      while (status.dwCurrentState == SERVICE_START_PENDING)
      {
        dwCheckPoint = status.dwCheckPoint;
        Sleep((status.dwWaitHint ? status.dwWaitHint : 500));
        if (!QueryServiceStatus(svc, &status))
        {
          break;
        }
        if (status.dwCheckPoint == dwCheckPoint)
        {
          break;
        }
      }
    }
  }
#endif

  CloseServiceHandle(svc);
  CloseServiceHandle(mgr);
  return TRUE;
}

static
BOOL unregisterService(UINT *error)
{
  BOOL result;
  SC_HANDLE mgr, svc;
  SERVICE_STATUS status;

  if (!(mgr = OpenSCManager(NULL, NULL, GENERIC_WRITE)))
  {
    *error = IDS_UNINSTALL_SERVICE_MANAGER;
    return FALSE;
  }

  if (!(svc = OpenService(mgr, TEXT("egads"), SERVICE_ALL_ACCESS)))
  {
    *error = IDS_UNINSTALL_SERVICE_OPEN;
    CloseServiceHandle(mgr);
    /* Service could be non-existant, so don't fail, our job is already done */
    return (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST);
  }

  if (!ControlService(svc, SERVICE_CONTROL_STOP, &status))
  {
    if (GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
    {
      *error = IDS_UNINSTALL_SERVICE_STOP;
      CloseServiceHandle(svc);
      CloseServiceHandle(mgr);
      return FALSE;
    }
  }
  else
  {
    DWORD dwCheckPoint, dwTries = 0;
    SERVICE_STATUS status;

    if (QueryServiceStatus(svc, &status))
    {
      while (status.dwCurrentState == SERVICE_STOP_PENDING)
      {
        dwCheckPoint = status.dwCheckPoint;
        Sleep((status.dwWaitHint ? status.dwWaitHint : 500));
        if (!QueryServiceStatus(svc, &status))
        {
          MessageBox(NULL, TEXT("QueryServiceStatus failed"), TEXT("Error"), MB_OK);
          break;
        }
        if (dwCheckPoint == status.dwCheckPoint)
        {
          if (dwTries++ == 60)  /* approx. 30 seconds */
          {
            MessageBox(NULL, TEXT("CheckPoint break"), TEXT("Error"), MB_OK);
            break;
          }
        }
        else
        {
          dwTries = 0;
        }
      }
    }
  }

  *error = IDS_UNINSTALL_SERVICE_DELETE;
  if (!(result = DeleteService(svc)))
  {
    if (GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE)
    {
      result = TRUE;
    }
  }
  CloseServiceHandle(svc);
  CloseServiceHandle(mgr);
  return result;
}

static
void cleanupExecutable(LPCTSTR filename, LPCTSTR location)
{
  DWORD count;
  TCHAR batch_file[1024];
  HANDLE file;
  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  file = CreateFile(TEXT("\\delegads.bat"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (file == INVALID_HANDLE_VALUE)
  {
    return;
  }

  wsprintf(batch_file, TEXT(":Repeat\r\ndel \"%s\"\r\nif exist \"%s\" goto Repeat\r\nrmdir \"%s\"\r\ndel \"%s\"\r\n"),
           filename, filename, location, TEXT("\\delegads.bat"));
  WriteFile(file, batch_file, lstrlen(batch_file) * sizeof(TCHAR), &count, NULL);
  CloseHandle(file);

  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  if (CreateProcess(NULL, TEXT("\\delegads.bat"), NULL, NULL, FALSE, CREATE_SUSPENDED | IDLE_PRIORITY_CLASS, NULL, TEXT("\\"), &si, &pi))
  {
    SetThreadPriority(pi.hThread, THREAD_PRIORITY_IDLE);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    CloseHandle(pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
  }
}

static
void buildInstallPath(void)
{
  GetWindowsDirectory(location, sizeof(location));
  lstrcpy(&(location[3]), "Program Files\\EGADS\\");
}

static
void eulaFailure(void)
{
  messageBox(NULL, IDS_EULA_MISSING, IDS_FATAL_ERROR, MB_OK | MB_ICONERROR);
}

BOOL CALLBACK LicenseDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
  switch (msg)
  {
    case WM_INITDIALOG:
    {
      int count = 0;
      char *p, *text;
      DWORD read, size;
      HANDLE hFile;

      /* Load the dialog text from the LICENSE.TXT file */
      hFile = CreateFile(TEXT("license.txt"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      if (!hFile)
      {
        EndDialog(hDlg, FALSE);
        eulaFailure();
        return TRUE;
      }
      size = GetFileSize(hFile, NULL);
      if (size == 0xFFFFFFFF)
      {
        CloseHandle(hFile);
        EndDialog(hDlg, FALSE);
        eulaFailure();
        return TRUE;
      }
      text = (char *)GlobalAlloc(GMEM_FIXED, size + 1);
      if (!ReadFile(hFile, text, size, &read, NULL) || size != read)
      {
        GlobalFree(text);
        CloseHandle(hFile);
        EndDialog(hDlg, FALSE);
        eulaFailure();
        return TRUE;
      }
      CloseHandle(hFile);

      /* Count the number of bare linefeeds in the text */
      for (p = strchr(text, '\n');  p != NULL;  p = strchr(p + 1, '\n'))
      {
        if (p == text || *(p - 1) != '\r')
        {
          count++;
        }
      }

      /* Insert carriage returns before all of the bare linefeeds */
      text = GlobalReAlloc(text, size + count + 1, 0);
      for (p = strchr(text, '\n');  p != NULL;  p = strchr(p + 1, '\n'))
      {
        if (p == text || *(p - 1) != '\r')
        {
          memmove(p + 1, p, strlen(p) + 1);
          *p = '\r';
        }
      }

      /* Insert the text into the dialog for display */
      SendMessage(GetDlgItem(hDlg, IDC_TEXT), EM_LIMITTEXT, (WPARAM)0, (LPARAM)0);
      SendMessage(GetDlgItem(hDlg, IDC_TEXT), WM_SETTEXT, (WPARAM)0, (LPARAM)text);

      /* Give the Agree button focus */
      SetFocus(GetDlgItem(hDlg, IDOK));
      GlobalFree(text);
      break;
    }

    case WM_COMMAND:
      switch (LOWORD(wParam))
      {
        case IDOK:      /* Agree */
          EndDialog(hDlg, TRUE);
          return TRUE;

        case IDCANCEL:  /* Disagree */
          EndDialog(hDlg, FALSE);
          return TRUE;
      }
      break;
  }

  return FALSE;
}

UINT APIENTRY ChoosePathDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
  switch (msg)
  {
    case WM_INITDIALOG:
      SetWindowLong(hDlg, DWL_USER, lParam);
      break;

    case WM_COMMAND:
      switch (LOWORD(wParam))
      {
        case IDOK:
        {
          LPOPENFILENAME ofn;

          ofn = (LPOPENFILENAME)GetWindowLong(hDlg, DWL_USER);
          SendMessage(GetDlgItem(hDlg, edt1), WM_GETTEXT, (WPARAM)MAX_PATH, (LPARAM)ofn->lpstrFile);
          EndDialog(hDlg, TRUE);
          return TRUE;
        }

        case lst2:
          if (HIWORD(wParam) == LBN_DBLCLK)
          {
            PostMessage(hDlg, WM_UPDATE_PATH, (WPARAM)0, (LPARAM)0);
          }
          break;
      }
      break;

    case WM_UPDATE_PATH:
    {
      TCHAR path[MAX_PATH + 1];

      SendMessage(GetDlgItem(hDlg, stc1), WM_GETTEXT, (WPARAM)sizeof(path), (LPARAM)path);
      SendMessage(GetDlgItem(hDlg, edt1), WM_SETTEXT, (WPARAM)sizeof(path), (LPARAM)path);
      return TRUE;
    }
  }

  return FALSE;
}

BOOL CALLBACK InstallDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
  switch (msg)
  {
    case WM_INITDIALOG:
      SendMessage(GetDlgItem(hDlg, IDC_INSTALL_PATH), EM_LIMITTEXT, (WPARAM)MAX_PATH, (LPARAM)0);
      SendMessage(GetDlgItem(hDlg, IDC_INSTALL_PATH), WM_SETTEXT, (WPARAM)0, (LPARAM)location);
      SendMessage(GetDlgItem(hDlg, IDC_INSTALL_PATH), EM_SETSEL, (WPARAM)0, (LPARAM)-1);
      return FALSE;

    case WM_COMMAND:
      switch (LOWORD(wParam))
      {
        case IDOK:
        {
          TCHAR path[MAX_PATH + 1], buf[MAX_PATH * 3 + 1], buffer[256];
          struct _stat stat_buf;

          SendMessage(GetDlgItem(hDlg, IDC_INSTALL_PATH), WM_GETTEXT, (WPARAM)sizeof(path), (LPARAM)path);
          lstrcpy(location, path);

          while (path[lstrlen(path) - 1] == '\\')
          {
            path[lstrlen(path) - 1] = '\0';
          }

          if (_stat(path, &stat_buf) != 0)
          {
            LoadString(instance, IDS_DOESNOTEXIST_CREATE, buffer, sizeof(buffer));
            wsprintf(buf, buffer, path);
            LoadString(instance, IDS_INSTALL, buffer, sizeof(buffer));
            if (MessageBox(hDlg, buf, buffer, MB_YESNO | MB_ICONQUESTION) == IDNO)
            {
              return TRUE;
            }
            if (!CreateDirectory(path, NULL))
            {
              LoadString(instance, IDS_CREATE_FAILED, buffer, sizeof(buffer));
              wsprintf(buf, buffer, path);
              LoadString(instance, IDS_INSTALL_ERROR, buffer, sizeof(buffer));
              MessageBox(hDlg, buf, buffer, MB_OK | MB_ICONERROR);
              return TRUE;
            }
          }
          else
          {
            if (!(stat_buf.st_mode & _S_IFDIR))
            {
              LoadString(instance, IDS_NOT_DIRECTORY, buffer, sizeof(buffer));
              wsprintf(buf, buffer, path);
              LoadString(instance, IDS_INSTALL_ERROR, buffer, sizeof(buffer));
              MessageBox(hDlg, buf, buffer, MB_OK | MB_ICONERROR);
              return TRUE;
            }
          }

          EndDialog(hDlg, TRUE);
          return TRUE;
        }

        case IDCANCEL:
          EndDialog(hDlg, FALSE);
          return TRUE;

        case IDC_BROWSE:
        {
          TCHAR drive[MAX_PATH + 1], path[MAX_PATH + 1], buffer[256];
          OPENFILENAME ofn;

          SendMessage(GetDlgItem(hDlg, IDC_INSTALL_PATH), WM_GETTEXT, (WPARAM)sizeof(path), (LPARAM)path);
          while (path[lstrlen(path) - 1] == '\\')
          {
            path[lstrlen(path) - 1] = '\0';
          }

          lstrcpyn(drive, path, 2);
          drive[3] = '\0';
          LoadString(instance, IDS_INSTALLATION_PATH, buffer, sizeof(buffer));

          ofn.lStructSize = sizeof(OPENFILENAME);
          ofn.hwndOwner = hDlg;
          ofn.hInstance = instance;
          ofn.lpstrFilter = NULL;
          ofn.lpstrCustomFilter = NULL;
          ofn.nMaxCustFilter = 0;
          ofn.nFilterIndex = 0;
          ofn.lpstrFile = path;
          ofn.nMaxFile = sizeof(path);
          ofn.lpstrFileTitle = NULL;
          ofn.nMaxFileTitle = 0;
          ofn.lpstrInitialDir = drive;
          ofn.lpstrTitle = buffer;
          ofn.Flags = OFN_ENABLEHOOK | OFN_ENABLETEMPLATE | OFN_NOCHANGEDIR;
          ofn.nFileOffset = 0;
          ofn.nFileExtension = 0;
          ofn.lpstrDefExt = NULL;
          ofn.lCustData = (DWORD)&ofn;
          ofn.lpfnHook = ChoosePathDlgProc;
          ofn.lpTemplateName = MAKEINTRESOURCE(IDD_CHOOSE_PATH);

          if (GetOpenFileName(&ofn))
          {
            SendMessage(GetDlgItem(hDlg, IDC_INSTALL_PATH), WM_SETTEXT, (WPARAM)0, (LPARAM)ofn.lpstrFile);
            SendMessage(GetDlgItem(hDlg, IDC_INSTALL_PATH), EM_SETSEL, (WPARAM)0, (LPARAM)-1);
          }

          return TRUE;
        }
      }
      break;
  }

  return FALSE;
}

static
int uninstallEGADS(void)
{
  int count = 0, i;
  HKEY key;
  UINT id;
  DWORD size;
  TCHAR filename[MAX_PATH + 1], path[MAX_PATH + 1];

  if (messageBox(NULL, IDS_UNINSTALL_CONFIRM, IDS_UNINSTALL, MB_YESNO | MB_ICONQUESTION) == IDNO)
  {
    return 1;
  }

  /* Query the registry to find the install location */
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\egads"), 0, KEY_READ, &key) != ERROR_SUCCESS)
  {
    messageBox(NULL, IDS_UNINSTALL_FAILED, IDS_FATAL_ERROR, MB_OK | MB_ICONERROR);
    return 1;
  }

  size = sizeof(location);
  RegQueryValueEx(key, TEXT("InstallLocation"), NULL, NULL, (LPBYTE)location, &size);
  size = sizeof(filename);
  RegQueryValueEx(key, TEXT("UninstallString"), NULL, NULL, (LPBYTE)filename, &size);
  memmove(&(filename[0]), &(filename[1]), sizeof(filename) - 1);
  *(strrchr(filename, '\"')) = '\0';
  RegCloseKey(key);

  if (!unregisterService(&id))
  {
    messageBox(NULL, id, IDS_FATAL_ERROR, MB_OK | MB_ICONERROR);
    return 1;
  }

  for (i = 1;  packing_list[i];  i++)
  {
    wsprintf(path, "%s\\%s", location, packing_list[i]);
    if (!DeleteFile(path))
    {
      count++;
    }
  }

  GetWindowsDirectory(path, sizeof(path));
  lstrcat(path, TEXT("\\system32\\egads.dll"));
  if (!DeleteFile(path))
  {
    count++;
  }

  GetWindowsDirectory(path, sizeof(path));
  lstrcat(path, TEXT("\\system32\\egads.exe"));
  if (!DeleteFile(path))
  {
    count++;
  }

  /* Delete the uninstall key and we're done */
  RegDeleteKey(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\egads"));
  messageBox(NULL, (count ? IDS_UNINSTALL_PARTIAL : IDS_UNINSTALL_SUCCESS), IDS_UNINSTALL, MB_OK);
  cleanupExecutable(filename, location);
  return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
  BOOL copied = FALSE;
  OSVERSIONINFO version;

  instance = hInstance;
  if (!lstrcmp(lpCmdLine, TEXT("/uninstall")))
  {
    return uninstallEGADS();
  }
  buildInstallPath();

  version.dwOSVersionInfoSize = sizeof(version);
  if (!GetVersionEx(&version) || version.dwPlatformId != VER_PLATFORM_WIN32_NT || version.dwMajorVersion < 4)
  {
    messageBox(NULL, IDS_FATAL_ERROR, IDS_UNSUPPORTED_VERSION, MB_ICONERROR | MB_OK);
    return 1;
  }

  /* First we display the EULA to the user */
  if (!DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_EULA), NULL, (DLGPROC)LicenseDlgProc, 0))
  {
    /* LICENSE.TXT couldn't be found or the user disagreed with our license. */
    return 1;
  }

  while (!copied)
  {
    int i;
    TCHAR target[MAX_PATH + 1], system[MAX_PATH + 1];

    /* Now display a dialog to allow the user to set the location where to
     * install to.
     */
    if (!DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_INSTALL), NULL, (DLGPROC)InstallDlgProc, 0))
    {
      /* User aborted the installation */
      return 1;
    }
    while (location[lstrlen(location) - 1] == '\\')
    {
      location[lstrlen(location) - 1] = '\0';
    }

    /* Copy the files to the chosen installation location */
    copied = TRUE;
    for (i = 0;  packing_list[i];  i++)
    {
      wsprintf(target, TEXT("%s\\%s"), location, packing_list[i]);
      if (!CopyFile(packing_list[i], target, FALSE))
      {
        if (messageBox(NULL, IDS_COPY_FAILED, IDS_ERROR, MB_RETRYCANCEL | MB_ICONERROR) == IDCANCEL)
        {
          return 1;
        }
        copied = FALSE;
        break;
      }
    }

    GetWindowsDirectory(system, sizeof(system));
    wsprintf(target, TEXT("%s\\system32\\egads.dll"), system);
    if (copied && !CopyFile(TEXT("egads.dll"), target, FALSE))
    {
      if (messageBox(NULL, IDS_COPY_FAILED, IDS_ERROR, MB_RETRYCANCEL | MB_ICONERROR) == IDCANCEL)
      {
        return 1;
      }
      copied = FALSE;
    }

    GetWindowsDirectory(system, sizeof(system));
    wsprintf(target, TEXT("%s\\system32\\egads.exe"), system);
    if (copied && !CopyFile(TEXT("egads.exe"), target, FALSE))
    {
      if (messageBox(NULL, IDS_COPY_FAILED, IDS_ERROR, MB_RETRYCANCEL | MB_ICONERROR) == IDCANCEL)
      {
        return 1;
      }
      copied = FALSE;
    }

    /* On Windows NT 4.0, we need to copy the freely redistributable file PDH.DLL
     * into the system32 directory so that EGADS can find it and use it.  Microsoft
     * does advise against doing this, but other programs requiring the DLL do this
     * too, so we'll jump off the bridge with them.  As a safeguard, we won't
     * over-write an existing copy of the DLL.
     */
    if (copied && version.dwMajorVersion == 4)
    {
      GetWindowsDirectory(system, sizeof(system));
      wsprintf(target, TEXT("%s\\system32\\pdh.dll"), system);
      if (!CopyFile(TEXT("pdh.dll"), target, TRUE))
      {
         if (GetLastError() != ERROR_FILE_EXISTS)
         {
           if (messageBox(NULL, IDS_COPY_FAILED, IDS_ERROR, MB_RETRYCANCEL | MB_ICONERROR) == IDCANCEL)
           {
             return 1;
           }
           copied = FALSE;
         }
      }
    }
  }

  /* Register uninstall information in the registry */
  addRemovePrograms();

  /* Register the installed service with the service manager */
  if (!registerService())
  {
    messageBox(NULL, IDS_SERVICE_FAILED, IDS_FATAL_ERROR, MB_OK | MB_ICONERROR);
    return 1;
  }

  /* We're done */
  messageBox(NULL, IDS_INSTALLATION_COMPLETE, IDS_SUCCESS, MB_OK);
  return 0;
}

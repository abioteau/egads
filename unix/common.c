#include "platform.h"
#include <errno.h>
#include <sys/stat.h>

int EGADS_read(int fd, void *buffer, int nb)
{
  int count, total = 0;

  while (total < nb)
  {
    count = read(fd, buffer + total, nb - total);
    if (count <= 0)
    {
      if (count == -1 && (errno == EAGAIN || errno == EINTR))
      {
        continue;
      }
      return 0;
    }
    total += count;
  }

  return total;
}

int EGADS_write(int fd, void *buffer, int nb)
{
  int count, total = 0;

  while (total < nb)
  {
    count = write(fd, buffer + total, nb - total);
    if (count <= 0)
    {
      if (count == -1 && (errno == EAGAIN || errno == EINTR))
      {
        continue;
      }
      return 0;
    }
    total += count;
  }

  return total;
}

int EGADS_safedir(char *dir, int write_to_file)
{
#ifndef USING_SPLAT
  int owner_uid, result = 1;
  char old[PATH_MAX + 1], new[PATH_MAX + 1];
  struct stat info;

  if (!getcwd(old, sizeof(old)))
  {
    return -1;
  }
  chdir(dir);

  if (lstat(".", &info) == -1)
  {
    result = -1;
  }
  else
  {
    if (!write_to_file)
    {
      if (info.st_mode & (S_IFLNK|S_IRWXO|S_IRWXG))
      {
        result = 0;
      }
    }
    else
    {
      if (!(info.st_mode & S_ISVTX) || (info.st_mode & (S_IWOTH | S_IWGRP | S_IFLNK)))
      {
        result = 0;
      }
    }
  }

  owner_uid = info.st_uid;
  while (result == 1)
  {
    if (!getcwd(new, sizeof(new)))
    {
      result = -1;
      break;
    }
    if (!strcmp(new, "/"))
    {
      break;
    }
    chdir("..");
    if (lstat(".", &info) == -1)
    {
      result = -1;
      break;
    }
    if ((info.st_mode & (S_IFLNK | S_IWOTH | S_IWGRP)) ||
        (info.st_uid && info.st_uid != owner_uid))
    {
      result = 0;
      break;
    }
  }

  chdir(old);
  return result;
#else
  int err = 0;

  return splat_is_safe_dir(dir, getuid(), &err);
#endif
}

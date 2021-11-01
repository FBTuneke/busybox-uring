#pragma once

#include "../include/libbb.h"

static inline void exe_path(char *str)
{
      FILE *fp;
      char buf[4096], *p;

      *str = '\0';
      
      if(!(fp = fopen("/proc/self/maps", "r")))
            return;

      fgets(buf, sizeof(buf), fp);
      fclose(fp);

      *(p = strchr(buf, '\n')) = '\0';
      // printf("1: %s\n", buf);
      while(*p != '/')
            p--;

      *p = '\0';
      // printf("2: %s\n", buf);

      while(*p != ' ')
            p--;
      
      // printf("2: %s\n", p);

      strncpy(str, p+1, PATH_MAX);
      str[PATH_MAX] = '\0';
}
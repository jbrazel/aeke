#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include "log.h"

extern int errno;

#ifdef MEM_DEBUG
static int bytesAllocated = 0;
static int nAllocations = 0;
static int nFrees = 0;
static int counter = 0;
#endif

void
xmemoryStats(void)
{
#ifdef MEM_DEBUG
  logMsg(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
  logMsg("%i bytes still allocated in %i allocs/%i frees\n", 
	 bytesAllocated, nAllocations, nFrees);
#endif
}

void*
xmalloc(unsigned int size)
{
#ifdef MEM_DEBUG
  static int exitHandlerSet = 0;
#endif
  char *p;
  
  assert(size != 0);

#ifdef MEM_DEBUG
  p = malloc(size + 2 * sizeof(unsigned long));
#else
  p = malloc(size);
#endif

  if (p == NULL) 
    {
      errMsg("malloc: %s\n", strerror(errno));
      exit(0);
    }

#ifdef MEM_DEBUG
  {
    unsigned long *pp = (unsigned long *)p;
    pp[0] = size;
    pp[1] = counter++;
    logMsg("%i+ %i MEM\n", counter - 1, size);

    nAllocations++;
    bytesAllocated += size;
  }

  if (!exitHandlerSet)
    {
      atexit(xmemoryStats);
      exitHandlerSet++;
    }

  p += 2 * sizeof(unsigned long);
#endif
  
  memset(p, 0, size);
  return p;
}

void
xfree(void *ptr)
{
#ifdef MEM_DEBUG
  unsigned long *p = (unsigned long*)((char*)ptr - 2 * sizeof(unsigned long));

  bytesAllocated -= p[0];
  logMsg("%i- %i MEM\n", p[1], p[0]);

  nFrees++;
  free(p);
#else
  free(ptr);
#endif
}

char*
xstrdup(const char *str)
{
  char *s = xmalloc(strlen(str)+1);
#ifdef __OpenBSD__
  strlcpy(s, str, strlen(str)+1);
#else
  strcpy(s, str);
#endif
  return s;
}


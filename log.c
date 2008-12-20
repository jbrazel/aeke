#include <stdarg.h>
#include <stdio.h>

extern int debug;
int show_error_messages = 1;

static const char *logPrefix = NULL;

void 
setLogPrefix(const char *prefixString)
{
  logPrefix = prefixString;
}

void
logMsg(const char *format, ...)
{
  va_list args;

  if (logPrefix != NULL)
    fprintf(stderr, "%s: ", logPrefix);

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);

  fflush(stderr);
}

void
dbgMsg(int dbglevel, const char *format, ...)
{
  va_list args;

  if (debug >= dbglevel) 
    {
      if (logPrefix != NULL)
	fprintf(stderr, "%s: ", logPrefix);

      va_start(args, format);
      vfprintf(stderr, format, args);
      va_end(args);
    }
}

void
dbgHexDump(int dbgLevel, const char *blurb, unsigned char *data, int length)
{
  if (debug < dbgLevel)
    return;

  dbgMsg(dbgLevel, "%s", blurb);

  while(length--)
    fprintf(stderr, "%02x", (unsigned int)*data++);
  
  fprintf(stderr, "\n");
}

void
errMsg(const char *format, ...)
{
  va_list args;

  if (show_error_messages) 
    {  
      if (logPrefix != NULL)
        fprintf(stderr, "%s: ", logPrefix);

      va_start(args, format);
      vfprintf(stderr, format, args);
      va_end(args);
    }
}


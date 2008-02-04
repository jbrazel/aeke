#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "client.h"

int debug = 0;
char *passPhrase = NULL;
static char *localFile, *remoteFile;
static int copyFromRemote;

static void sentCommandString(Socket*, int);
static void fileXfered(Socket *s, int status);

static void
onClientAuthenticated(Socket *s, int status)
{
  int len = strlen(remoteFile) + 2;
  char *commandString = (char*) setupForWrite(s, len, 1);
  AekeSocket *a = (AekeSocket*)s->data;

  if (status != 0)
    {
      closeSocket(s);
      return;
    }

  snprintf(commandString, len, "%c%s", 
	   copyFromRemote ? 'R' : 'W', remoteFile);
  
  (*a->write_routine)(s, sentCommandString);
}

static void
sentCommandString(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  if (status != 0)
    {
      errMsg("Failed to send command string (status %i)\n", status);
      closeSocket(s);
      return;
    }

  if (copyFromRemote)
    {
#if defined( __OpenBSD__) || defined(__linux__)
      a->tmpFile = mkxtemp(xstrdup("./tmp-XXXXXX"));
#else
      a->tmpFile = mktemp(xstrdup("./tmp-XXXXXX"));
#endif
	dbgMsg(3, "Dumping to local file %s\n", a->tmpFile);

      connectToFile(s, a->tmpFile, 'w', fileXfered);
    }
  else
    {
      connectToFile(s, localFile, 'r', fileXfered);
    }
}

static void
fileXfered(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  if (status != 0)
    {
      errMsg("File transfer failed (status %i)\n", status);
    }
  else if (copyFromRemote && rename(a->tmpFile, localFile))
    {
      dbgMsg(1, "Error renaming %s -> %s: %s\n", a->tmpFile, localFile,
	     strerror(errno));
      status = -1;
    }

  if (status)
    unlink(a->tmpFile);

  if (copyFromRemote)
    xfree(a->tmpFile);

  closeSocket(s);
}

int 
main(int argc, char **argv)
{
  int arg, portknockTimeout = 0;
  char *connectString;

  setLogPrefix("[aeke]");
  initCrypto();
  ioSetup();
  
  while((arg = getopt(argc, argv, "dt:")) > 0)
    {
      switch(arg) {
      case 'd':
	debug++;
	break;
      case 't':
        portknockTimeout = atoi(optarg);
        break;
      default:
	if (debug) errMsg("Unknown option '-%c'\n", arg);
	exit(debug);
      }
    }

  if ((argc - optind) < 2)
    {
      errMsg("%s host:port:[port:...]remoteFile local_copy\n", argv[0]);
      errMsg("%s localFile host:port:[port:...]remote_copy\n", argv[0]);
      errMsg("AEKE_PROXY environment variable has the format:\n"
	     "\t<ip_addr>:<port>[:<port>][;<ip_addr>...]\n");
      exit(1);
    }

  if (!access(argv[optind], F_OK))
    {
      remoteFile = argv[optind+1];
      localFile = argv[optind];
      copyFromRemote = 0;

      if (strrchr(remoteFile, ':') == NULL)
        {
          errMsg("Local->Local copying not supported (use cp(1))\n");
          exit(1);
        }
    }
  else
    {
      remoteFile = argv[optind];
      localFile = argv[optind+1];
      copyFromRemote = 1;
    }

  connectString = remoteFile;
  remoteFile = strrchr(connectString, ':');
  *remoteFile++ = '\0';

  client(connectString, portknockTimeout, onClientAuthenticated);
  ioLoop(0);

  exit(0);
}

/* EOF */

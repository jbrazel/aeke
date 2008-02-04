#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include "client.h"

int debug = 0;
char *command = "";

static void sentCommandString(Socket*, int);

static void
onClientAuthenticated(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;
  char *buffer;

  if (status != 0)
    {
      /* Caller prints the error. */
      closeSocket(s);
      return;
    }

  dbgMsg(2, "Client connected and authenticated/\n");

  buffer = (char*) setupForWrite(s, strlen(command)+2, 1);
  snprintf(buffer, strlen(command)+2, "!%s", command);
  (*a->write_routine)(s, sentCommandString);
}

static void
sentCommandString(Socket *s, int status)
{
  Socket *tty;

  if (status != 0)
    {
      errMsg("Failed to send command string (status %i)\n", status);
      closeSocket(s);
      return;
    }
  
  dbgMsg(1, "Spawning shell.\n");
  tty = openClientTty(NULL);
  joinSockets(s, tty, closeSocketPair);
}

static void
usage(const char *progName)
{
  errMsg("Usage:\n\t%s [-d[d...]] ip_addr:port[:port ...]\n", 
	 progName);
  errMsg("AEKE_PROXY environment variable has the format:\n"
	 "\t<ip_addr>:<port>[:<port>][;<ip_addr>...]\n");
  exit(1);
}

int 
main(int argc, char **argv)
{
  char *connectString, *command;
  int arg, portknockTimeout = 0;

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
  
  connectString = argv[optind];

  if (connectString == NULL)
    {
      usage(argv[0]);
      exit(1);
    }

  if (argv[optind+1] != NULL)
    command = argv[++optind];

  client(connectString, portknockTimeout, onClientAuthenticated);
  ioLoop(0);
  cleanupCrypto();

  exit(0);
}

/* EOF */

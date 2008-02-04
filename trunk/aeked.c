#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "log.h"
#include "buffer.h"
#include "io.h"
#include "common.h"
#include "crypto.h"

#define PASSWORD_FILE "pwd.md5"
#ifdef __OpenBSD__
#define SHELL "/bin/ksh"
#else
#define SHELL "/bin/bash"
#endif

#ifndef WAIT_ANY
#define WAIT_ANY (-1)
#endif

static void acceptClientConnection(Socket *s);
static void clientAuthenticated(Socket *s, int status);
static void motdSent(Socket *s, int status);
static void proxyConnected(Socket *outgoing, int status);
static void proxyConnectionEstablished(Socket *proxySock, int status);
static void recvdCommandString(Socket *s, int status);
static void closeServerSocketPair(Socket *s, int status);
static void fileRead(Socket *s, int status);
static void fileWritten(Socket *s, int status);
static void serverCleanup(void);

static unsigned char passwordHash[MD5_DIGEST_LENGTH];
static int portknockTimeout = 0;

int debug = 0;

static Socket *masterSocket = NULL;
static int nSockets = 0;

static void
processExit()
{
  int status;
  while (waitpid(WAIT_ANY, &status, WNOHANG) > 0);
}

static void
serverCloseSocket(Socket *s)
{
  closeSocket(s);

  if (--nSockets == 0)
    {
#ifdef PORTKNOCKING
#error "PORTKNOCKING defined, but no portknock code added"  
#endif
    }
}

static void
readPasswordFile(void)
{
  int pwdFd;

  if ((pwdFd = open(PASSWORD_FILE, O_RDONLY)) < 0)
    {
      errMsg("%s: %s\n", PASSWORD_FILE, strerror(errno));
      exit(debug);      
    }

  if (read(pwdFd, passwordHash, MD5_DIGEST_LENGTH) != MD5_DIGEST_LENGTH)
    {
      errMsg("Error reading password hash: %s\n", strerror(errno));
      exit(debug);
    }

  close(pwdFd);
}

static void
server(int portNumber)
{
  int sock;
  struct sockaddr_in addr;

  atexit(serverCleanup);
  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (sock < 0)
    {
      errMsg("socket(): %s\n", strerror(errno));
      exit(debug);
    }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons((unsigned short)portNumber);

  if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)))
    {
      errMsg("bind(): %s\n", strerror(errno));
      exit(debug);
    }

  listen(sock, 5);

  masterSocket = createSocket();
  masterSocket->sock = sock;

  registerSocket(masterSocket);
  onAccept(masterSocket, acceptClientConnection);
  ioLoop(1);  
}

static void
serverCleanup(void)
{
  if (masterSocket != NULL)
    {
      AekeSocket *a = (AekeSocket*)masterSocket->data;
      memset(&a->u.clientAddress, 0, sizeof(a->u.clientAddress));
      serverCloseSocket(masterSocket);
    }
}

static void
acceptClientConnection(Socket *s)
{
  int child;
  socklen_t szAddr;
  Socket *childSock;
  AekeSocket *a = (AekeSocket*)s->data;

  szAddr = sizeof(struct sockaddr_in);

  a->u.clientAddress.sin_family = AF_INET;
  a->u.clientAddress.sin_addr.s_addr = INADDR_ANY;

  if ((child = accept(s->sock, (struct sockaddr*)&a->u.clientAddress, &szAddr)) < 0)
    {
      errMsg("accept(): %s\n", strerror(errno));
      exit(debug);
    }

  fcntl(child, F_SETFD, FD_CLOEXEC);

  childSock = createSocket();
  childSock->sock = child;
  nSockets++;

  dbgMsg(2, "Recv'd client connection from %s:%u.\n",
	 inet_ntoa(a->u.clientAddress.sin_addr), ntohs(a->u.clientAddress.sin_port));

  readPasswordFile();

  registerSocket(childSock);
  authenticateToClient(childSock, passwordHash, clientAuthenticated);
}

static void
clientAuthenticated(Socket *s, int status)
{
  unsigned long *buf;
  AekeSocket *a = (AekeSocket*)s->data;

  if (status < 0)
    {
      struct sockaddr_in addr;
      socklen_t sz = sizeof(addr);

      getpeername(s->sock, (struct sockaddr*)&addr, &sz);

      dbgMsg(1, "Client authentication failed on %s:%u\n",
	     inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
      serverCloseSocket(s);
      return;
    }

  dbgMsg(2, "Client authenticated, sending motd...\n");

  buf = (unsigned long*) setupForWrite(s, 2 * sizeof(unsigned long), 1);
  buf[0] = htonl(time(NULL));
  buf[1] = htonl(getpid());

  (*a->write_routine)(s, motdSent);
}

static void
motdSent(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  if (status < 0)
    {
      dbgMsg(1, "Error sending MOTD\n");
      serverCloseSocket(s);
      return;
    }

  dbgMsg(2, "Client motd sent, reading client command.\n");

  (*a->read_routine)(s, -1, recvdCommandString);
}

static void
makeProxyConnection(Socket *clientSide, char *connectString)
{
  Socket *proxySock;

  dbgMsg(2, "Making proxy connection to '%s'\n", connectString);
  proxySock = createSocket();
  nSockets++;

  {
    AekeSocket *incoming = (AekeSocket*)clientSide->data;
    AekeSocket *outgoing = (AekeSocket*)proxySock->data;

    incoming->peer = proxySock;
    outgoing->peer = clientSide;

    /* Don't try to read/write anything to the client-side
     * connection yet: wait until the proxy socket has connected
     * first.
     */
  }
  
  connectSocket(proxySock, connectString, portknockTimeout, proxyConnected);
  dbgMsg(3, "Proxy for %i is %i\n", clientSide->sock, proxySock->sock);
}

static void
proxyConnected(Socket *proxySock, int status)
{
  AekeSocket *a = (AekeSocket*)proxySock->data;
  AekeSocket *clientSide = (AekeSocket*)a->peer->data;
  unsigned long *buf;

  if (status < 0)
    {
      dbgMsg(1, "Proxy connect failed on %s:%u\n",
	     inet_ntoa(a->u.connectData.ip), 
             a->u.connectData.knockSequence[a->u.connectData.currentKnockPtr-1]);

      serverCloseSocket(a->peer);
      serverCloseSocket(proxySock);
      return;
    }  

  dbgMsg(3, "Proxy (%i) connected, sending ACK to %i\n", 
	 proxySock->sock, a->peer->sock);

  buf = (unsigned long*) setupForWrite(a->peer, 2 * sizeof(unsigned long), 1);
  buf[0] = htonl(time(NULL));
  buf[1] = htonl(getpid());

  (*clientSide->write_routine)(a->peer, proxyConnectionEstablished);
}

static void
proxyConnectionEstablished(Socket *clientSide, int status)
{
  AekeSocket *a = (AekeSocket*)clientSide->data;
  AekeSocket *proxySock = (AekeSocket*)a->peer->data;

  if (status < 0)
    {
      dbgMsg(1, "Failed to write back proxy connect status\n");
      serverCloseSocket(clientSide);
      serverCloseSocket(a->peer);
      return;
    }  

  /* Disable encryption on the client-side socket, and re-join the two sockets: data 
   * will now be 'written through' to the remote server without any interpretation.
   */

  dbgMsg(2, "Sent ACK to originator, disabling encryption.\n");

  disableEncryption(clientSide);

  a->read_routine = readPartialData;
  a->rawMode = 1;
  proxySock->read_routine = readPartialData;
  proxySock->rawMode = 1;

  joinSockets(clientSide, a->peer, closeServerSocketPair);
}

static void
recvdCommandString(Socket *s, int status)
{
  int length = s->transferData.readBuffer.totalLength;
  AekeSocket *a = (AekeSocket*)s->data;
  Socket *tty;

  if (status < 0)
    {
      dbgMsg(1, "Error reading client command: %s\n", strerror(status));
      serverCloseSocket(s);
      return;
    }

  a->commandData = xmalloc(length);

  memcpy(a->commandData, s->transferData.readBuffer.b.buffer,
	 length);
  
  dbgMsg(2, "Client command recv'd: '%s'\n", 
	 a->commandData);

  switch(toupper(a->commandData[0]))
    {
    case 'R':
      /* Read file. */
      connectToFile(s, a->commandData + 1, 'r', fileRead);
      break;

    case 'W':
      /* Write file. */
#if defined( __OpenBSD__) || defined(__linux__)
      a->tmpFile = mkxtemp(xstrdup("./tmp-XXXXXX"));
#else
      a->tmpFile = mktemp(xstrdup("./tmp-XXXXXX"));
#endif
      connectToFile(s, a->tmpFile, 'w', fileWritten);
      break;

    case 'F':
      /* Forward connection -- open peer connection, switch off encryption,
       * join two sockets.
       */
      makeProxyConnection(s, a->commandData+1);
      break;

    case '!':
      if (a->commandData[1] == '\0')
	tty = openTty(SHELL);
      else
	tty = openTty(a->commandData+1);

      if (tty == NULL)
        {
          dbgMsg(1, "Couldn't open tty\n");
          serverCloseSocket(s);
          break;
        }

      nSockets++;
      joinSockets(s, tty, closeServerSocketPair);
      break;

    default:
      dbgMsg(1, "Bad commend '%s' from client\n", a->commandData);
      serverCloseSocket(s);
      break;
    }
}

static void 
closeServerSocketPair(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  serverCloseSocket(a->peer);
  serverCloseSocket(s);
}

static void
fileRead(Socket *s, int status)
{
  if (status < 0)
    dbgMsg(1, "Error reading local file: %s\n", strerror(status));

  serverCloseSocket(s);
}

static void
fileWritten(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  if (status < 0)
    {
      dbgMsg(1, "Error writing local file: %s\n", strerror(status));
    }
  else if (rename(a->tmpFile, a->commandData + 1))
    {
      dbgMsg(1, "Error renaming %s -> %s: %s\n", a->tmpFile, a->commandData + 1,
	     strerror(errno));
      unlink(a->tmpFile);
    }

  xfree(a->tmpFile);
  serverCloseSocket(s);
}

static void
intr()
{
  exit(0);
}

int main(int argc, char **argv)
{
  int arg, portNumber;
  int setPassword = 0;

  signal(SIGINT, intr);
  signal(SIGCHLD, processExit);

  setLogPrefix("[aeked]");
  initCrypto();
  ioSetup();

  while((arg = getopt(argc, argv, "dsP:")) > 0)
    {
      switch(arg) {
      case 'd':
	debug++;
	break;
      case 's':
	setPassword++;
	break;
      case 't':
        portknockTimeout = atoi(optarg);
        break;
      default:
	errMsg("Unknown option '-%c'\n", arg);
	exit(debug);
      }
    }

  if (setPassword) 
    {
      int fd = open(PASSWORD_FILE, O_CREAT|O_TRUNC|O_WRONLY, 0600), rv = 0;
      char *password;
      unsigned char password1[MD5_DIGEST_LENGTH], password2[MD5_DIGEST_LENGTH];

      while(1)
	{
	  password = getpass("Password:");
	  makeHash((unsigned char*)password, strlen(password), password1);
	  
	  password = getpass("Verify:");
	  makeHash((unsigned char*)password, strlen(password), password2);

	  if (memcmp(password1, password2, MD5_DIGEST_LENGTH))
	    errMsg("Password mismatch.\n\n");
	  else
	    break;
	}

      if (fd < 0)
	{
	  errMsg("%s: %s\n", PASSWORD_FILE, strerror(errno));
	  exit(debug);
	}

      if (write(fd, password1, MD5_DIGEST_LENGTH) != MD5_DIGEST_LENGTH)
	{
	  errMsg("write(): %s\n", strerror(errno));
	  rv = 1;
	}

      close(fd);
      logMsg("Password updated.\n");
      exit(rv);
    }

  if (argv[optind] == NULL)
    {
      errMsg("No port number provided\n");
      exit(debug);
    }

  portNumber = atoi(argv[optind]);

  if (portNumber < 0 || portNumber > 65535)
    {
      errMsg("Bad port number %i\n", portNumber);
      exit(debug);
    }

  if (debug == 0)
    {
      /* Daemon mode. */
      int i;

      for(i = 0; i < getdtablesize(); i++)
	if (isatty(i))
	  close(i);

      switch(fork()) {
      case 0:
	setsid();
	break;
      default:
        exit(0);
      }
    }

  server(portNumber);

  return 0;
}

/* EOF */
	 

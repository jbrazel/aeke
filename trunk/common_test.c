#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <termios.h>

#include "buffer.h"
#include "io.h"
#include "common.h"
#include "log.h"
#include "crypto.h"

#define AEKE_CIPHER    SN_aes_128_cbc

int debug = 0;

static int testNumber = 1;

static void
childHandler(int ignored)
{
  int pid, status;

  pid = waitpid(-1, &status, WNOHANG);
  
  if (pid <= 0)
    {
      perror("waitpid(WNOHANG)");
      exit(-1);
    }

  if ((!WIFEXITED(status)) || WEXITSTATUS(status) != 0)
    {
      errMsg("Unit tests failed\n");
      exit(-1);
    }

  logMsg("Tests passed successfully\n");
  exit(0);
}

static void serverTest1Done(Socket *s, int status);

static void
serverTest1(Socket *child)
{
#if defined( __OpenBSD__) || defined(__linux__)
  char *tfile = mkxtemp(xstrdup("./tmp-XXXXXX"));
#else
  char *tfile = mktemp(xstrdup("./tmp-XXXXXX"));
#endif

  logMsg("Test 1 - Get file\n");
  connectToFile(child, tfile, 'w', serverTest1Done);	/* Socket closed on return. */
  xfree(tfile);
}

static void 
serverTest1Done(Socket *s, int status)
{
  if (status < 0)
    {
      errMsg("Test 1 failed.\n");
      exit(1);
    }

  logMsg("File transferred\n");
  closeSocket(s);

  xmemoryStats();
}

static void serverTest2Done(Socket *s, int status);

static void
serverTest2(Socket *child)
{
  AekeSocket *a = (AekeSocket*)child->data;

  logMsg("Test 2 - switching off encryption\n");
  disableEncryption(child);

  (*a->read_routine)(child, -1, serverTest2Done);
}

static void
serverTest2Done(Socket *s, int status)
{
  if (status < 0)
    {
      errMsg("Test 2 failed.\n");
      exit(1);
    }

  logMsg("Unencrypted string: %s\n", s->transferData.readBuffer.b.buffer);
  closeSocket(s);

  xmemoryStats();
}

static void
serverTest3(Socket *s)
{
  Socket *tty = openTty("/bin/sh");
  joinSockets(s, tty, closeSocketPair);
  logMsg("All Done.\n");
}

static void
childAuthenticated(Socket *child, int status)
{
  /* Slight race condition here: if the client makes a second connection
   * before the server finished it's half of the first test, testNumber 
   * wouldn't be incremented in time. Consequently, the server-side would
   * be expecting the previous test, while the client is expecting the next
   * test.
   * This isn't a problem in the production code, as it relies on no such 
   * global variables. 
   */

  int thisTest = testNumber++;

  logMsg("Child auth returned %i\n", status);

  switch(thisTest) {
  case 1:
    serverTest1(child);
    break;

  case 2:
    serverTest2(child);
    break;

  case 3:
    serverTest3(child);
    break;

  case 4:
    closeSocket(child);
    logMsg("Tests completed successfully.\n");
    ioShutdown();
    break;

  default:
    errMsg("Unknown test %i\n", thisTest);
    exit(1);
  }
}

static void
getClient(Socket *s)
{
  int child;
  socklen_t szAddr;
  struct sockaddr_in addr;
  Socket *childSock;

  szAddr = sizeof(addr);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;

  if ((child = accept(s->sock, (struct sockaddr*)&addr, &szAddr)) < 0)
    {
      perror("accept()");
      exit(1);
    }

  childSock = createSocket();
  childSock->sock = child;

  registerSocket(childSock);

  { 
    unsigned char pwd[MD5_DIGEST_LENGTH];
    makeHash((unsigned char*)"cat", 3, pwd);
    authenticateToClient(childSock, pwd, childAuthenticated);
  }
}

static Socket *masterSocket = NULL;

static void
server(void)
{
  int sock;
  struct sockaddr_in addr;
  
  initCrypto();
  setLogPrefix("[Server]");

  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (sock < 0)
    {
      perror("socket()");
      exit(1);
    }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(6666);

  if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)))
    {
      perror("bind");
      exit(1);
    }

  listen(sock, 5);

  xmemoryStats();

  masterSocket = createSocket();
  masterSocket->sock = sock;

  xmemoryStats();

  registerSocket(masterSocket);
  onAccept(masterSocket, getClient);

  ioLoop();

  xmemoryStats();
  closeSocket(masterSocket);
  xmemoryStats();
  exit(0);
}

/*******/

static void clientTest1Done(Socket *s, int status);
static void clientTest2Done(Socket *s, int status);

static int test1Fd;

static void
clientTest1(Socket *s)
{
  logMsg("Test 1 - send file\n");
  test1Fd = open("/etc/passwd", O_RDONLY);

  if (test1Fd < 0)
    clientTest1Done(s, -errno);
  
  sendFile(s, test1Fd, clientTest1Done);
}

static void 
clientTest1Done(Socket *s, int status)
{
  if (status < 0)
    {
      errMsg("Test 1 failed: %i\n", status);
      exit(1);
    }
  
  close(test1Fd);

  testNumber++;
  closeSocket(s);

  xmemoryStats();
}

static void
clientTest2(Socket *s)
{
  unsigned char *b;
  char *mesg = "Plaintext message.";

  disableEncryption(s);

  b = setupForWrite(s, strlen(mesg)+1, 1);
  strcpy((char*)b, mesg);
  sendData(s, clientTest2Done);
}

static void 
clientTest2Done(Socket *s, int status)
{
  if (status < 0)
    {
      errMsg("Test 2 failed: %i\n", status);
      exit(1);
    }

  testNumber++;
  closeSocket(s);

  xmemoryStats();
}

struct termios previousTtySettings;

static void 
clientTest3(Socket *s)
{
  Socket *tty;

  logMsg("Final test: spawning shell -- type 'exit' to quit\n");
  tty = openClientTty(NULL);
  joinSockets(s, tty, closeSocketPair);
  testNumber++;
}

static void
clientAuthed(Socket *s, int status)
{
  logMsg("Child auth returned %i\n", status);

  switch(testNumber) {
  case 1:
    clientTest1(s);
    break;

  case 2:
    clientTest2(s);
    break;

  case 3:
    clientTest3(s);
    break;

  case 4:
    closeSocket(s);
    logMsg("Tests all completed successfully.\n");
    exit(0);

  default:
    errMsg("Unknown test %i\n", testNumber);
    exit(1);
  }
}

static void
clientConnected(Socket *s, int status)
{
  logMsg("Client connected with status %i\n", status);
  if (status < 0)
    exit(1);
  authenticateToServer(s, "cat", clientAuthed);
}

static void 
client(void)
{
  Socket *s = createSocket();

  signal(SIGCHLD, childHandler);

  initCrypto();
  setLogPrefix("[Client]");

  connectSocket(s, "127.0.0.1:6666", 2, clientConnected);
  ioLoop();
}

int 
main()
{
  switch(fork()) {
  case -1:
    perror("fork()");
    exit(1);
  case 0:
    server();
  default:
    sleep(2);
    while(1)
      client();
  }

  return 0;
}

/* EOF */

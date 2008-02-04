#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>

#include "buffer.h"
#include "common.h"
#include "log.h"

static void onConnected(Socket *s, int status);
static void clientAuthenticated(Socket *s, int status);
static void motdRead(Socket *s, int status);

void 
client(char *connectString, int timeout, completion_handler done)
{
  int nConnectionHops;
  Socket *s;
  char *proxyList = NULL, *ptr;
  AekeSocket *a;

  s = createSocket();
  
  /* Set up list of connection strings. */

  if (getenv("AEKE_PROXY") != NULL)
    {
      char *list = getenv("AEKE_PROXY");
      int len = strlen(list);

      if (list[len-1] == ';')
	list[len-1] = '\0';
      
      len += strlen(connectString) + 2;
      
      proxyList = (char*)xmalloc(len);
      snprintf(proxyList, len, "%s;%s", list, connectString);
    }
  else
    {
      proxyList = xstrdup(connectString);
    }

  dbgMsg(3, "Connection data: %s\n", proxyList);

  for(nConnectionHops = 0, ptr = proxyList; 
      nConnectionHops <= MAX_PROXY_HOPS && ptr != NULL; 
      nConnectionHops++, ptr = strchr(ptr, ';'))
    ptr++;

  dbgMsg(3, "%i proxy hops\n", nConnectionHops);

  if (nConnectionHops > MAX_PROXY_HOPS)
    {
      errMsg("Too many hops (max %i), try modifying AEKE_PROXY env variable\n");
      (*done)(s, -1); 
      return;
    }

  a = (AekeSocket*)s->data;

  for(nConnectionHops = 0; proxyList != NULL; )
    {
      a->u.connectData.connectionStrings[nConnectionHops++] = proxyList;
      if ((ptr = strchr(proxyList, ';')) != NULL)
	*ptr++ = '\0';
      dbgMsg(3, "Proxy %i: %s\n", nConnectionHops, proxyList);
      proxyList = ptr;
    }

  pushReturn(s, done);

  connectSocket(s, a->u.connectData.connectionStrings[a->u.connectData.hopNo++],
		timeout, onConnected);
}

static void 
onConnected(Socket *s, int status)
{
  char *passPhrase, prompt[sizeof("xxx.xxx.xxx.xxx Password:")];
  AekeSocket *a = (AekeSocket*)s->data;
  
  if (status < 0)
    {
      errMsg("Connect failed: %s\n", strerror(errno));
      popReturn(s, -1);
      return;
    }

  snprintf(prompt, sizeof(prompt), "%s Password:", inet_ntoa(a->u.connectData.ip));
  passPhrase = getpass(prompt);
  authenticateToServer(s, passPhrase, clientAuthenticated);
}

static void
clientAuthenticated(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  if (status < 0)
    {
      errMsg("Authentication failed: %s\n", strerror(errno));
      popReturn(s, -1);
      return;
    }  

  (*a->read_routine)(s, -1, motdRead);
}

static void
motdRead(Socket *s, int status)
{
  unsigned long *buf;
  time_t serverTime;
  AekeSocket *a = (AekeSocket*)s->data;

  if (status < 0)
    {
      errMsg("Authentication failed: %s\n", strerror(errno));
      popReturn(s, -1);
      return;
    }  
  
  buf = (unsigned long*)s->transferData.readBuffer.b.buffer;

  serverTime = (time_t)ntohl(buf[0]);
  printf("Time of day on server: %s", ctime(&serverTime));
  printf("Server pid: %lu\n", (unsigned long) ntohl(buf[1]));

  if (a->u.connectData.connectionStrings[a->u.connectData.hopNo] == NULL)
    popReturn(s, status);  
  else
    connectSocket(s, a->u.connectData.connectionStrings[a->u.connectData.hopNo++],
		  -1, onConnected);
}


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

int
main(int argc, char **argv)
{
  int i;

  if (argc < 5) {
    fprintf(stderr, "Usage:\n\t%s pid newfile oldfile port\n", argv[0]);    
    fprintf(stderr, "\nWill kill pid 'pid' and replace existing file 'oldfile'"
		    " with 'newfile' (move newfile -> oldfile), before"
 		    " re-running the service on port 'port' (run `oldfile port`)\n");
    fprintf(stderr, "\nWill wait 2 minutes in daemon mode for operator to log\n"
		    " off, then 10 seconds after each attempt to terminate \n"
		    "(SIGTERM,SIGKILL) the application.\n");

    exit(1);
  }

  if (access(argv[2], R_OK|X_OK))
    {
      fprintf(stderr, "Can't access %s\n", argv[2]);
      exit(1);
    }

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

  sleep(120);
  kill(atoi(argv[1]), SIGTERM);
  sleep(10);
  kill(atoi(argv[1]), SIGKILL);
  sleep(10);

  rename(argv[2], argv[3]);
  execl(argv[3], argv[3], argv[4], NULL);
  exit(0);
}


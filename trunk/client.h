#ifndef CLIENT_H
#define CLIENT_H

#include "log.h"
#include "buffer.h"
#include "io.h"
#include "common.h"
#include "crypto.h"

extern void client(char *connectString, int timeout, completion_handler done);

#endif /* CLIENT_H */

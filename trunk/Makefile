# Don't use make, use gmake.
CC=	gcc
SRC=	aeked.o buffer.o common.o crypto.o io.o log.o utils.o 
CSRC=	aeke.o client.o buffer.o common.o crypto.o io.o log.o utils.o 
CPSRC=	aeke_cp.o client.o buffer.o common.o crypto.o io.o log.o utils.o 
ITEST=	io_test.o io.o buffer.o utils.o log.o crypto.o
CTEST=	common_test.o io.o buffer.o utils.o log.o common.o crypto.o
CFLAGS=	-I. -I../../include -g -Wall -pedantic #-DPORTKNOCKING
LDFLAGS=	-lcrypto 
EXTRALDFLAGS=	

OS=	$(shell uname)

ifeq ($(OS),	Linux)
EXTRALDFLAGS += -lutil
endif
ifeq	($(OS), OpenBSD)
EXTRALDFLAGS += -lutil
endif

all:	aeked aeke aeke_cp
	
aeked:	$(SRC)
	$(CC) -o $@ $(SRC) $(LDFLAGS) $(EXTRALDFLAGS)

aeke:	$(CSRC)
	$(CC) -o $@ $(CSRC) $(LDFLAGS) $(EXTRALDFLAGS)

aeke_cp:	$(CPSRC)
	$(CC) -o $@ $(CPSRC) $(LDFLAGS) $(EXTRALDFLAGS)

io_test:	$(ITEST)
	$(CC) -o $@ $(ITEST) $(LDFLAGS) $(EXTARLDFLAGS)

common_test:	$(CTEST)
	$(CC) -o $@ $(CTEST) $(LDFLAGS) $(EXTRALDFLAGS)

clean:	
	rm -f $(SRC) $(CSRC) $(CPSRC) tmp-* aeked aeke aeke_cp io_test common_test common_test.o \
		io_test.o 

aeked.o: aeked.c log.h buffer.h utils.h io.h socket.h common.h crypto.h
buffer.o: buffer.c buffer.h utils.h
common.o: common.c buffer.h utils.h io.h socket.h common.h log.h \
  crypto.h
common_test.o: common_test.c buffer.h utils.h io.h socket.h common.h \
  log.h crypto.h
crypto.o: crypto.c buffer.h utils.h io.h socket.h common.h crypto.h \
  log.h
client.o: client.c buffer.h utils.h common.h socket.h
io.o: io.c buffer.h utils.h io.h socket.h log.h
io_test.o: io_test.c buffer.h utils.h io.h socket.h log.h
log.o: log.c
utils.o: utils.c
aeke.o: aeke.c client.h
aeke_cp.o: aeke_cp.c client.h

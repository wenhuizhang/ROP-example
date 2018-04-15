#
# File          : Makefile
# Description   : Build file for CSE543 project 1, applied cryptography
#                 


# Environment Setup
LIBDIRS=-L. -L/opt/local/lib -L/usr/lib
#INCLUDES=-I. -I/opt/local/include
#CC=../afl-2.51b/afl-gcc 
CC=gcc
CFLAGS=-c $(INCLUDES) -g -Wall -m32 -ffreestanding -fno-stack-protector
LINK=gcc -g -m32 -ffreestanding
LDFLAGS=$(LIBDIRS)
AR=ar rc
RANLIB=ranlib

# Suffix rules
.c.o :
	${CC} ${CFLAGS} $< -o $@

#
# Setup builds

TARGETS=buf-attack env-attack sys-attack str-attack
LIBS=

#
# Project Protections

p2 : $(TARGETS)

# cse543-p2 : cse543-pwdmgr.o cse543-cracker.o cse543-kvs.o cse543-util.o cse543-filesys.o cse543-disk.o cse543-list.o
#	$(LINK) $(LDFLAGS) cse543-pwdmgr.o cse543-cracker.o cse543-kvs.o cse543-util.o cse543-filesys.o cse543-disk.o cse543-list.o $(LIBS) -o $@

buf-attack: cse543-buf-attack.o cse543-util.o
	$(LINK) $(LDFLAGS) cse543-buf-attack.o cse543-util.o -o $@

env-attack: cse543-env-attack.o cse543-util.o
	$(LINK) $(LDFLAGS) cse543-env-attack.o cse543-util.o -o $@

sys-attack: cse543-system-attack.o cse543-util.o
	$(LINK) $(LDFLAGS) cse543-system-attack.o cse543-util.o -o $@

str-attack: cse543-string-attack.o cse543-util.o
	$(LINK) $(LDFLAGS) cse543-string-attack.o cse543-util.o -o $@

clean:
	rm -f *.o *~ $(TARGETS)

BASENAME=p2
tar: 
	tar cvfz $(BASENAME).tgz -C ..\
	    $(BASENAME)/Makefile \
            $(BASENAME)/cse543-p2 \
            $(BASENAME)/cse543-pwdmgr.c \
            $(BASENAME)/cse543-buf-attack.c \
            $(BASENAME)/cse543-env-attack.c \
            $(BASENAME)/cse543-system-attack.c \
            $(BASENAME)/cse543-string-attack.c \
            $(BASENAME)/cse543-util.c \
            $(BASENAME)/cse543-util.h

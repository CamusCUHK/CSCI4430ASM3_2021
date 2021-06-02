CC=gcc
CFLAGS= -Wall -Wno-sign-compare -Wno-write-strings -O3 -I./
LDFLAGS=-lnfnetlink -lnetfilter_queue -lm -lpthread

# EXE=nat
# OBJ=nat.o checksum.o

# all: $(EXE)

# $(EXE): nat.c checksum.c
# 	$(CC) $(CFLAGS) -o $(EXE) $(OBJ) $(LDFLAGS) 

# clean:
# 	/bin/rm -f $(OBJ) $(EXE)

# nat.c checksum.c# # # # # # # # # 

all: nat.c checksum.c
	$(CC) $(CFLAGS) -o nat nat.c checksum.c $(LDFLAGS)

CFLAGS := -I../ubpf/inc -I../protocol/src/c -I../bpfmap

all: agent.o

agent.o: multiAgent.c
	$(CC) $(CFLAGS) -o $@ -c $<
	$(AR) cr agent.a agent.o

clean:
	$(RM) -f *.o *.a

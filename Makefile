CC      = gcc
CFLAGS  = -I.
LDFLAGS = -lpthread
DEPS    =
OBJ     = main.o 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

futex-perf: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(OBJ) futex-perf

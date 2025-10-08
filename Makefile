CC      = gcc
CFLAGS  = -O3
LDFLAGS = -lpthread
DEPS    = perf.h
OBJ     = main.o perf.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

futex-perf: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(OBJ) futex-perf

CFLAGS = -Og -ggdb -Wall
LDFLAGS = -lsodium

.PHONY: clean all

all: aes_tests

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

aes_tests: aes_tests.o aes.o
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o *.a aes_tests

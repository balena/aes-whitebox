CFLAGS = -Og -ggdb -Wall -Wno-unused-function
LDFLAGS = -lsodium -lflint -lgmp

.PHONY: clean all

all: aes128_oracle_gen aes128_tests

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

aes128_oracle.o: aes128_oracle.c aes128_oracle_tables.c
	$(CC) $(CFLAGS) -c $< -o $@

libaes128.a: aes128.o
	$(AR) $(ARFLAGS) $@ $^

aes128_oracle_gen: aes128_oracle_gen.o
	$(CC) $(LDFLAGS) $^ -o $@

aes128_oracle_tables.c: aes128_oracle_gen
	./aes128_oracle_gen 80000000000000000000000000000000

libaes128_oracle.a: aes128_oracle.o
	$(AR) $(ARFLAGS) $@ $^

aes128_tests: aes128_tests.o libaes128.a libaes128_oracle.a
	$(CC) $(LDFLAGS) $^ -o $@
	./aes128_tests

clean:
	rm -f *.o *.a aes128_oracle_tables.c aes128_oracle_gen aes128_tests

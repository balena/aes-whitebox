CFLAGS = -Og -ggdb -Wall -Wno-unused-function
CXXFLAGS = $(CFLAGS)

.PHONY: clean all

all: aes128_oracle_gen aes128_tests

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cc
	$(CC) $(CFLAGS) -c $< -o $@

aes128_oracle.o: aes128_oracle.c aes128_oracle_tables.c
	$(CC) $(CFLAGS) -c $< -o $@

libaes128.a: aes128.o
	$(AR) $(ARFLAGS) $@ $^

aes128_oracle_gen: aes128_oracle_gen.o
	$(CXX) $(LDFLAGS) -lntl $^ -o $@

aes128_oracle_tables.c: aes128_oracle_gen
	#./aes128_oracle_gen 000102030405060708090a0b0c0d0e0f
	./aes128_oracle_gen 2b7e151628aed2a6abf7158809cf4f3c

libaes128_oracle.a: aes128_oracle.o
	$(AR) $(ARFLAGS) $@ $^

aes128_tests: aes128_tests.o libaes128.a libaes128_oracle.a
	$(CC) $(LDFLAGS) $^ -o $@
	./aes128_tests

clean:
	rm -f *.o *.a aes128_oracle_tables.c aes128_oracle_gen aes128_tests

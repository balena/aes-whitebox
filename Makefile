CFLAGS = -Og -ggdb -Wall
CXXFLAGS = $(CFLAGS) -std=c++11

.PHONY: clean all

all: aes128_oracle_gen aes128_tests

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

aes128_oracle.o: aes128_oracle.cc aes128_oracle_tables.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

libaes128.a: aes128.o
	$(AR) $(ARFLAGS) $@ $^

aes128_oracle_gen: aes128_oracle_gen.o
	$(CXX) $(LDFLAGS) -lntl $^ -o $@

aes128_oracle_tables.cc: aes128_oracle_gen
	./aes128_oracle_gen 2b7e151628aed2a6abf7158809cf4f3c

libaes128_oracle.a: aes128_oracle.o
	$(AR) $(ARFLAGS) $@ $^

aes128_tests: aes128_tests.o libaes128.a libaes128_oracle.a
	$(CC) $(LDFLAGS) $^ -o $@
	./aes128_tests

clean:
	rm -f *.o *.a aes128_oracle_tables.cc aes128_oracle_gen aes128_tests

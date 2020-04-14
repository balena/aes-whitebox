CFLAGS = -Og -ggdb -Wall
CXXFLAGS = $(CFLAGS) -std=c++11

# All tests were taken from NIST, 2001 test vectors:
# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

TEST_PLAIN = 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710

AES128_KEY             = 2b7e151628aed2a6abf7158809cf4f3c
AES128_CFB_TEST_CIPHER = 3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6
AES128_CFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES128_OFB_TEST_CIPHER = 3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e
AES128_OFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES128_CTR_TEST_CIPHER = 874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee
AES128_CTR_TEST_NONCE  = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff

AES192_KEY             = 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
AES192_CFB_TEST_CIPHER = cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff
AES192_CFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES192_OFB_TEST_CIPHER = cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a
AES192_OFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES192_CTR_TEST_CIPHER = 1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050
AES192_CTR_TEST_NONCE  = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff

AES256_KEY             = 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
AES256_CFB_TEST_CIPHER = dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471
AES256_CFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES256_OFB_TEST_CIPHER = dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484
AES256_OFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES256_CTR_TEST_CIPHER = 601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6
AES256_CTR_TEST_NONCE  = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff

.PHONY: clean all

all: aes128_tests aes192_tests aes256_tests

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

libaes.a: aes.o
	$(AR) $(ARFLAGS) $@ $^

aes_whitebox_compiler: aes_whitebox_compiler.o
	$(CXX) $(LDFLAGS) $^ -o $@ -lntl

aes128_tests: aes_whitebox_compiler
	./aes_whitebox_compiler aes128 $(AES128_KEY)
	$(CXX) $(CXXFLAGS) -c aes_whitebox.cc -o aes_whitebox.o
	$(CC) $(CFLAGS) -c aes_tests.c -o aes_tests.o
	$(CC) $(LDFLAGS) aes_whitebox.o aes_tests.o -o $@
	./$@ cfb $(TEST_PLAIN) $(AES128_CFB_TEST_IV) $(AES128_CFB_TEST_CIPHER)
	./$@ ofb $(TEST_PLAIN) $(AES128_OFB_TEST_IV) $(AES128_OFB_TEST_CIPHER)
	./$@ ctr $(TEST_PLAIN) $(AES128_CTR_TEST_NONCE) $(AES128_CTR_TEST_CIPHER)

aes192_tests: aes_whitebox_compiler
	./aes_whitebox_compiler aes192 $(AES192_KEY)
	$(CXX) $(CXXFLAGS) -c aes_whitebox.cc -o aes_whitebox.o
	$(CC) $(CFLAGS) -c aes_tests.c -o aes_tests.o
	$(CC) $(LDFLAGS) aes_whitebox.o aes_tests.o -o $@
	./$@ cfb $(TEST_PLAIN) $(AES192_CFB_TEST_IV) $(AES192_CFB_TEST_CIPHER)
	./$@ ofb $(TEST_PLAIN) $(AES192_OFB_TEST_IV) $(AES192_OFB_TEST_CIPHER)
	./$@ ctr $(TEST_PLAIN) $(AES192_CTR_TEST_NONCE) $(AES192_CTR_TEST_CIPHER)

aes256_tests: aes_whitebox_compiler
	./aes_whitebox_compiler aes256 $(AES256_KEY)
	$(CXX) $(CXXFLAGS) -c aes_whitebox.cc -o aes_whitebox.o
	$(CC) $(CFLAGS) -c aes_tests.c -o aes_tests.o
	$(CC) $(LDFLAGS) aes_whitebox.o aes_tests.o -o $@
	./$@ cfb $(TEST_PLAIN) $(AES256_CFB_TEST_IV) $(AES256_CFB_TEST_CIPHER)
	./$@ ofb $(TEST_PLAIN) $(AES256_OFB_TEST_IV) $(AES256_OFB_TEST_CIPHER)
	./$@ ctr $(TEST_PLAIN) $(AES256_CTR_TEST_NONCE) $(AES256_CTR_TEST_CIPHER)

clean:
	rm -f *.o *.a aes_whitebox_tables.cc aes_whitebox_compiler aes128_tests aes192_tests aes256_tests

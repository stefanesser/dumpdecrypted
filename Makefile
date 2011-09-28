BIN = /Developer/Platforms/iPhoneOS.platform/Developer/usr/bin
GCC_BIN = $(BIN)/gcc-4.2
#GCC = $(GCC_BASE) -arch armv6
GCC = $(GCC_BASE) -arch armv7
GCC_UNIVERSAL = $(GCC_BASE) -arch armv6 -arch armv7
GCC_NATIVE = gcc
SDK=/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.3.sdk/

CFLAGS = 
GCC_BASE = $(GCC_BIN) -Os $(CFLAGS) -Wimplicit -isysroot $(SDK) -F$(SDK)System/Library/Frameworks -F$(SDK)System/Library/PrivateFrameworks

all: dumpdecrypted.dylib

dumpdecrypted.dylib: dumpdecrypted.o 
	$(GCC_UNIVERSAL) -dynamiclib -o $@ $^

%.o: %.c
	$(GCC_UNIVERSAL) -dynamiclib -c -o $@ $< 

clean:
	rm -f *.o dumpdecrypted.dylib

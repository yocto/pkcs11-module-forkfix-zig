all: clean build install

build:
	if [ ! -f "./include/pkcs11.h" ];then chmod +x *.sh && ./download_headers.sh; fi
	mkdir -p bin
	zig build

install:
	mkdir -p /usr/lib/pkcs11/
	cp zig-out/lib/libpkcs11-forkfix.so /usr/lib/pkcs11/pkcs11-forkfix.so
	chmod +x /usr/lib/pkcs11/pkcs11-forkfix.so

clean:
	rm -Rf bin

.PHONY: all build install clean
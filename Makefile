# Where you want it installed when you do 'make install'
PREFIX=/usr/local
# Where you want the includes to go when you do 'make install'
IPREFIX=/usr/local

# You shouldn't have to touch the rest unless the compile is failing for some reason?
DISTNAME=b0
VERSION=0.0.23
SRC=./src
EXAMPLE_DIR=./examples
B0_SRC=$(SRC)/b0.b0 $(SRC)/b0.h.b0 $(SRC)/core.b0 $(SRC)/b0_libc.b0 $(SRC)/b0_linux.b0 $(SRC)/b0_win64.b0 $(SRC)/b0_freebsd.b0 $(SRC)/b0_stdlib.b0 $(SRC)/b0_variables.b0 $(SRC)/b0_preprocess.b0

# To assist in cross-compiling
CC=gcc
AS=fasm
CFLAGS=-Wall -O2 -mtune=opteron -m64 -I$(SRC)
LDFLAGS=
ASFLAGS=-m524000
DIFF=gdiff

#flags for ghostscript and html2ps
GS=gs
GSFLAGS=-sDEVICE=pdfwrite -q -dNOPAUSE -dBATCH
HTML2PS=html2ps

#flags for building the examples
B0_FLAGS=-W
B0_FLAGS_EX=-W -felf

#Solaris Package
PKG=B0core
#possible ARCH values are i386, sparc, all
ARCH=i386
VER=v$(VERSION)
PKGFILE=$(PKG)-$(VER)-$(ARCH).pkg

all: b0

#We build the C version by default (since it's the one that works on all *nix platforms)
b0: b0_bootstrap $(B0_SRC)
	mv b0_bootstrap b0
	
b0_bootstrap: $(SRC)/b0.c $(SRC)/b0.h
	$(CC) $(CFLAGS) -s $(LDFLAGS) -o b0_bootstrap $(SRC)/b0.c

libc:  b0_bootstrap $(B0_SRC)
	rm -f src/b0.inc
	echo "#define UNIX_LIBC;" > src/b0.inc
	./b0_bootstrap $(B0_FLAGS) -felfo -i./src:./include $(SRC)/b0.b0
	$(AS) $(ASFLAGS) $(SRC)/b0.asm ./b0.o
	$(CC) $(CFLAGS) $(LDFLAGS) -s -o b0 b0.o
	rm -f $(SRC)/b0.asm ./b0.o
	
linux:  b0_bootstrap $(B0_SRC)
	rm -f src/b0.inc
	echo "#define LINUX;" > src/b0.inc
	./b0_bootstrap $(B0_FLAGS) -felf -i./src:./include $(SRC)/b0.b0
	$(AS) $(ASFLAGS) $(SRC)/b0.asm ./b0
	brandelf -t Linux ./b0

freebsd:  b0_bootstrap $(B0_SRC)
	rm -f src/b0.inc
	echo "#define FREEBSD;" > src/b0.inc
	./b0_bootstrap $(B0_FLAGS) -felfo -i./src:./include $(SRC)/b0.b0
	$(AS) $(ASFLAGS) $(SRC)/b0.asm ./b0.o
	$(CC) $(CFLAGS) $(LDFLAGS) -s -o b0 b0.o
	rm -f $(SRC)/b0.asm ./b0.o
	
solaris:  b0_bootstrap $(B0_SRC)
	rm -f src/b0.inc
	echo "#define SOLARIS;" > src/b0.inc
	./b0_bootstrap $(B0_FLAGS) -felfo -i./src:./include $(SRC)/b0.b0
	$(AS) $(ASFLAGS) $(SRC)/b0.asm ./b0.o
	$(CC) $(CFLAGS) $(LDFLAGS) -s -o b0 b0.o
	rm -f $(SRC)/b0.asm ./b0.o
	
b0_o: $(B0_SRC)
	rm -f src/b0.inc
	echo "#define SYSV_ELFO;" > src/b0.inc
	./b0 $(B0_FLAGS) -felfo -i./src:./include $(SRC)/b0.b0
	$(AS) -m512000 $(SRC)/b0.asm ./b0.o
	rm -f $(SRC)/b0.asm 
	
clean: 
	rm -f *.o *.asm *.tmp *~ *.core core b0 b0_bootstrap $(DISTNAME)-$(VERSION).tar.bz2 $(DISTNAME)-$(VERSION).tar.gz *.gz *.pdf *.ps $(EXAMPLE_DIR)/*.as* $(EXAMPLE_DIR)/*.o $(EXAMPLE_DIR)/*~ $(SRC)/*.as* $(SRC)/*.o $(SRC)/*~ include/*~ doc/*~ doc/css/*~
	
docs: ./doc/b0-man.html
	$(HTML2PS) -o b0.ps ./doc/b0-man.html
	$(GS) $(GSFLAGS) -sOutputFile=b0.pdf b0.ps
	rm -f ./b0.ps

install: b0
	if ( test ! -d $(PREFIX)/bin ) ; then mkdir -p $(PREFIX)/bin ; fi
	if ( test ! -d $(IPREFIX)/include ) ; then mkdir -p $(IPREFIX)/include ; fi
	if ( test ! -d $(IPREFIX)/include/b0 ) ; then mkdir -p $(IPREFIX)/include/b0 ; fi
	cp -f b0 $(PREFIX)/bin/b0
	chmod a+x $(PREFIX)/bin/b0
	cp -f ./include/* \
		$(IPREFIX)/include/b0
	cp -f ./doc/b0.man $(PREFIX)/man/man1/b0.1
	@echo 
	@echo Please set environment variable BO_INCLUDE=$(IPREFIX)/include/b0
	@echo 

uninstall:
	rm -fR $(IPREFIX)/include/b0
	rm -f $(PREFIX)/bin/b0
	rm -f $(PREFIX)/man/man1/b0.1
	
dist:
	rm -f $(DISTNAME)-$(VERSION).tar.gz
	ln -sf . $(DISTNAME)-$(VERSION)
	tar -cf $(DISTNAME)-$(VERSION).tar \
	   $(DISTNAME)-$(VERSION)/README \
	   $(DISTNAME)-$(VERSION)/Makefile \
	   $(DISTNAME)-$(VERSION)/build.cmd \
	   $(DISTNAME)-$(VERSION)/COPYING \
	   $(DISTNAME)-$(VERSION)/examples/* \
	   $(DISTNAME)-$(VERSION)/doc/* \
	   $(DISTNAME)-$(VERSION)/include/* \
	   $(DISTNAME)-$(VERSION)/src/* 
	gzip $(DISTNAME)-$(VERSION).tar
	rm -f $(DISTNAME)-$(VERSION)
	
pkg:
	pkgmk -o -d /tmp -a $(ARCH)
	touch $(PKGFILE)
	pkgtrans -s /tmp $(PKGFILE) $(PKG) 
	rm -r /tmp/$(PKG)
	gzip $(PKGFILE)
	@echo check current directory for .pkg.gz files

test-libc: b0
	./b0 -felfo -i./src -i./include -v ./src/b0.b0
	$(AS) $(ASFLAGS) $(SRC)/b0.asm ./b0.o
	$(CC) $(CFLAGS) $(LDFLAGS) -s -o b0_b02 b0.o
	mv ./src/b0.asm ./src/b0.asm_b0
	./b0_b02 -felfo -i./src -i./include -v ./src/b0.b0
	$(AS) $(ASFLAGS) $(SRC)/b0.asm ./b0.o
	$(CC) $(CFLAGS) $(LDFLAGS) -s -o b0_b03 b0.o
	mv ./src/b0.asm ./src/b0.asm_b02
	./b0_b03 -felfo -i./src -i./include -v ./src/b0.b0
	$(DIFF) -q -a ./src/b0.asm ./src/b0.asm_b0 
	$(DIFF) -q -a ./src/b0.asm_b0 ./src/b0.asm_b02 
	rm ./src/b0.asm ./src/b0.asm_b0 ./src/b0.asm_b02 ./b0.o ./b0_b02 ./b0_b03
	
test-linux: b0
	./b0 -felf -i./src -v ./src/b0.b0
	$(AS) $(ASFLAGS) $(SRC)/b0.asm ./b0_b02
	brandelf -t Linux ./b0_b02
	mv ./src/b0.asm ./src/b0.asm_b0
	./b0_b02 -felf -i./src -v ./src/b0.b0
	$(AS) $(ASFLAGS) $(SRC)/b0.asm ./b0_b03
	brandelf -t Linux ./b0_b03
	mv ./src/b0.asm ./src/b0.asm_b02
	./b0_b03 -felf -i./src -v ./src/b0.b0
	$(DIFF) -q -a ./src/b0.asm ./src/b0.asm_b0 
	$(DIFF) -q -a ./src/b0.asm_b0 ./src/b0.asm_b02 
	rm ./src/b0.asm ./src/b0.asm_b0 ./src/b0.asm_b02 ./b0_b02 ./b0_b03
	
test-freebsd: b0
	./b0 -felfo -i./src -i./include -v ./src/b0.b0
	$(AS) $(ASFLAGS) $(SRC)/b0.asm ./b0.o
	$(CC) $(CFLAGS) $(LDFLAGS) -s -o b0_b02 b0.o
	mv ./src/b0.asm ./src/b0.asm_b0
	./b0_b02 -felfo -i./src  -i./include -v ./src/b0.b0
	$(AS) $(ASFLAGS) $(SRC)/b0.asm ./b0.o
	$(CC) $(CFLAGS) $(LDFLAGS) -s -o b0_b03 b0.o
	mv ./src/b0.asm ./src/b0.asm_b02
	./b0_b03 -felfo -i./src -i./include -v ./src/b0.b0
	$(DIFF) -q -a ./src/b0.asm ./src/b0.asm_b0 
	$(DIFF) -q -a ./src/b0.asm_b0 ./src/b0.asm_b02 
	rm ./src/b0.asm ./src/b0.asm_b0 ./src/b0.asm_b02 ./b0.o ./b0_b02 ./b0_b03


CC = gcc -O2 -Wall
VER = 0.09
RPM_ROOT = /home/wojtekka/rpm

default:
	@echo -e -- \\033[1m6tunnel\\033[0m make --
	@if [ -d /usr/local/v6/lib ]; then make KAME; else make generic; fi
generic:
	$(CC) 6tunnel.c -o 6tunnel
KAME:
	$(CC) 6tunnel.c -o 6tunnel -L/usr/local/v6/lib -linet6

install:
	@case $$(uname -s) in \
	  *BSD) make install-bsd;; \
	  *) make install-generic;; \
	esac

install-generic:	default
	strip 6tunnel
	install 6tunnel /usr/local/bin
	install	6tunnel.1 /usr/local/man/man1

install-bsd:	default
	strip 6tunnel
	install 6tunnel /usr/local/bin
	install	6tunnel.1 /usr/local/share/man/man1
	
targz:	clean
	cd ..; tar zcvf 6tunnel/6tunnel-$(VER).tar.gz --exclude 6tunnel/6tunnel-$(VER).tar.gz --exclude 6tunnel/older 6tunnel

rpm:	targz
	sed 's/#VERSION#/$(VER)/' < 6tunnel.spec > $(RPM_ROOT)/SPECS/6tunnel.spec
	cp 6tunnel-$(VER).tar.gz $(RPM_ROOT)/SOURCES
	rpm -ba $(RPM_ROOT)/SPECS/6tunnel.spec
	rm -rf $(RPM_ROOT)/BUILD/6tunnel
	rm -f $(RPM_ROOT)/SOURCE/6tunnel-$(VER).tar.gz
#	rm -f $(RPM_ROOT)/SPECS/6tunnel.spec
	mv $(RPM_ROOT)/{RPMS/i386,SRPMS}/6tunnel-*.rpm .
	
clean:
	rm -f 6tunnel *.o *~ core 6tunnel-*.{tar.gz,rpm}

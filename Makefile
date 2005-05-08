CC = gcc -O2 -Wall
VER = 0.03
RPM_ROOT = /home/wojtekka/rpm

default:
	@echo -e -- \\033[1m6tunnel\\033[0m make --
	@case $$(./uname -s) in \
	  Linux) make Linux;; \
	  *BSD) make BSD;; \
	  *) echo "$$(uname -s) is not supported";; \
	esac 

Linux:
	$(CC) 6tunnel.c -o 6tunnel

BSD:
	$(CC) 6tunnel.c -o 6tunnel -L/usr/local/v6/lib -linet6

install:	default
	strip 6tunnel
	install 6tunnel /usr/bin

targz:	clean
	cd ..; tar zcvf 6tunnel/6tunnel-$(VER).tar.gz --exclude 6tunnel/6tunnel-$(VER).tar.gz --exclude 6tunnel/older 6tunnel

rpm:	targz
	cp 6tunnel.spec $(RPM_ROOT)/SPECS
	cp 6tunnel-$(VER).tar.gz $(RPM_ROOT)/SOURCES
	rpm -ba $(RPM_ROOT)/SPECS/6tunnel.spec
	rm -rf $(RPM_ROOT)/BUILD/6tunnel
	rm -f $(RPM_ROOT)/SOURCE/6tunnel-$(VER).tar.gz
	rm -f $(RPM_ROOT)/SPECS/6tunnel.spec
	mv $(RPM_ROOT)/{RPMS/i386,SRPMS}/6tunnel-*.rpm .
	
clean:
	rm -f 6tunnel *.o *~ core 6tunnel-*.{tar.gz,rpm}

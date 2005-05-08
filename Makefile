CC = gcc -O2 -Wall
VER = 0.01
RPM_ROOT = /home/wojtekka/rpm

all:
	$(CC) 6tunnel.c -o 6tunnel
	strip 6tunnel

install:
	install 6tunnel /usr/bin

tar:	clean
	cd ..; tar zcvf 6tunnel/6tunnel-$(VER).tar.gz --exclude 6tunnel/6tunnel-$(VER).tar.gz 6tunnel

rpm:	tar
	cp 6tunnel.spec $(RPM_ROOT)/SPECS
	cp 6tunnel-$(VER).tar.gz $(RPM_ROOT)/SOURCES
	rpm -ba $(RPM_ROOT)/SPECS/6tunnel.spec
	rm -rf $(RPM_ROOT)/BUILD/6tunnel
	rm -f $(RPM_ROOT)/SOURCE/6tunnel-$(VER).tar.gz
	rm -f $(RPM_ROOT)/SPECS/6tunnel.spec
	mv $(RPM_ROOT)/{RPMS/i386,SRPMS}/6tunnel-*.rpm .
	
clean:
	rm -f 6tunnel *.o *~ core 6tunnel-*.{tar.gz,rpm}

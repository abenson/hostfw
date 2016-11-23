MANPREFIX=/usr/share/man
PREFIX=/sbin

all:
	@echo "Run \"make install\" to install."
	@echo "Edit this file to change installation directories."

man: firewall.1.gz

firewall.1: firewall.1.md
	pandoc -s -t man -o firewall.1 firewall.1.md

firewall.1.gz: firewall.1
	gzip -f -c firewall.1 > firewall.1.gz

install:
	/usr/bin/install -g root -o root -m 0755 -p firewall $(PREFIX)/firewall
	/usr/bin/install -g root -o root -m 0644 -p firewall.1.gz $(MANPREFIX)/man1/firewall.1.gz


DESTDIR=
PREFIX=/usr
SBINDIR=$(PREFIX)/sbin
# bookworm's systemd debhelper do not understand unit files shiped in /usr yet.
SERVICEDIR=/lib/systemd/system
MANDIR=$(PREFIX)/share/man

-include /usr/share/pve-doc-generator/pve-doc-generator.mk

CFLAGS += -O2 -Werror -Wall -Wextra -Wpedantic -Wtype-limits -Wl,-z,relro -std=gnu11
CFLAGS += $(shell $(PKG_CONFIG) --cflags json-c glib-2.0)
LDFLAGS += $(shell $(PKG_CONFIG) --libs json-c glib-2.0)

SOURCES = qmeventd.c qmeventd-log.c qmeventd-monitor.c
HEADERS = qmeventd.h qmeventd-log.h qmeventd-monitor.h

qmeventd: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

qmeventd-monitor-test: qmeventd-monitor-test.c qmeventd-monitor.c qmeventd-monitor.h
	$(CC) $(CFLAGS) -o $@ qmeventd-monitor-test.c qmeventd-monitor.c $(LDFLAGS)

.PHONY: unit-test
unit-test: qmeventd-monitor-test
	./qmeventd-monitor-test

# plus an end-to-end run of the daemon against a fake QEMU and guest agent
# (needs python3, not part of the package build)
.PHONY: test
test: unit-test qmeventd
	python3 test-qmeventd-events.py ./qmeventd

docs: qmeventd.8

.PHONY: install
install: qmeventd docs
	install -d $(DESTDIR)/$(SBINDIR)
	install -m 0755 qmeventd $(DESTDIR)/$(SBINDIR)
	install -d $(DESTDIR)/$(SERVICEDIR)
	install -m 0644 qmeventd.service $(DESTDIR)/$(SERVICEDIR)
	install -d $(DESTDIR)/$(MANDIR)/man8
	install -m 0644 qmeventd.8 $(DESTDIR)/$(MANDIR)/man8

.PHONY: clean
clean:
	$(MAKE) cleanup-docgen
	rm -rf qmeventd qmeventd-monitor-test

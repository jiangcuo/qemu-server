DESTDIR=
PREFIX=/usr
SBINDIR=$(PREFIX)/sbin
# Fixed production location of the supervised capture worker (see
# QMEV_CAPTURE_WORKER_PATH in qmeventd-capture.h).
LIBEXECDIR=$(PREFIX)/libexec/qemu-server
# bookworm's systemd debhelper do not understand unit files shiped in /usr yet.
SERVICEDIR=/lib/systemd/system
MANDIR=$(PREFIX)/share/man

-include /usr/share/pve-doc-generator/pve-doc-generator.mk

# The doc generator is optional. When it is not installed its cleanup-docgen
# target does not exist, and `make clean` (also reached via `make -C src
# clean`) must still succeed.
ifeq ($(wildcard /usr/share/pve-doc-generator/pve-doc-generator.mk),)
cleanup-docgen:
	@:
endif

CFLAGS += -O2 -Werror -Wall -Wextra -Wpedantic -Wtype-limits -Wl,-z,relro -std=gnu11
CFLAGS += $(shell $(PKG_CONFIG) --cflags json-c glib-2.0)
LDFLAGS += $(shell $(PKG_CONFIG) --libs json-c glib-2.0)

QMEVENTD_SOURCES = qmeventd.c qmeventd-log.c qmeventd-capture.c

qmeventd: $(QMEVENTD_SOURCES) qmeventd.h qmeventd-log.h qmeventd-capture.h
	$(CC) $(CFLAGS) -o $@ $(QMEVENTD_SOURCES) $(LDFLAGS)

qmeventd-log.o: qmeventd-log.c qmeventd-log.h
	$(CC) $(CFLAGS) -c -o $@ $<

qmeventd-capture.o: qmeventd-capture.c qmeventd-capture.h qmeventd-log.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Unit/protocol regression tests. Process side effects are replaced with
# linker --wrap doubles; this target never contacts a real VM or socket.
qmeventd-test: qmeventd-test.c qmeventd.c qmeventd-log.o qmeventd-capture.o qmeventd.h qmeventd-log.h qmeventd-capture.h
	$(CC) $(CFLAGS) -o $@ qmeventd-test.c qmeventd-log.o qmeventd-capture.o $(LDFLAGS) \
	    -Wl,--wrap=kill -Wl,--wrap=fork -Wl,--wrap=execvp -Wl,--wrap=_exit -Wl,--wrap=fopen

# Focused tests for the capture bridge. The module is compiled into the test
# translation unit, so only the (injected) seams and json-c/glib are needed.
qmeventd-capture-test: qmeventd-capture-test.c qmeventd-capture.c qmeventd-capture.h qmeventd-log.h
	$(CC) $(CFLAGS) -o $@ qmeventd-capture-test.c qmeventd-log.o $(LDFLAGS)

.PHONY: test
test: qmeventd-test qmeventd-capture-test python-test
	./qmeventd-test
	./qmeventd-capture-test

# The worker is a required part of the daemon package and test suite.
WORKER_ENTRY = qmeventd-worker
WORKER_MODULES = qmeventd_capture.py

.PHONY: python-test
python-test: test_capture_worker.py test_capture_regressions.py test_build_integration.py $(WORKER_MODULES)
	python3 -m unittest -v test_capture_worker test_capture_regressions test_build_integration

.PHONY: test-all
test-all: test python-test

docs: qmeventd.8

.PHONY: install-worker
install-worker: $(WORKER_ENTRY) $(WORKER_MODULES)
	install -d $(DESTDIR)/$(LIBEXECDIR)
	install -m 0755 $(WORKER_ENTRY) $(DESTDIR)/$(LIBEXECDIR)/
	install -m 0644 $(WORKER_MODULES) $(DESTDIR)/$(LIBEXECDIR)/
	install -d -m 0700 $(DESTDIR)/var/lib/qemu-server/screenshots

.PHONY: install
install: qmeventd docs install-worker
	install -d $(DESTDIR)/$(SBINDIR)
	install -m 0755 qmeventd $(DESTDIR)/$(SBINDIR)
	install -d $(DESTDIR)/$(SERVICEDIR)
	install -m 0644 qmeventd.service $(DESTDIR)/$(SERVICEDIR)
	install -d $(DESTDIR)/$(MANDIR)/man8
	install -m 0644 qmeventd.8 $(DESTDIR)/$(MANDIR)/man8

.PHONY: clean
clean:
	$(MAKE) cleanup-docgen
	rm -rf qmeventd qmeventd-log.o qmeventd-capture.o qmeventd-test qmeventd-capture-test

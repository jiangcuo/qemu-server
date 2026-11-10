DESTDIR=
PREFIX=/usr
PERLDIR=$(PREFIX)/share/perl5

SOURCES=PCI.pm		\
	RNG.pm		\
	USB.pm		\
	Memory.pm	\
	ImportDisk.pm	\
	Cloudinit.pm	\
	Autoinstall.pm	\
	Timezone.pm	\
	Agent.pm	\
	Events.pm	\
	Helpers.pm	\
	Monitor.pm	\
	Machine.pm	\
	MetaInfo.pm	\
	CPUConfig.pm	\
	CGroup.pm	\
	Drive.pm	\
	QMPHelpers.pm	\
	Spdk.pm	\
	OVMF.pm	\
	Virtiofs.pm	\
	VMHook.pm


.PHONY: install
install: $(SOURCES)
	for i in $(SOURCES); do install -D -m 0644 $$i $(DESTDIR)$(PERLDIR)/PVE/QemuServer/$$i; done

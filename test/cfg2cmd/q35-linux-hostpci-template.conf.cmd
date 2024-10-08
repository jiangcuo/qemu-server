/usr/bin/kvm \
  -id 8006 \
  -name 'vm8006,debug-threads=on' \
  -no-shutdown \
  -chardev 'socket,id=qmp,path=/var/run/qemu-server/8006.qmp,server=on,wait=off' \
  -mon 'chardev=qmp,mode=control' \
  -chardev 'socket,id=qmp-event,path=/var/run/qmeventd.sock,reconnect=5' \
  -mon 'chardev=qmp-event,mode=control' \
  -pidfile /var/run/qemu-server/8006.pid \
  -daemonize \
  -drive 'if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/pve-edk2-firmware//OVMF_CODE.fd' \
  -drive 'if=pflash,unit=1,id=drive-efidisk0,format=qcow2,file=/var/lib/vz/images/100/base-100-disk-1.qcow2,readonly=on' \
  -smp '1,sockets=1,cores=1,maxcpus=1' \
  -nodefaults \
  -boot 'menu=on,strict=on,reboot-timeout=1000,splash=/usr/share/qemu-server/bootsplash.jpg' \
  -vga none \
  -nographic \
  -cpu qemu64 \
  -m 512 \
  -device 'pci-bridge,id=pci.1,chassis_nr=1,bus=pci.0,addr=0x1e' \
  -device 'pci-bridge,id=pci.2,chassis_nr=2,bus=pci.0,addr=0x1f' \
  -device 'piix3-usb-uhci,id=uhci,bus=pci.0,addr=0x1.0x2' \
  -device 'usb-tablet,id=tablet,bus=uhci.0,port=1' \
  -device 'virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x3,free-page-reporting=on' \
  -iscsi 'initiator-name=iqn.1993-08.org.debian:01:aabbccddeeff' \
  -device 'virtio-scsi-pci,id=scsihw0,bus=pci.0,addr=0x5' \
  -drive 'file=/var/lib/vz/images/100/base-100-disk-2.raw,if=none,id=drive-scsi0,format=raw,cache=none,aio=io_uring,detect-zeroes=on,readonly=on' \
  -device 'scsi-hd,bus=scsihw0.0,channel=0,scsi-id=0,lun=0,drive=drive-scsi0,id=scsi0' \
  -machine 'accel=tcg,type=pc+pve0' \
  -snapshot
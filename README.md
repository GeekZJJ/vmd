# macOS vmd
The vmd application from OpenBSD has been adjusted to work on macOS.
This version uses the Apple Hypervisor Framework, which came with macOS Big Sur.

This tool is like SimpleVM and vftool, but followes the vmd/vmctl syntax.

### Requirements
  - macOS >= 11.0

### Compile
```
make
```

### Run
To start the VM in verbose mode:
```
./vmctl -v start -cb openwrt/bzImage \
	-k "console=hvc0 root=/dev/vda rootwait noinitrd" \
	-d openwrt/openwrt-x86-64-generic-ext4-rootfs.img \
	-m 1g \
	-p 1 \
	-n nat -n host \
	openwrt
```

This will automatically spawn a new console session to interact with the guest.

Multiple disks can be attached by repeating the -d flag.

The -l flag can be used to specify the link layer address (MAC address). This
should be specified as six colon-separated hex values.

### Shutdown
To shutdown a running VM press CTRL+C in the terminal, or send the SIGINT
signal. When a cu session is still running, first enter ~., and then CTRL+C.
Keep repeating the signal to forcefully shutdown the VM.

### Console handling
The program cu is used to facilitate the console. When the -c flag has been used
with vmctl, then the console will automatically open. The uucp directory must be
writable, which can be fixed with:
``` shell
$ ls -alh /var/spool/uucp
total 0
drwxr-xr-x  2 _uucp  wheel    64B  7 26 21:03 .
drwxr-xr-x  6 root   wheel   192B  1  1  2020 ..

$ sudo chmod 775 /var/spool/uucp/
$ sudo chgrp staff /var/spool/uucp/

$ ls -alh /var/spool/uucp
total 0
drwxrwxr-x  2 _uucp  staff    64B  7 26 21:03 .
drwxr-xr-x  6 root   wheel   192B  1  1  2020 ..
```

If cu doesn't respond to ~ commands, make sure to enter CTRL+D first.

### Linux guests
Currently, only Linux guests are supported due to the framework limitations. Not
all distributions support the virtio console out of the box (like Debian). Make
sure to boot these systems with `console=tty1`, so you can add the required
modules to `/etc/initramfs-tools/modules`:
```
virtio
virtio_pci
virtio_blk
virtio_net
virtio_console
```
After changing the modules file re-create the initramfs image:
```
update-initramfs -u
```

Copy the new initramfs image to the host, and then you should be able to use
the virtio console (hvc0).

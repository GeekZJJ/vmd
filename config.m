/*
 * OpenBSD vmd/vmctl modified for macOS with Apple Hypervisor Framework
 */

/*
 * Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>

#include <err.h>
#include <sys/stat.h>
#include <sys/tty.h>
#include "vmctl.h"
#include "vmd.h"
#include "vmnet.h"


int
vmcfg_init(struct parse_result *res, struct vmconfig *vmcfg)
{
	NSError *error = nil;

	/* OpenTTY */
	if (vm_opentty(vmcfg))
		goto err;

	/* Configure VM */
	if (vmcfg_vhw(res, vmcfg->vm))
		goto err;
#ifdef WITH_EFI
	if (res->efi) {
		if (vmcfg_efi_boot(res, vmcfg->vm))
			goto err;
	} else {
		if (vmcfg_boot(res, vmcfg->vm))
			goto err;
	}
#else
	if (vmcfg_boot(res, vmcfg->vm))
		goto err;
#endif
	if (vmcfg_storage(res, vmcfg->vm))
		goto err;
	if (vmcfg_net(res, vmcfg->vm))
		goto err;
	if (vmcfg_console(res, vmcfg))
		goto err;
	if (vmcfg_misc(res, vmcfg->vm))
		goto err;

	/* Validate configuration */
	error = nil;
	[vmcfg->vm validateWithError:&error];
	if (error)
		goto err;

	vmcfg->name = strdup(res->name);

	if (verbose > 1)
		NSLog(@"Succesfully initialized VM %s", vmcfg->name);


	return (0);
err:
	if (error)
		NSLog(@"Failed to initialize VM configuration: %@", error);
	else
		NSLog(@"Failed to initialize VM configuration");

	return (-1);
}

int
vmcfg_vhw(struct parse_result *res, VZVirtualMachineConfiguration *vmcfg)
{
	NSError *error = nil;

	[vmcfg setCPUCount:res->vcpu];
	[vmcfg setMemorySize:res->size];

	if (error)
		goto err;

	return (0);
err:
	NSLog(@"Unable to configure vCPU or memory: %@", error);
	return (-1);
}

#ifdef WITH_EFI

/*
 * XXX: Requires macOS Ventura
 */

int
vmcfg_efi_boot(struct parse_result *res, VZVirtualMachineConfiguration *vmcfg)
{
	NSError *error = nil;
	NSURL *variableStoreURL = [NSURL fileURLWithPath:@"nvram.var"];
	VZEFIVariableStoreInitializationOptions opt = 0;

	VZEFIBootLoader *efi = [
		[VZEFIBootLoader alloc]
		init
	];

	VZGenericMachineIdentifier *mid = [
		[VZGenericMachineIdentifier alloc]
		init
	];

	VZGenericPlatformConfiguration *platform = [
		[VZGenericPlatformConfiguration alloc]
		init
	];

	VZEFIVariableStore *vars = [
			[VZEFIVariableStore alloc]
			initCreatingVariableStoreAtURL:variableStoreURL
			options:opt
			error:&error
	];

	/* XXX: machineIdentifier should be written to disk */
	[platform setMachineIdentifier:mid];

	[efi setVariableStore:vars];
	[vmcfg setPlatform:platform];
	[vmcfg setBootLoader:efi];

	if (error)
		goto err;

	return (0);
err:
	NSLog(@"Unable to configure EFI boot loader: %@", error);
	return (-1);
}
#endif

int
vmcfg_boot(struct parse_result *res, VZVirtualMachineConfiguration *vmcfg)
{
	NSError *error = nil;
	NSURL *kernelURL = [NSURL fileURLWithPath:res->kernelpath];
	NSURL *initrdURL;

	/* Linux bootloader and initramfs  */
	VZLinuxBootLoader *linux = [
		[VZLinuxBootLoader alloc]
		initWithKernelURL:kernelURL
	];

	if (res->kernelcmdline)
		[linux setCommandLine:res->kernelcmdline];

	if (res->initrdpath) {
		initrdURL = [NSURL fileURLWithPath:res->initrdpath];
		[linux setInitialRamdiskURL:initrdURL];
	}
	[vmcfg setBootLoader:linux];

	if (error)
		goto err;

	if (verbose > 1) {
		NSLog(@"Assigned file \"%@\" to kernel",
		[res->kernelpath lastPathComponent]
		);
		if (res->initrdpath) {
			NSLog(@"Assigned file \"%@\" to initramfs",
			[res->initrdpath lastPathComponent]
			);
		}
	}
	return (0);
err:
	NSLog(@"Unable to configure boot loader: %@", error);
	return (-1);
}

VZBridgedNetworkInterface *get_bridge_interface(NSString *ifacename) {
	NSArray *hostInterfaces = VZBridgedNetworkInterface.networkInterfaces;
	for (VZBridgedNetworkInterface *hostIface in hostInterfaces)
		if ([hostIface.identifier isEqualToString: ifacename]) {
			return hostIface;
		}
	return nil;
}

int netdev_add_nat(NSArray **ndevs, VZMACAddress* macaddr) {
	VZVirtioNetworkDeviceConfiguration *vnet = [
		[VZVirtioNetworkDeviceConfiguration alloc]
		init
	];
	VZNetworkDeviceAttachment *nat = [
		[VZNATNetworkDeviceAttachment alloc]
		init
	];
	[vnet setMACAddress:macaddr];
	[vnet setAttachment:nat];
	*ndevs = [*ndevs arrayByAddingObject:vnet];
	return 0;
}

int netdev_add_bridge(NSArray **ndevs, NSString *ifacename, VZMACAddress *macaddr) {
	VZBridgedNetworkInterface *brInterface = get_bridge_interface(ifacename);
	if (!brInterface) {
		NSLog(@"Network interface '%@' not found or not available", ifacename);
		return -1;
	}
	NSLog(@" + Bridged network to %@", brInterface);
	VZNetworkDeviceAttachment *bridged = [[VZBridgedNetworkDeviceAttachment alloc] initWithInterface:brInterface];
	if (!bridged) {
		NSLog(@"Bridged network to %@ failed", brInterface);
		return -1;
	}
	/* VirtIO network device */
	VZVirtioNetworkDeviceConfiguration *vnet = [
		[VZVirtioNetworkDeviceConfiguration alloc]
		init
	];
	[vnet setMACAddress:macaddr];
	[vnet setAttachment:bridged];
	*ndevs = [*ndevs arrayByAddingObject:vnet];
	return (0);
}

int set_socket_buflen(int fd, int sndbuflen, int rcvbuflen) {
    /* according to VZFileHandleNetworkDeviceAttachment docs SO_RCVBUF has to be
        at least double of SO_SNDBUF, ideally 4x. Modern macOS have kern.ipc.maxsockbuf
        of 8Mb, so we try 2Mb + 6Mb first and fall back by halving */
    while (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuflen, sizeof(sndbuflen)) ||
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuflen, sizeof(rcvbuflen))) {
        sndbuflen /= 2;
        rcvbuflen /= 2;
        if (rcvbuflen < 128 * 1024) {
            printf("Could not set socket buffer sizes: %s\n", strerror(errno));
            return -1;
        }
    }
	return 0;
}

int netdev_add_hostonly(NSArray **ndevs, VZMACAddress *macaddr) {
  int mtu = 1500;
  NSFileHandle *fh;

  int socket_fds[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socket_fds) < 0) {
    NSLog(@"Could not create socket pair");
    return -1;
  }
  int sndbuflen = 2 * 1024 * 1024;
  int rcvbuflen = 6 * 1024 * 1024;
  set_socket_buflen(socket_fds[0], sndbuflen, rcvbuflen);
  set_socket_buflen(socket_fds[1], sndbuflen, rcvbuflen);
  printf("socketpair %d %d\n", socket_fds[0], socket_fds[1]);
  if (!setup_vmnet(socket_fds[1], "44381771-A145-4499-B6DB-4678C93726B2")) {
    NSLog(@"setup_vmnet failed");
	goto out;
  }
  fh = [[NSFileHandle alloc] initWithFileDescriptor:socket_fds[0]];
  VZFileHandleNetworkDeviceAttachment *host =
      [[VZFileHandleNetworkDeviceAttachment alloc] initWithFileHandle:fh];
  if (mtu > 1500) {
#if (TARGET_OS_OSX && __MAC_OS_X_VERSION_MAX_ALLOWED >= 130000)
    if (@available(macOS 13, *))
            host.maximumTransmissionUnit = mtu;
    else
            fprintf(stderr, "WARNING: your macOS does not support MTU changes, "
                            "using default 1500\n");
#else
    fprintf(stderr, "WARNING: This build does not support MTU changes, using "
                    "default 1500\n");
#endif
  }

  /* VirtIO network device */
  VZVirtioNetworkDeviceConfiguration *vnet =
      [[VZVirtioNetworkDeviceConfiguration alloc] init];
  [vnet setMACAddress:macaddr];
  [vnet setAttachment:host];
  *ndevs = [*ndevs arrayByAddingObject:vnet];
  return (0);
out:
  close(socket_fds[0]);
  close(socket_fds[1]);
  return -1;
}

int
vmcfg_net(struct parse_result *res, VZVirtualMachineConfiguration *vmcfg)
{
	NSArray *ndevs = @[];

	/* VirtIO network device */
	for (NSValue *net in res->nets) {
		net_desc_t *nd = [net pointerValue];
		if (!nd) {
			NSLog(@"nd==NULL");
			return -1;
		}
		NSLog(@"nd==%d", (nd)->type);
		// NSLog(@"nd==%d,%@,%@", nd->type, nd->macaddr, nd->data);
		switch (nd->type) {
			case NET_TYPE_BRIDGE:
				NSLog(@"Add bridge net to %@", nd->data);
				if (netdev_add_bridge(&ndevs, nd->data, nd->macaddr)) {
					NSLog(@"Add bridge net to %@ failed", nd->data);
					return -1;
				}
				break;
			case NET_TYPE_NAT:
				NSLog(@"Add nat net");
				if (netdev_add_nat(&ndevs, nd->macaddr)) {
					NSLog(@"Add nat net failed");
					return -1;
				}
				break;
			case NET_TYPE_HOST_ONLY:
				NSLog(@"Add host-only net");
				if (netdev_add_hostonly(&ndevs, nd->macaddr)) {
					NSLog(@"Add host-only net failed");
					return -1;
				}
				break;
			default:
				return -1;
		}
	}
	NSLog(@"Add %zu net", (unsigned long)ndevs.count);

	[vmcfg setNetworkDevices:ndevs];
	return (0);
}

int
vmcfg_storage(struct parse_result *res, VZVirtualMachineConfiguration *vmcfg)
{
	int i;

	NSError *error = nil;
	NSArray *disks = @[];
	NSString *diskpath;
	NSURL *diskurl;

	/* VirtIO storage device */
	for (i=0; i < res->ndisks; i++) {
		diskpath = [NSString stringWithUTF8String:res->disks[i]];
		diskurl = [NSURL fileURLWithPath:diskpath];

		VZDiskImageStorageDeviceAttachment *sd = [
			[VZDiskImageStorageDeviceAttachment alloc]
			initWithURL:diskurl
			readOnly:false
                        error:&error
		];

		if (sd) {
			VZStorageDeviceConfiguration *disk = [
				[VZVirtioBlockDeviceConfiguration alloc]
				initWithAttachment:sd
			];
			disks = [disks arrayByAddingObject:disk];
			if (verbose > 1)
				NSLog(@"Assigned disk \"%@\" to sd%d\n",
					[diskpath lastPathComponent],
					i
				);
		}
	}
	[vmcfg setStorageDevices:disks];

	if (error)
		goto err;

	return (0);
err:
	NSLog(@"Unable to configure storage device: %@", error);
	return (-1);
}

int
vmcfg_console(struct parse_result *res, struct vmconfig *vmcfg)
{
	NSError *error = nil;
	NSFileHandle *inputfh = [
		[NSFileHandle alloc]
		initWithFileDescriptor:vmcfg->vm_tty
	];
	NSFileHandle *outputfh = [
		[NSFileHandle alloc]
		initWithFileDescriptor:vmcfg->vm_tty
	];

	/* VirtIO console device */
	VZSerialPortAttachment *ttyVI00 = [
		[VZFileHandleSerialPortAttachment alloc]
		initWithFileHandleForReading:inputfh
		fileHandleForWriting:outputfh
	];
	VZVirtioConsoleDeviceSerialPortConfiguration *viocon = [
		[VZVirtioConsoleDeviceSerialPortConfiguration alloc]
		init
	];
	[viocon setAttachment:ttyVI00];
	[vmcfg->vm setSerialPorts:@[viocon]];
	if (error)
		goto err;

	return (0);
err:
	NSLog(@"Unable to configure serial console: %@", error);
	return (-1);
}

int
vmcfg_misc(struct parse_result *res, VZVirtualMachineConfiguration *vmcfg)
{
	NSError *error = nil;

	/* VirtIO entropy device */
	VZEntropyDeviceConfiguration *viornd = [
		[VZVirtioEntropyDeviceConfiguration alloc]
		init
	];
	[vmcfg setEntropyDevices:@[viornd]];

	if (error)
		goto err;

	return (0);
err:
	NSLog(@"Unable to configure miscellaneous device: %@", error);
	return (-1);
}

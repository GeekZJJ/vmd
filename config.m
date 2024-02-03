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
#include <unistd.h>
#import <Virtualization/Virtualization.h>

#include <err.h>
#include <sys/stat.h>
#include <sys/tty.h>
#include "vmctl.h"
#include "vmd.h"

/* for socket networking */
#include <sys/un.h>
#include <sys/socket.h>

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
	// if (vmcfg_net_host(res, vmcfg->vm))
	// if (vmcfg_net_bridged(res, vmcfg->vm))
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

/* TODO: Allow multiple network devices */
int
vmcfg_net_host(struct parse_result *res, VZVirtualMachineConfiguration *vmcfg)
{
	struct stat st;
	int mtu = 1500;
	struct sockaddr_un caddr = {
		.sun_family = AF_UNIX,
	};
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
		.sun_path = "./objs/tap.sock" //要先建好socket然后再connect
	};
	NSString *path = @"./objs/tap.sock";
	NSFileHandle *fh;
	int sndbuflen = 2 * 1024 * 1024; /* for SO_RCVBUF/SO_SNDBUF - see below */
	int rcvbuflen = 6 * 1024 * 1024;
	int fd;

	NSLog(@" + UNIX domain socket network");

	if (path)
		strncpy(addr.sun_path, [path UTF8String], sizeof(addr.sun_path) - 1);

	NSString *tmpDir = @"./objs";//NSTemporaryDirectory();
	NSString *tmpSock = [NSString stringWithFormat: @"%@/macosvm.sock", tmpDir];
	if ([tmpSock lengthOfBytesUsingEncoding:NSUTF8StringEncoding] >= sizeof(caddr.sun_path)) {
		NSLog(@"Temporary socket path '%@' is too long, consider setting TMPSOCKDIR to shorter path.", tmpSock);
		return -1;
	}
	strcpy(caddr.sun_path, [tmpSock UTF8String]);
	/* for security reasons we don't allow the target to be anything other
			that a previously created socket (especially not a link) */
	if (lstat(caddr.sun_path, &st) == 0) { /* target exists */
		if ((st.st_mode & S_IFMT) != S_IFSOCK) {
			NSLog(@"Temporary socket path '%@' already exists and is not a socket.", tmpSock);
			return -1;
		}
		/* ok, unlink it */
		if (unlink(caddr.sun_path)) {
			NSLog(@"Cannot remove stale temporary socket '%@': %s", tmpSock, strerror(errno));
			return -1;
		}
	} /* if it doesn't exist, we're all good */

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	/* bind is mandatory */
	if (bind(fd, (struct sockaddr *)&caddr, sizeof(caddr))) {
		NSLog(@"Could not bind UNIX socket to '%s': %s", caddr.sun_path, strerror(errno));
		return -1;
	}
	NSLog(@"   Bound to '%s', connecting to '%s'", caddr.sun_path, addr.sun_path);
	// add_unlink_on_exit(caddr.sun_path);
	/* connect is optional for DGRAM, but fixes the peer so we force the desired target */
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		NSLog(@"Could not connect to UNIX socket '%s': %s", addr.sun_path, strerror(errno));
		return -1;
	}

	/* according to VZFileHandleNetworkDeviceAttachment docs SO_RCVBUF has to be
		at least double of SO_SNDBUF, ideally 4x. Modern macOS have kern.ipc.maxsockbuf
		of 8Mb, so we try 2Mb + 6Mb first and fall back by halving */
	while (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuflen, sizeof(sndbuflen)) ||
			setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuflen, sizeof(rcvbuflen))) {
		sndbuflen /= 2;
		rcvbuflen /= 2;
		if (rcvbuflen < 128 * 1024) {
			NSLog(@"Could not set socket buffer sizes: %s", strerror(errno));
			return -1;
		}
	}

	fh = [[NSFileHandle alloc] initWithFileDescriptor:fd];
	VZFileHandleNetworkDeviceAttachment *host = [[VZFileHandleNetworkDeviceAttachment alloc] initWithFileHandle:fh];
	if (mtu > 1500) {
#if (TARGET_OS_OSX && __MAC_OS_X_VERSION_MAX_ALLOWED >= 130000)
		if (@available(macOS 13, *))
			host.maximumTransmissionUnit = mtu;
		else
			fprintf(stderr, "WARNING: your macOS does not support MTU changes, using default 1500\n");
#else
		fprintf(stderr, "WARNING: This build does not support MTU changes, using default 1500\n");
#endif
	}

	NSError *error = nil;
	NSArray *ndevs = @[];
	VZMACAddress *lladdr;

	/* VirtIO network device */
	VZVirtioNetworkDeviceConfiguration *vio0 = [
		[VZVirtioNetworkDeviceConfiguration alloc]
		init
	];

	if (res->lladdr != NULL) {
		lladdr = [
			[VZMACAddress alloc]
			initWithString:res->lladdr
		];
	} else {
		lladdr = [VZMACAddress randomLocallyAdministeredAddress];
	}

	if (lladdr == NULL) {
		NSLog(@"Unable to assign link layer address to vio0");
		goto done;
	}

	[vio0 setMACAddress:lladdr];
	[vio0 setAttachment:host];
	ndevs = [ndevs arrayByAddingObject:vio0];

	[vmcfg setNetworkDevices:ndevs];
	if (error)
		goto err;

	if (verbose > 1)
		NSLog(@"Assigned link layer address %@ to vio0", lladdr);

	return (0);
err:
	NSLog(@"Unable to configure network device: %@", error);
done:
	return (-1);
}

/* TODO: Allow multiple network devices */
int
vmcfg_net_bridged(struct parse_result *res, VZVirtualMachineConfiguration *vmcfg)
{
	NSString *iface = @"en0";//d[@"interface"];
	VZBridgedNetworkInterface *brInterface = nil;
	NSArray *hostInterfaces = VZBridgedNetworkInterface.networkInterfaces;
	if ([hostInterfaces count] < 1) {
		NSLog(@"No host interfaces are available for bridging");
		return -1;
	} else {
		for (VZBridgedNetworkInterface *hostIface in hostInterfaces)
			NSLog(@"Host interface %@ is available for bridging", hostIface.identifier);
	}
	if (iface) {
		for (VZBridgedNetworkInterface *hostIface in hostInterfaces)
			if ([hostIface.identifier isEqualToString: iface]) {
				brInterface = hostIface;
				break;
			}
	} else {
		brInterface = (VZBridgedNetworkInterface*) hostInterfaces[0];
		NSLog(@"WARNING: no network interface specified for bridging, using first: %@ (%@)\n",
									brInterface.identifier, brInterface.localizedDisplayName);
	}
	if (!brInterface) {
		NSLog(@"Network interface '%@' not found or not available", iface);
		return -1;
	}
	NSLog(@" + Bridged network to %@", brInterface);
	VZNetworkDeviceAttachment *bridged = [[VZBridgedNetworkDeviceAttachment alloc] initWithInterface:brInterface];

	NSError *error = nil;
	NSArray *ndevs = @[];
	VZMACAddress *lladdr;

	/* VirtIO network device */
	VZVirtioNetworkDeviceConfiguration *vio0 = [
		[VZVirtioNetworkDeviceConfiguration alloc]
		init
	];

	if (res->lladdr != NULL) {
		lladdr = [
			[VZMACAddress alloc]
			initWithString:res->lladdr
		];
	} else {
		lladdr = [VZMACAddress randomLocallyAdministeredAddress];
	}

	if (lladdr == NULL) {
		NSLog(@"Unable to assign link layer address to vio0");
		goto done;
	}

	[vio0 setMACAddress:lladdr];
	[vio0 setAttachment:bridged];
	ndevs = [ndevs arrayByAddingObject:vio0];

	[vmcfg setNetworkDevices:ndevs];
	if (error)
		goto err;

	if (verbose > 1)
		NSLog(@"Assigned link layer address %@ to vio0", lladdr);

	return (0);
err:
	NSLog(@"Unable to configure network device: %@", error);
done:
	return (-1);
}

/* TODO: Allow multiple network devices */
int
vmcfg_nat(struct parse_result *res, VZVirtualMachineConfiguration *vmcfg)
{
	NSError *error = nil;
	NSArray *ndevs = @[];
	VZMACAddress *lladdr;

	/* VirtIO network device */
	VZVirtioNetworkDeviceConfiguration *vio0 = [
		[VZVirtioNetworkDeviceConfiguration alloc]
		init
	];
	VZNetworkDeviceAttachment *nat = [
		[VZNATNetworkDeviceAttachment alloc]
		init
	];

	if (res->lladdr != NULL) {
		lladdr = [
			[VZMACAddress alloc]
			initWithString:res->lladdr
		];
	} else {
		lladdr = [VZMACAddress randomLocallyAdministeredAddress];
	}

	if (lladdr == NULL) {
		NSLog(@"Unable to assign link layer address to vio0");
		goto done;
	}

	[vio0 setMACAddress:lladdr];
	[vio0 setAttachment:nat];
	ndevs = [ndevs arrayByAddingObject:vio0];

	[vmcfg setNetworkDevices:ndevs];
	if (error)
		goto err;

	if (verbose > 1)
		NSLog(@"Assigned link layer address %@ to vio0", lladdr);

	return (0);
err:
	NSLog(@"Unable to configure network device: %@", error);
done:
	return (-1);
}

int netdev_set_macaddr(VZNetworkDeviceConfiguration *vnet, NSString *macaddr) {
	VZMACAddress *lladdr;
	if (macaddr) {
		lladdr = [
			[VZMACAddress alloc]
			initWithString:macaddr
		];
	} else {
		lladdr = [VZMACAddress randomLocallyAdministeredAddress];
	}
	if (lladdr == NULL) {
		NSLog(@"Unable to assign link layer address to vnet");
		return -1;
	}
	[vnet setMACAddress:lladdr];
	return 0;
}

VZBridgedNetworkInterface *get_bridge_interface(NSString *ifacename) {
	NSArray *hostInterfaces = VZBridgedNetworkInterface.networkInterfaces;
	for (VZBridgedNetworkInterface *hostIface in hostInterfaces)
		if ([hostIface.identifier isEqualToString: ifacename]) {
			return hostIface;
		}
	return nil;
}

int netdev_add_nat(NSArray **ndevs, NSString* macaddr) {
	VZVirtioNetworkDeviceConfiguration *vnet = [
		[VZVirtioNetworkDeviceConfiguration alloc]
		init
	];
	VZNetworkDeviceAttachment *nat = [
		[VZNATNetworkDeviceAttachment alloc]
		init
	];
	if (netdev_set_macaddr(vnet, macaddr)) {
		NSLog(@"Unable to assign link layer address to vnet");
		return -1;
	}
	[vnet setAttachment:nat];
	*ndevs = [*ndevs arrayByAddingObject:vnet];
	return 0;
}

int netdev_add_bridge(NSArray **ndevs, NSString *ifacename, NSString *macaddr) {
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
	if (netdev_set_macaddr(vnet, macaddr)) {
		NSLog(@"Unable to assign link layer address to vnet");
		return -1;
	}
	[vnet setAttachment:bridged];
	*ndevs = [*ndevs arrayByAddingObject:vnet];
	return (0);
}

int unix_socket_bind_connect(NSString *remote_path, NSString *local_path) {
	int fd;
	int sndbuflen = 2 * 1024 * 1024; /* for SO_RCVBUF/SO_SNDBUF - see below */
	int rcvbuflen = 6 * 1024 * 1024;
	struct stat st;
	struct sockaddr_un remote_addr, local_addr;

	bzero(&remote_addr, sizeof(remote_addr));
	bzero(&local_addr, sizeof(local_addr));
	if ([local_path lengthOfBytesUsingEncoding:NSUTF8StringEncoding] >= sizeof(local_addr.sun_path)) {
		NSLog(@"Remote socket path '%@' is too long, consider setting TMPSOCKDIR to shorter path.", local_path);
		return -1;
	}
	if ([remote_path lengthOfBytesUsingEncoding:NSUTF8StringEncoding] >= sizeof(remote_addr.sun_path)) {
		NSLog(@"Temporary socket path '%@' is too long, consider setting TMPSOCKDIR to shorter path.", remote_path);
		return -1;
	}
	// if (lstat(remote_addr.sun_path, &st) != 0) { /* remote not exists */
	// 	NSLog(@"Remote socket path '%@' not exists.", remote_path);
	// 	return -1;
	// } else if ((st.st_mode & S_IFMT) != S_IFSOCK) { /* remote not a socket */
	// 	NSLog(@"Remote socket path '%@' is not a socket.", remote_path);
	// 	return -1;
	// }
	strncpy(remote_addr.sun_path, [remote_path UTF8String], sizeof(remote_addr.sun_path) - 1);
	strncpy(local_addr.sun_path, [local_path UTF8String], sizeof(local_addr.sun_path) - 1);

	if (lstat(local_addr.sun_path, &st) == 0) { /* local exists */
		if ((st.st_mode & S_IFMT) != S_IFSOCK) {
			NSLog(@"Temporary socket path '%@' already exists and is not a socket.", local_path);
			return -1;
		}
		/* ok, unlink it */
		if (unlink(local_addr.sun_path)) {
			NSLog(@"Cannot remove stale temporary socket '%@': %s", local_path, strerror(errno));
			return -1;
		}
	} /* if it doesn't exist, we're all good */

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	/* bind is mandatory */
	if (bind(fd, (struct sockaddr *)&local_addr, sizeof(local_addr))) {
		NSLog(@"Could not bind UNIX socket to '%s': %s", local_addr.sun_path, strerror(errno));
		goto out;
	}
	NSLog(@"   Bound to '%s', connecting to '%s'", local_addr.sun_path, remote_addr.sun_path);
	// add_unlink_on_exit(caddr.sun_path); todo
	/* connect is optional for DGRAM, but fixes the peer so we force the desired target */
	if (connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr))) {
		NSLog(@"Could not connect to UNIX socket '%s': %s", remote_addr.sun_path, strerror(errno));
		goto out;
	}

	/* according to VZFileHandleNetworkDeviceAttachment docs SO_RCVBUF has to be
		at least double of SO_SNDBUF, ideally 4x. Modern macOS have kern.ipc.maxsockbuf
		of 8Mb, so we try 2Mb + 6Mb first and fall back by halving */
	while (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuflen, sizeof(sndbuflen)) ||
			setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuflen, sizeof(rcvbuflen))) {
		sndbuflen /= 2;
		rcvbuflen /= 2;
		if (rcvbuflen < 128 * 1024) {
			NSLog(@"Could not set socket buffer sizes: %s", strerror(errno));
			goto out;
		}
	}
	return fd;
out:
	close(fd);
	return -1;
}

int netdev_add_hostonly(NSArray **ndevs, NSString *sock_path, NSString *macaddr) {
	int mtu = 1500, fd = -1;
	NSFileHandle *fh;
	NSString *tmpDir = @"./objs";//NSTemporaryDirectory();
	NSString *tmpSock = [NSString stringWithFormat: @"%@/vm.%d.%lu.sock", tmpDir, getpid(), (unsigned long)(*ndevs).count];

	fd = unix_socket_bind_connect(sock_path, tmpSock);
	if (fd<0) {
		NSLog(@"Could not connect to %@", sock_path);
		return -1;
	}
	fh = [[NSFileHandle alloc] initWithFileDescriptor:fd];
	VZFileHandleNetworkDeviceAttachment *host = [[VZFileHandleNetworkDeviceAttachment alloc] initWithFileHandle:fh];
	if (mtu > 1500) {
#if (TARGET_OS_OSX && __MAC_OS_X_VERSION_MAX_ALLOWED >= 130000)
		if (@available(macOS 13, *))
			host.maximumTransmissionUnit = mtu;
		else
			fprintf(stderr, "WARNING: your macOS does not support MTU changes, using default 1500\n");
#else
		fprintf(stderr, "WARNING: This build does not support MTU changes, using default 1500\n");
#endif
	}

	/* VirtIO network device */
	VZVirtioNetworkDeviceConfiguration *vnet = [
		[VZVirtioNetworkDeviceConfiguration alloc]
		init
	];

	if (netdev_set_macaddr(vnet, macaddr)) {
		NSLog(@"Unable to assign link layer address to vnet");
		goto out;
	}
	[vnet setAttachment:host];
	*ndevs = [*ndevs arrayByAddingObject:vnet];
	return (0);
out:
	close(fd);
	return -1;
}

/* TODO: Allow multiple network devices */
int
vmcfg_net(struct parse_result *res, VZVirtualMachineConfiguration *vmcfg)
{
	int i;
	NSArray *ndevs = @[];

	/* VirtIO network device */
	for (i=0; i < res->nnets; i++) {
		char* word = res->nets[i];
		if (!strncmp(word, "bridge", sizeof("bridge"))) {
			char *ret = strstr(word, "@");
			if (strlen(ret)<2) {
				return -1;
			}
			if (netdev_add_bridge(&ndevs, [NSString stringWithUTF8String: ret+1], NULL)) {
				NSLog(@"Add bridge net to %s failed", ret+1);
				return -1;
			}
			NSLog(@"Add bridge net to %s", ret+1);
		} else if (!strcmp(word, "nat")) {
			if (netdev_add_nat(&ndevs,  NULL)) {
				NSLog(@"Add nat net failed");
				return -1;
			}
			NSLog(@"Add nat net");
		} else if (!strcmp(word, "host")) {
			if (netdev_add_hostonly(&ndevs, @"./objs/tap.sock", NULL)) {
				NSLog(@"Add host-only net failed");
				return -1;
			}
			NSLog(@"Add host-only net");
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

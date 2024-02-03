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
#include <stdio.h>
#import <Virtualization/Virtualization.h>
#include <vmnet/vmnet.h>

#include <err.h>
#include <sys/stat.h>
#include <sys/tty.h>
#include "vmctl.h"
#include "vmd.h"

/* for socket networking */
#include <sys/un.h>
#include <sys/socket.h>

#include "msg_x.h"

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

#if __MAC_OS_X_VERSION_MAX_ALLOWED < 101500
#error "Requires macOS 10.15 or later"
#endif

static bool debug = false;

#define DEBUGF(fmt, ...)                                                       \
  do {                                                                         \
    if (debug)                                                                 \
      fprintf(stderr, "DEBUG| " fmt "\n", __VA_ARGS__);                        \
  } while (0)

static void print_vmnet_status(const char *func, vmnet_return_t v) {
  switch (v) {
  case VMNET_SUCCESS:
    DEBUGF("%s(): vmnet_return_t VMNET_SUCCESS", func);
    break;
  case VMNET_FAILURE:
    fprintf(stderr, "%s(): vmnet_return_t VMNET_FAILURE\n", func);
    break;
  case VMNET_MEM_FAILURE:
    fprintf(stderr, "%s(): vmnet_return_t VMNET_MEM_FAILURE\n", func);
    break;
  case VMNET_INVALID_ARGUMENT:
    fprintf(stderr, "%s(): vmnet_return_t VMNET_INVALID_ARGUMENT\n", func);
    break;
  case VMNET_SETUP_INCOMPLETE:
    fprintf(stderr, "%s(): vmnet_return_t VMNET_SETUP_INCOMPLETE\n", func);
    break;
  case VMNET_INVALID_ACCESS:
    fprintf(stderr, "%s(): vmnet_return_t VMNET_INVALID_ACCESS\n", func);
    break;
  case VMNET_PACKET_TOO_BIG:
    fprintf(stderr, "%s(): vmnet_return_t VMNET_PACKET_TOO_BIG\n", func);
    break;
  case VMNET_BUFFER_EXHAUSTED:
    fprintf(stderr, "%s(): vmnet_return_t VMNET_BUFFER_EXHAUSTED\n", func);
    break;
  case VMNET_TOO_MANY_PACKETS:
    fprintf(stderr, "%s(): vmnet_return_t VMNET_TOO_MANY_PACKETS\n", func);
    break;
  default:
    fprintf(stderr, "%s(): vmnet_return_t %d\n", func, v);
    break;
  }
}

static void print_vmnet_start_param(xpc_object_t param) {
  if (param == NULL)
    return;
  xpc_dictionary_apply(param, ^bool(const char *key, xpc_object_t value) {
    xpc_type_t t = xpc_get_type(value);
    if (t == XPC_TYPE_UINT64)
      printf("* %s: %lld\n", key, xpc_uint64_get_value(value));
    else if (t == XPC_TYPE_INT64)
      printf("* %s: %lld\n", key, xpc_int64_get_value(value));
    else if (t == XPC_TYPE_STRING)
      printf("* %s: %s\n", key, xpc_string_get_string_ptr(value));
    else if (t == XPC_TYPE_UUID) {
      char uuid_str[36 + 1];
      uuid_unparse(xpc_uuid_get_bytes(value), uuid_str);
      printf("* %s: %s\n", key, uuid_str);
    } else
      printf("* %s: (unknown type)\n", key);
    return true;
  });
}

struct state {
  int socket_fd;
  char *vmnet_gateway;
  char *vmnet_mask;
  uuid_t interface_id;
  dispatch_queue_t socket_recv_queue;
  dispatch_queue_t vmnet_recv_queue;
  __block interface_ref iface;
} _state;

#define MAX_PACKET_COUNT_AT_ONCE 32

static void _on_vmnet_packets_available(interface_ref iface,
										int64_t pkt_cnt,
                                        int64_t max_bytes,
                                        struct state *state) {
  static struct vmpktdesc *pdv = NULL;
  static struct msghdr_x *msg = NULL;
  static struct iovec *iov = NULL;
  static void *recv_buf = NULL;
  static size_t current_pool_size = 0;
  if (current_pool_size < pkt_cnt) {
    current_pool_size =
        pkt_cnt < MAX_PACKET_COUNT_AT_ONCE ? MAX_PACKET_COUNT_AT_ONCE : pkt_cnt;
    iov = realloc(iov, current_pool_size * sizeof(struct iovec));
    if (iov == NULL) {
            perror("calloc(current_pool_size, sizeof(struct iovec))");
            goto done;
    }
    pdv = realloc(pdv, current_pool_size * sizeof(struct vmpktdesc));
    if (pdv == NULL) {
            perror("realloc(current_pool_size, sizeof(struct vmpktdesc)");
            goto done;
    }
    recv_buf = realloc(recv_buf, current_pool_size * max_bytes);
    if (recv_buf == NULL) {
            perror("realloc(current_pool_size, max_bytes)");
            goto done;
    }
    msg = realloc(msg, current_pool_size * sizeof(struct msghdr_x));
    if (msg == NULL) {
            perror("realloc(current_pool_size, sizeof(struct msghdr_x)");
            goto done;
    }
  }
  bzero(pdv, current_pool_size * sizeof(struct vmpktdesc));
  for (int i = 0; i < pkt_cnt; i++) {
    iov[i].iov_base = recv_buf + i * max_bytes;
    iov[i].iov_len = max_bytes;
    pdv[i].vm_flags = 0;
    pdv[i].vm_pkt_size = max_bytes;
    pdv[i].vm_pkt_iovcnt = 1;
    pdv[i].vm_pkt_iov = &iov[i];
  }
  int received_count = pkt_cnt;
  vmnet_return_t read_status = vmnet_read(iface, pdv, &received_count);
  if (read_status != VMNET_SUCCESS) {
    perror("vmnet_read");
    goto done;
  }

  bzero(msg, current_pool_size * sizeof(struct msghdr_x));
  for (unsigned int i = 0; i < received_count; i++) {
    msg[i].msg_iov = &iov[i];
    msg[i].msg_iovlen = 1;
  }
  if (received_count != sendmsg_x(state->socket_fd, msg, received_count, 0)) {
    fprintf(stderr, "sendmsg_x() fd %d failed: %s\n", state->socket_fd,
            strerror(errno));
    return;
  }
  return;
done:
  if (pdv != NULL)
    free(pdv);
  if (iov != NULL)
    free(iov);
  if (recv_buf != NULL)
    free(recv_buf);
  if (msg != NULL)
    free(msg);
  pdv = NULL;
  iov = NULL;
  recv_buf = NULL;
  msg = NULL;
  current_pool_size = 0;
}

static void on_vmnet_packets_available(interface_ref iface, int64_t estim_count,
                                       int64_t max_bytes, struct state *state) {
  int64_t q = estim_count / MAX_PACKET_COUNT_AT_ONCE;
  int64_t r = estim_count % MAX_PACKET_COUNT_AT_ONCE;
  DEBUGF("estim_count=%lld, dividing by MAX_PACKET_COUNT_AT_ONCE=%d; q=%lld, "
         "r=%lld",
         estim_count, MAX_PACKET_COUNT_AT_ONCE, q, r);
  for (int i = 0; i < q; i++) {
    _on_vmnet_packets_available(iface, MAX_PACKET_COUNT_AT_ONCE, max_bytes, state);
  }
  if (r > 0)
    _on_vmnet_packets_available(iface, r, max_bytes, state);
}

static interface_ref start(struct state *state) {
  xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_uint64(dict, vmnet_operation_mode_key, VMNET_HOST_MODE);
  if (state->vmnet_gateway != NULL) {
#if (TARGET_OS_OSX && __MAC_OS_X_VERSION_MAX_ALLOWED >= 110000)
    xpc_dictionary_set_string(dict, vmnet_host_ip_address_key, state->vmnet_gateway);
    xpc_dictionary_set_string(dict, vmnet_host_subnet_mask_key, state->vmnet_mask);
#else
    xpc_dictionary_set_string(dict, vmnet_start_address_key, state->vmnet_gateway);
    xpc_dictionary_set_string(dict, vmnet_subnet_mask_key, state->vmnet_mask);
#endif
  }

#if (TARGET_OS_OSX && __MAC_OS_X_VERSION_MAX_ALLOWED >= 110000)
  xpc_dictionary_set_uuid(dict, vmnet_network_identifier_key, state->interface_id);
// #else
//   xpc_dictionary_set_uuid(dict, vmnet_interface_id_key, state->interface_id);
#endif
   xpc_dictionary_set_bool(dict, vmnet_allocate_mac_address_key, false);
   xpc_dictionary_set_uuid(dict, vmnet_interface_id_key, state->interface_id);

  dispatch_queue_t q = dispatch_queue_create(
      "io.github.lima-vm.socket_vmnet.start", DISPATCH_QUEUE_SERIAL);
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);

  __block interface_ref iface;
  __block vmnet_return_t status;
  __block uint64_t max_bytes = 0;
  iface = vmnet_start_interface(
      dict, q, ^(vmnet_return_t x_status, xpc_object_t x_param) {
        status = x_status;
        if (x_status == VMNET_SUCCESS) {
          print_vmnet_start_param(x_param);
          max_bytes =
              xpc_dictionary_get_uint64(x_param, vmnet_max_packet_size_key);
        }
        dispatch_semaphore_signal(sem);
      });
  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
  print_vmnet_status(__FUNCTION__, status);
  dispatch_release(q);
  xpc_release(dict);
  if (status != VMNET_SUCCESS) {
    return NULL;
  }
  char event_queue_lable[30] = {0};
  snprintf(event_queue_lable, sizeof(event_queue_lable), "vmnet%d_vmnet_recv", state->socket_fd);
  state->vmnet_recv_queue = dispatch_queue_create(event_queue_lable, DISPATCH_QUEUE_CONCURRENT);
  vmnet_interface_set_event_callback(
      iface, VMNET_INTERFACE_PACKETS_AVAILABLE, state->vmnet_recv_queue,
      ^(interface_event_t __attribute__((unused)) x_event_id,
        xpc_object_t x_event) {
        uint64_t estim_count = xpc_dictionary_get_uint64(
            x_event, vmnet_estimated_packets_available_key);
        on_vmnet_packets_available(iface, estim_count, max_bytes, state);
      });

  return iface;
}

static void stop(struct state *state) {
  if (state->iface == NULL) {
    return;
  }
  char stop_queue_label[30] = {0};
  snprintf(stop_queue_label, sizeof(stop_queue_label), "vmnet%d_stop",state->socket_fd);
  dispatch_release(state->socket_recv_queue);
  dispatch_queue_t q = dispatch_queue_create(stop_queue_label, DISPATCH_QUEUE_SERIAL);
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  __block vmnet_return_t status;
  vmnet_stop_interface(state->iface, q, ^(vmnet_return_t x_status) {
    status = x_status;
    dispatch_semaphore_signal(sem);
  });
  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
  dispatch_release(state->vmnet_recv_queue);
  print_vmnet_status(__FUNCTION__, status);
  dispatch_release(q);
  // TODO: release event_q ?
}

static void on_socket_recv(struct state *state) {
  static int max_pkt_size = 1600;
  static struct vmpktdesc *pdv = NULL;
  static struct msghdr_x *msg = NULL;
  static struct iovec *iov = NULL;
  static void *recv_buf = NULL;
  static size_t current_pool_size = MAX_PACKET_COUNT_AT_ONCE;
  struct iovec *iov2 = NULL;
  iov2 = calloc(current_pool_size, sizeof(struct iovec));
  if (iov2 == NULL) {
    perror("calloc(current_pool_size, sizeof(struct iovec))");
    goto done;
  }

  iov = calloc(current_pool_size, sizeof(struct iovec));
  if (iov == NULL) {
    perror("calloc(current_pool_size, sizeof(struct iovec))");
    goto done;
  }
  pdv = calloc(current_pool_size, sizeof(struct vmpktdesc));
  if (pdv == NULL) {
    perror("realloc(current_pool_size, sizeof(struct vmpktdesc)");
    goto done;
  }
  recv_buf = calloc(current_pool_size, max_pkt_size);
  if (recv_buf == NULL) {
    perror("realloc(current_pool_size, max_bytes)");
    goto done;
  }
  msg = calloc(current_pool_size, sizeof(struct msghdr_x));
  if (msg == NULL) {
    perror("realloc(current_pool_size, sizeof(struct msghdr_x)");
    goto done;
  }
  bzero(msg, current_pool_size * sizeof(struct msghdr_x));
  for (unsigned int i = 0; i < current_pool_size; i++) {
    msg[i].msg_iov = &iov[i];
    msg[i].msg_iovlen = 1;
  }
  bzero(pdv, current_pool_size * sizeof(struct vmpktdesc));
  for (int i = 0; i < current_pool_size; i++) {
    iov[i].iov_base = recv_buf + i * max_pkt_size;
    iov[i].iov_len = max_pkt_size;
    pdv[i].vm_flags = 0;
    pdv[i].vm_pkt_size = max_pkt_size;
    pdv[i].vm_pkt_iovcnt = 1;
    pdv[i].vm_pkt_iov = &iov[i];
  }

  while (1) {
    ssize_t received = recvmsg_x(state->socket_fd, msg, current_pool_size, 0);
    if (received <= 0) {
            fprintf(stderr, "recvmsg_x() failed: %s\n", strerror(errno));
            goto done;
    }
    for (unsigned int ii = 0; ii < (u_int)received; ii++) {
            iov2[ii].iov_base = msg[ii].msg_iov->iov_base;
            iov2[ii].iov_len = msg[ii].msg_datalen;
            pdv[ii].vm_pkt_iov = &iov2[ii];
            pdv[ii].vm_pkt_size = msg[ii].msg_datalen;
            pdv[ii].vm_pkt_iovcnt = 1;
            pdv[ii].vm_flags = 0;
    }
    int written_count = received;
    vmnet_return_t write_status =
        vmnet_write(state->iface, pdv, &written_count);
    if (write_status != VMNET_SUCCESS) {
            perror("vmnet_write");
    }
  }
done:
  printf("Closing a connection (fd %d)\n", state->socket_fd);
  close(state->socket_fd);

out:
  if (pdv != NULL)
    free(pdv);
  if (iov != NULL)
    free(iov);
  if (iov2 != NULL)
    free(iov2);
  if (recv_buf != NULL)
    free(recv_buf);
  if (msg != NULL)
    free(msg);
  pdv = NULL;
  iov = NULL;
  recv_buf = NULL;
  msg = NULL;
  current_pool_size = 0;
}

int setup_vmnet(int fd, char *uuid) {
  char queue_label[30] = {0};
  struct state *pstate = malloc(sizeof(struct state));
  memset(pstate, 0, sizeof(struct state));
  pstate->socket_fd = fd;
  sprintf(queue_label, "vmnet%d_socket_recv", fd);
  pstate->socket_recv_queue = dispatch_queue_create(queue_label, DISPATCH_QUEUE_CONCURRENT);

  uuid_parse(uuid, pstate->interface_id);

  pstate->iface = start(pstate);
  if (pstate->iface == NULL) {
    perror("start");
    return -1;
  }

  dispatch_async(pstate->socket_recv_queue, ^{
    on_socket_recv(pstate);
  });

  return 0;
}

int netdev_add_hostonly(NSArray **ndevs, NSString *sock_path, NSString *macaddr) {
	int mtu = 1500;
	NSFileHandle *fh;

	int socket_fds[2];
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socket_fds)<0) {
		NSLog(@"Could not connect to %@", sock_path);
		return -1;
	}
    int sndbuflen = 2 * 1024 * 1024;
    int rcvbuflen = 6 * 1024 * 1024;
	set_socket_buflen(socket_fds[0], sndbuflen, rcvbuflen);
	set_socket_buflen(socket_fds[1], sndbuflen, rcvbuflen);
	printf("socketpair %d %d\n", socket_fds[0], socket_fds[1]);
	if (setup_vmnet(socket_fds[1], "44381771-A145-4499-B6DB-4678C93726B2")) {
		NSLog(@"setup_vmnet failed");
	}
	fh = [[NSFileHandle alloc] initWithFileDescriptor:socket_fds[0]];
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
	close(socket_fds[0]);
	close(socket_fds[1]);
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

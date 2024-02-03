#ifndef __VMNET_H
#define __VMNET_H

#include <vmnet/vmnet.h>

typedef struct {
  int socket_fd;
  char *vmnet_gateway;
  char *vmnet_mask;
  uuid_t interface_id;
  dispatch_queue_t socket_recv_queue;
  dispatch_queue_t vmnet_recv_queue;
  __block interface_ref iface;
} vmnet_context_t;

vmnet_context_t* setup_vmnet(int fd, char *uuid);
void release_vmnet(vmnet_context_t *ctx);
#endif

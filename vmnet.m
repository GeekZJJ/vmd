#include <errno.h>

/* for socket networking */
#include <sys/un.h>
#include <sys/socket.h>

#include "msg_x.h"
#include "vmnet.h"

#if __MAC_OS_X_VERSION_MAX_ALLOWED < 101500
#error "Requires macOS 10.15 or later"
#endif

static bool debug = false;

#define MAX_PACKET_COUNT_AT_ONCE 32

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

static void _on_vmnet_packets_available(interface_ref iface,
                                        int64_t pkt_cnt,
                                        int64_t max_bytes,
                                        vmnet_context_t *ctx) {
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
  if (received_count != sendmsg_x(ctx->socket_fd, msg, received_count, 0)) {
    fprintf(stderr, "sendmsg_x() fd %d failed: %s\n", ctx->socket_fd,
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
                                       int64_t max_bytes, vmnet_context_t *ctx) {
  int64_t q = estim_count / MAX_PACKET_COUNT_AT_ONCE;
  int64_t r = estim_count % MAX_PACKET_COUNT_AT_ONCE;
  DEBUGF("estim_count=%lld, dividing by MAX_PACKET_COUNT_AT_ONCE=%d; q=%lld, "
         "r=%lld",
         estim_count, MAX_PACKET_COUNT_AT_ONCE, q, r);
  for (int i = 0; i < q; i++) {
    _on_vmnet_packets_available(iface, MAX_PACKET_COUNT_AT_ONCE, max_bytes, ctx);
  }
  if (r > 0)
    _on_vmnet_packets_available(iface, r, max_bytes, ctx);
}

static void on_socket_recv(vmnet_context_t *ctx) {
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
    ssize_t received = recvmsg_x(ctx->socket_fd, msg, current_pool_size, 0);
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
      vmnet_write(ctx->iface, pdv, &written_count);
    if (write_status != VMNET_SUCCESS) {
      perror("vmnet_write");
    }
  }
done:
  printf("Closing a connection (fd %d)\n", ctx->socket_fd);
  close(ctx->socket_fd);

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

static interface_ref vmset_start(vmnet_context_t *ctx) {
  xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_uint64(dict, vmnet_operation_mode_key, VMNET_HOST_MODE);
  if (ctx->vmnet_gateway != NULL) {
#if (TARGET_OS_OSX && __MAC_OS_X_VERSION_MAX_ALLOWED >= 110000)
    xpc_dictionary_set_string(dict, vmnet_host_ip_address_key, ctx->vmnet_gateway);
    xpc_dictionary_set_string(dict, vmnet_host_subnet_mask_key, ctx->vmnet_mask);
#else
    xpc_dictionary_set_string(dict, vmnet_start_address_key, ctx->vmnet_gateway);
    xpc_dictionary_set_string(dict, vmnet_subnet_mask_key, ctx->vmnet_mask);
#endif
  }

#if (TARGET_OS_OSX && __MAC_OS_X_VERSION_MAX_ALLOWED >= 110000)
    xpc_dictionary_set_uuid(dict, vmnet_network_identifier_key, ctx->interface_id);
// #else
//   xpc_dictionary_set_uuid(dict, vmnet_interface_id_key, ctx->interface_id);
#endif
   xpc_dictionary_set_bool(dict, vmnet_allocate_mac_address_key, false);
   xpc_dictionary_set_uuid(dict, vmnet_interface_id_key, ctx->interface_id);

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
  snprintf(event_queue_lable, sizeof(event_queue_lable), "vmnet%d_vmnet_recv", ctx->socket_fd);
  ctx->vmnet_recv_queue = dispatch_queue_create(event_queue_lable, DISPATCH_QUEUE_CONCURRENT);
  vmnet_interface_set_event_callback(
      iface, VMNET_INTERFACE_PACKETS_AVAILABLE, ctx->vmnet_recv_queue,
      ^(interface_event_t __attribute__((unused)) x_event_id,
        xpc_object_t x_event) {
        uint64_t estim_count = xpc_dictionary_get_uint64(
            x_event, vmnet_estimated_packets_available_key);
        on_vmnet_packets_available(iface, estim_count, max_bytes, ctx);
      });

  return iface;
}

static void vmset_stop(vmnet_context_t *ctx) {
  if (ctx->iface == NULL) {
    return;
  }
  char stop_queue_label[30] = {0};
  snprintf(stop_queue_label, sizeof(stop_queue_label), "vmnet%d_stop",ctx->socket_fd);
  dispatch_release(ctx->socket_recv_queue);
  dispatch_queue_t q = dispatch_queue_create(stop_queue_label, DISPATCH_QUEUE_SERIAL);
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  __block vmnet_return_t status;
  vmnet_stop_interface(ctx->iface, q, ^(vmnet_return_t x_status) {
    status = x_status;
    dispatch_semaphore_signal(sem);
  });
  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
  dispatch_release(ctx->vmnet_recv_queue);
  print_vmnet_status(__FUNCTION__, status);
  dispatch_release(q);
  // TODO: release event_q ?
}

vmnet_context_t* setup_vmnet(int fd, char *uuid) {
  char queue_label[30] = {0};
  vmnet_context_t *ctx = NULL;

//   if (uuid_parse(uuid, ctx->interface_id)) {
//     return NULL;
//   }
  
  ctx = malloc(sizeof(vmnet_context_t));
  memset(ctx, 0, sizeof(vmnet_context_t));
  ctx->socket_fd = fd;
  sprintf(queue_label, "vmnet%d_socket_recv", fd);
  ctx->socket_recv_queue = dispatch_queue_create(queue_label, DISPATCH_QUEUE_CONCURRENT);
  ctx->iface = vmset_start(ctx);
  if (ctx->iface == NULL) {
    perror("start");
    goto failed;
  }

  dispatch_async(ctx->socket_recv_queue, ^{
    on_socket_recv(ctx);
  });

  return ctx;
failed:
    if (ctx) free(ctx);
    return NULL;
}

void release_vmnet(vmnet_context_t *ctx) {
    vmset_stop(ctx);
}

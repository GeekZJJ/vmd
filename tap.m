#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <grp.h>
#include <sched.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include <vmnet/vmnet.h>

#include "cli.h"



/*
 * Extended version for sendmsg_x() and recvmsg_x() calls
 *
 * For recvmsg_x(), the size of the data received is given by the field
 * msg_datalen.
 *
 * For sendmsg_x(), the size of the data to send is given by the length of
 * the iovec array -- like sendmsg(). The field msg_datalen is ignored.
 */
struct msghdr_x {
	void            *msg_name;      /* optional address */
	socklen_t       msg_namelen;    /* size of address */
	struct iovec    *msg_iov;       /* scatter/gather array */
	int             msg_iovlen;     /* # elements in msg_iov */
	void            *msg_control;   /* ancillary data, see below */
	socklen_t       msg_controllen; /* ancillary data buffer len */
	int             msg_flags;      /* flags on received message */
	size_t          msg_datalen;    /* byte length of buffer in msg_iov */
};

#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <sys/syscall.h>

/*
 * recvmsg_x() is a system call similar to recvmsg(2) to receive
 * several datagrams at once in the array of message headers "msgp".
 *
 * recvmsg_x() can be used only with protocols handlers that have been specially
 * modified to support sending and receiving several datagrams at once.
 *
 * The size of the array "msgp" is given by the argument "cnt".
 *
 * The "flags" arguments supports only the value MSG_DONTWAIT.
 *
 * Each member of "msgp" array is of type "struct msghdr_x".
 *
 * The "msg_iov" and "msg_iovlen" are input parameters that describe where to
 * store a datagram in a scatter gather locations of buffers -- see recvmsg(2).
 * On output the field "msg_datalen" gives the length of the received datagram.
 *
 * The field "msg_flags" must be set to zero on input. On output, "msg_flags"
 * may have MSG_TRUNC set to indicate the trailing portion of the datagram was
 * discarded because the datagram was larger than the buffer supplied.
 * recvmsg_x() returns as soon as a datagram is truncated.
 *
 * recvmsg_x() may return with less than "cnt" datagrams received based on
 * the low water mark and the amount of data pending in the socket buffer.
 *
 * recvmsg_x() returns the number of datagrams that have been received,
 * or -1 if an error occurred.
 *
 * NOTE: This a private system call, the API is subject to change.
 */
ssize_t recvmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);

/*
 * sendmsg_x() is a system call similar to send(2) to send
 * several datagrams at once in the array of message headers "msgp".
 *
 * sendmsg_x() can be used only with protocols handlers that have been specially
 * modified to support sending and receiving several datagrams at once.
 *
 * The size of the array "msgp" is given by the argument "cnt".
 *
 * The "flags" arguments supports only the value MSG_DONTWAIT.
 *
 * Each member of "msgp" array is of type "struct msghdr_x".
 *
 * The "msg_iov" and "msg_iovlen" are input parameters that specify the
 * data to be sent in a scatter gather locations of buffers -- see sendmsg(2).
 *
 * sendmsg_x() fails with EMSGSIZE if the sum of the length of the datagrams
 * is greater than the high water mark.
 *
 * Address and ancillary data are not supported so the following fields
 * must be set to zero on input:
 *   "msg_name", "msg_namelen", "msg_control" and "msg_controllen".
 *
 * The field "msg_flags" and "msg_datalen" must be set to zero on input.
 *
 * sendmsg_x() returns the number of datagrams that have been sent,
 * or -1 if an error occurred.
 *
 * NOTE: This a private system call, the API is subject to change.
 */
ssize_t sendmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);

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
  dispatch_semaphore_t sem;
  int socket_fd;
  uint64_t tx;
  uint64_t rx;
  bool connected;
  struct sockaddr_un remote_addr;
} _state;

static void state_set_socket_fd(struct state *state, int socket_fd) {
  dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
  state->socket_fd = socket_fd;
  dispatch_semaphore_signal(state->sem);
}

static void state_remove_socket_fd(struct state *state, int socket_fd) {
  dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
  state->socket_fd = -1;
  bzero(&state->remote_addr, sizeof(state->remote_addr));
  dispatch_semaphore_signal(state->sem);
}

struct sockaddr_un localaddr;

#if 0
inline static int sendnmsg(int fd, struct vmpktdesc *pdv, size_t n, struct sockaddr_un *to){
	struct msghdr_x msg[n];
	struct iovec iov[n];
  for (unsigned int i = 0; i < n; i++) {
    iov[i].iov_base = pdv[i].vm_pkt_iov->iov_base;
    iov[i].iov_len = pdv[i].vm_pkt_iov->iov_len;
    msg[i].msg_iov = &iov[i];
    msg[i].msg_iovlen = 1;
    msg[i].msg_name = &localaddr;
    msg[i].msg_namelen = sizeof(struct sockaddr_un);
    msg[i].msg_control = &to;
    msg[i].msg_controllen = sizeof(struct sockaddr_un);
    msg[i].msg_flags = 0;
  }
  ssize_t sent = syscall(SYS_sendmsg_x, fd, msg, n, 0);
  if (sent <= 0) {
    fprintf(stderr, "sendmsg_x() failed: %s\n", strerror(errno));
    perror("sendmsg_x");
    return -1;
  }
  return sent;
}

static void _on_vmnet_packets_available(interface_ref iface, int64_t buf_count,
                                        int64_t max_bytes,
                                        struct state *state) {
  DEBUGF("Receiving from VMNET (buffer for %lld packets, max: %lld "
         "bytes)",
         buf_count, max_bytes);
  // TODO: use prealloced pool
  // struct iovec *iov = calloc(buf_count, sizeof(struct iovec));
  // if (iov == NULL) {
  //   perror("calloc(buf_count, sizeof(struct iovec))");
  //   goto done;
  // }
  // void *buf = calloc(buf_count, max_bytes);
  // if (buf == NULL) {
  //   perror("calloc(buf_count, max_bytes)");
  //   goto done;
  // }
  struct vmpktdesc *pdv = calloc(buf_count, sizeof(struct vmpktdesc));
  if (pdv == NULL) {
    perror("calloc(estim_count, sizeof(struct vmpktdesc)");
    goto done;
  }
  for (int i = 0; i < buf_count; i++) {
    pdv[i].vm_flags = 0;
    pdv[i].vm_pkt_size = max_bytes;
    // pdv[i].vm_pkt_iovcnt = 1, pdv[i].vm_pkt_iov = &iov[i];
    pdv[i].vm_pkt_iovcnt = 1, pdv[i].vm_pkt_iov = malloc(sizeof(struct iovec));
    if (pdv[i].vm_pkt_iov == NULL) {
      perror("malloc(sizeof(struct iovec))");
      goto done;
    }
    pdv[i].vm_pkt_iov->iov_base = malloc(max_bytes);
    if (pdv[i].vm_pkt_iov->iov_base == NULL) {
      perror("malloc(max_bytes)");
      goto done;
    }
    pdv[i].vm_pkt_iov->iov_len = max_bytes;
  }
  int received_count = buf_count;
  vmnet_return_t read_status = vmnet_read(iface, pdv, &received_count);
  print_vmnet_status(__FUNCTION__, read_status);
  if (read_status != VMNET_SUCCESS) {
    perror("vmnet_read");
    goto done;
  }

  DEBUGF(
      "Received from VMNET: %d packets (buffer was prepared for %lld packets)",
      received_count, buf_count);
  struct sockaddr_un to;
  dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
  memcpy(&to, &state->remote_addr, sizeof(state->remote_addr));
  dispatch_semaphore_signal(state->sem);
  state->rx+=received_count;

  for (int i = 0; i < received_count; i++) {
    uint8_t dest_mac[6], src_mac[6];
    assert(pdv[i].vm_pkt_iov[0].iov_len > 12);
    memcpy(dest_mac, pdv[i].vm_pkt_iov[0].iov_base, sizeof(dest_mac));
    memcpy(src_mac, pdv[i].vm_pkt_iov[0].iov_base + 6, sizeof(src_mac));
    DEBUGF("[Handler i=%d] Dest %02X:%02X:%02X:%02X:%02X:%02X, Src "
           "%02X:%02X:%02X:%02X:%02X:%02X, size %zu, %s.",
           i, dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4],
           dest_mac[5], src_mac[0], src_mac[1], src_mac[2], src_mac[3],
           src_mac[4], src_mac[5], pdv[i].vm_pkt_size, state->connected?"forward":"drop");
  }
  if (!state->connected) goto done;
  if (sendnmsg(state->socket_fd, pdv, received_count, &to) != received_count) {
    perror("sendto");
    state->connected = false;
    goto done;
  }
done:
  if (pdv != NULL) {
    for (int i = 0; i < buf_count; i++) {
      if (pdv[i].vm_pkt_iov != NULL) {
        if (pdv[i].vm_pkt_iov->iov_base != NULL) {
          free(pdv[i].vm_pkt_iov->iov_base);
        }
        free(pdv[i].vm_pkt_iov);
      }
    }
    free(pdv);
  }
  // if (pdv != NULL) free(pdv);
  // if (iov != NULL) free(iov);
  // if (buf != NULL) free(buf);
  static int i = 0;
  if ( state->connected/*  && (i%2==0) */) {
    fprintf(stdout, "\rguest tx:%lld rx:%lld", state->tx, state->rx);
    fflush(stdout);
  }
  i++;
}
#else
static void _on_vmnet_packets_available(interface_ref iface, int64_t buf_count,
                                        int64_t max_bytes,
                                        struct state *state) {
  DEBUGF("Receiving from VMNET (buffer for %lld packets, max: %lld "
         "bytes)",
         buf_count, max_bytes);
  // TODO: use prealloced pool
  struct vmpktdesc *pdv = calloc(buf_count, sizeof(struct vmpktdesc));
  if (pdv == NULL) {
    perror("calloc(estim_count, sizeof(struct vmpktdesc)");
    goto done;
  }
  for (int i = 0; i < buf_count; i++) {
    pdv[i].vm_flags = 0;
    pdv[i].vm_pkt_size = max_bytes;
    pdv[i].vm_pkt_iovcnt = 1, pdv[i].vm_pkt_iov = malloc(sizeof(struct iovec));
    if (pdv[i].vm_pkt_iov == NULL) {
      perror("malloc(sizeof(struct iovec))");
      goto done;
    }
    pdv[i].vm_pkt_iov->iov_base = malloc(max_bytes);
    if (pdv[i].vm_pkt_iov->iov_base == NULL) {
      perror("malloc(max_bytes)");
      goto done;
    }
    pdv[i].vm_pkt_iov->iov_len = max_bytes;
  }
  int received_count = buf_count;
  vmnet_return_t read_status = vmnet_read(iface, pdv, &received_count);
  print_vmnet_status(__FUNCTION__, read_status);
  if (read_status != VMNET_SUCCESS) {
    perror("vmnet_read");
    goto done;
  }

  DEBUGF(
      "Received from VMNET: %d packets (buffer was prepared for %lld packets)",
      received_count, buf_count);
  struct sockaddr_un to;
  dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
  memcpy(&to, &state->remote_addr, sizeof(state->remote_addr));
  dispatch_semaphore_signal(state->sem);
  for (int i = 0; i < received_count; i++) {
    uint8_t dest_mac[6], src_mac[6];
    assert(pdv[i].vm_pkt_iov[0].iov_len > 12);
    memcpy(dest_mac, pdv[i].vm_pkt_iov[0].iov_base, sizeof(dest_mac));
    memcpy(src_mac, pdv[i].vm_pkt_iov[0].iov_base + 6, sizeof(src_mac));
    DEBUGF("[Handler i=%d] Dest %02X:%02X:%02X:%02X:%02X:%02X, Src "
           "%02X:%02X:%02X:%02X:%02X:%02X, size %zu, %s.",
           i, dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4],
           dest_mac[5], src_mac[0], src_mac[1], src_mac[2], src_mac[3],
           src_mac[4], src_mac[5], pdv[i].vm_pkt_size, state->connected?"forward":"drop");
    
    if (!state->connected) continue;
    
    ssize_t written = sendto(state->socket_fd, pdv[i].vm_pkt_iov[0].iov_base, pdv[i].vm_pkt_size, 0, 
                              (struct sockaddr *)&to, sizeof(to));
    if (written < 0) {
      perror("sendto");
      state->connected = false;
      goto done;
    }
    state->rx++;
  }
done:
  if (pdv != NULL) {
    for (int i = 0; i < buf_count; i++) {
      if (pdv[i].vm_pkt_iov != NULL) {
        if (pdv[i].vm_pkt_iov->iov_base != NULL) {
          free(pdv[i].vm_pkt_iov->iov_base);
        }
        free(pdv[i].vm_pkt_iov);
      }
    }
    free(pdv);
  }
  static int i = 0;
  // if ( state->connected/*  && (i%2==0) */) {
  //   fprintf(stdout, "\rguest tx:%lld rx:%lld", state->tx, state->rx);
  //   fflush(stdout);
  // }
  i++;
}
#endif

#define MAX_PACKET_COUNT_AT_ONCE 32
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

static interface_ref start(struct state *state, struct cli_options *cliopt) {
  printf("Initializing vmnet.framework (mode host-only)\n");
  xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_uint64(dict, vmnet_operation_mode_key, VMNET_HOST_MODE);
  if (cliopt->vmnet_gateway != NULL) {
    xpc_dictionary_set_string(dict, vmnet_start_address_key,
                              cliopt->vmnet_gateway);
    xpc_dictionary_set_string(dict, vmnet_subnet_mask_key, cliopt->vmnet_mask);
  }

  xpc_dictionary_set_uuid(dict, vmnet_interface_id_key,
                          cliopt->vmnet_interface_id);

  // Appears to simply generate a mac address unlikely to be used elsewhere.
  // No edge mac filtering was seen with this simple test tool.
  // If false then the interface_param generated will not have either a
  // vmnet_mac_address or a vmnet_interface_id key.
  //
  // The documentation implies that if you want the same mac address, you
  // set the interface_desc vmnet_interface_id_key to the uuid you get from
  // the interface_param.  However, this all refers to the "guest" MAC
  // and we are trying to emulate a VPN...
  xpc_dictionary_set_bool(dict,
      vmnet_allocate_mac_address_key,
      false
  );

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

  dispatch_queue_t event_q = dispatch_queue_create(
      "io.github.lima-vm.socket_vmnet.events", DISPATCH_QUEUE_CONCURRENT);
  vmnet_interface_set_event_callback(
      iface, VMNET_INTERFACE_PACKETS_AVAILABLE, event_q,
      ^(interface_event_t __attribute__((unused)) x_event_id,
        xpc_object_t x_event) {
        uint64_t estim_count = xpc_dictionary_get_uint64(
            x_event, vmnet_estimated_packets_available_key);
        on_vmnet_packets_available(iface, estim_count, max_bytes, state);
      });

  return iface;
}

static sigjmp_buf jmpbuf;
static void signalhandler(int signal) {
  printf("\nReceived signal %d\n", signal);
  siglongjmp(jmpbuf, 1);
}

static void stop(interface_ref iface) {
  if (iface == NULL) {
    return;
  }
  dispatch_queue_t q = dispatch_queue_create(
      "io.github.lima-vm.socket_vmnet.stop", DISPATCH_QUEUE_SERIAL);
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  __block vmnet_return_t status;
  vmnet_stop_interface(iface, q, ^(vmnet_return_t x_status) {
    status = x_status;
    dispatch_semaphore_signal(sem);
  });
  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
  print_vmnet_status(__FUNCTION__, status);
  dispatch_release(q);
  // TODO: release event_q ?
}

static int socket_bind(const char *socket_path,
                             const char *socket_group) {
  int fd = -1;
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  unlink(socket_path); /* avoid EADDRINUSE */
  if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    goto err;
  }
  addr.sun_family = AF_UNIX;
  if (strlen(socket_path) + 1 > sizeof(addr.sun_path)) {
    fprintf(stderr, "the socket path is too long\n");
    goto err;
  }
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    goto err;
  }
  memcpy(&localaddr, &addr, sizeof(addr));
  if (socket_group != NULL) {
    struct group *grp = getgrnam(socket_group); /* Do not free */
    if (grp == NULL) {
      if (errno != 0)
        perror("getgrnam");
      else
        fprintf(stderr, "unknown group name \"%s\"\n", socket_group);
      goto err;
    }
    /* fchown can't be used (EINVAL) */
    if (chown(socket_path, -1, grp->gr_gid) < 0) {
      perror("chown");
      goto err;
    }
    if (chmod(socket_path, 0770) < 0) {
      perror("chmod");
      goto err;
    }
  }
    int sndbuflen = 2 * 1024 * 1024; /* for SO_RCVBUF/SO_SNDBUF - see below */
    int rcvbuflen = 6 * 1024 * 1024;
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
  return fd;
err:
  if (fd >= 0)
    close(fd);
  return -1;
}

static void on_accept(struct state *state, int accept_fd, interface_ref iface);

int main(int argc, char *argv[]) {
  debug = false;//getenv("DEBUG") != NULL;
  int rc = 1, listen_fd = -1;
  __block interface_ref iface = NULL;
  dispatch_queue_t q = dispatch_queue_create(
      "io.github.lima-vm.socket_vmnet.accept", DISPATCH_QUEUE_CONCURRENT);

  // struct cli_options *cliopt = cli_options_parse(argc, argv);
  struct cli_options opt = {
    .socket_path = "./objs/tap.sock",
    .socket_group = NULL
  };
  uuid_parse("44381771-A145-4499-B6DB-4678C93726B2", opt.vmnet_interface_id);
  struct cli_options *cliopt = &opt;
  assert(cliopt != NULL);
  if (geteuid() != 0) {
    fprintf(stderr, "WARNING: Running without root. This is very unlikely to "
                    "work. See README.md .\n");
  }
  if (geteuid() != getuid()) {
    fprintf(stderr, "WARNING: Seems running with SETUID. This is insecure and "
                    "highly discouraged. See README.md .\n");
  }

  if (sigsetjmp(jmpbuf, 1) != 0) {
    goto done;
  }
  signal(SIGHUP, signalhandler);
  signal(SIGINT, signalhandler);
  signal(SIGTERM, signalhandler);
  signal(SIGPIPE, signalhandler);

  DEBUGF("Opening socket \"%s\" (for UNIX group \"%s\")", cliopt->socket_path,
         cliopt->socket_group);
  listen_fd = socket_bind(cliopt->socket_path, cliopt->socket_group);
  if (listen_fd < 0) {
    perror("socket_bind");
    goto done;
  }

  system("chmod 777 ./objs/tap.sock");

  struct state state;
  memset(&state, 0, sizeof(state));
  state.sem = dispatch_semaphore_create(1);
  iface = start(&state, cliopt);
  if (iface == NULL) {
    perror("start");
    goto done;
  }

  struct state *state_p = &state;
  dispatch_async(q, ^{
    on_accept(state_p, listen_fd, iface);
  });

  while (1) {
    sleep(10000);
  }
  rc = 0;
done:
  DEBUGF("shutting down with rc=%d", rc);
  dispatch_release(q);
  if (iface != NULL) {
    stop(iface);
  }
  if (listen >= 0) {
    close(listen_fd);
  }
  // cli_options_destroy(cliopt);
  return rc;
}

static void on_accept(struct state *state, int accept_fd, interface_ref iface) {
  state_set_socket_fd(state, accept_fd);
  unsigned int numMsg = 32;
  size_t buflen = 1600;
  socklen_t cmsgLen = sizeof(state->remote_addr);

	struct msghdr_x *msgList = NULL;
	struct sockaddr_un *srcAddrs = NULL;
	struct iovec *vec = NULL;
	char *buffers = NULL;
	char *cmsgBuf = NULL;

	msgList = calloc(numMsg, sizeof(struct msghdr_x));
  if (!msgList) {
    fprintf(stderr, "calloc msgList failed\n");
    goto out;
  }
  bzero(msgList, numMsg*sizeof(struct msghdr_x));
	srcAddrs = calloc(numMsg, sizeof(struct sockaddr_un));
  if (!srcAddrs) {
    fprintf(stderr, "calloc srcAddrs failed\n");
    goto out;
  }
	vec = calloc(numMsg, sizeof(struct iovec));
  if (!vec) {
    fprintf(stderr, "calloc vec failed\n");
    goto out;
  }
	buffers = calloc(numMsg, buflen);
  if (!buffers) {
    fprintf(stderr, "calloc buffers failed\n");
    goto out;
  }
	cmsgBuf = calloc(numMsg, ALIGN(cmsgLen));
  if (!cmsgBuf) {
    fprintf(stderr, "calloc cmsgBuf failed\n");
    goto out;
  }
  for (unsigned int i = 0; i < numMsg; i++) {
    struct msghdr_x *msg = &msgList[i];
    msg->msg_name = &srcAddrs[i];
    msg->msg_namelen = sizeof(srcAddrs[i]);
    vec[i].iov_base = buffers + (i * buflen);
    vec[i].iov_len = buflen;
    msg->msg_iov = &vec[i];
    msg->msg_iovlen = 1;
    msg->msg_control = cmsgBuf + (i * ALIGN(cmsgLen));
    msg->msg_controllen = cmsgLen;
    msg->msg_flags = 0;
    assert((uintptr_t)msg->msg_control % sizeof(uint32_t) == 0);
  }

  for (uint64_t i = 0;; i++) {
    DEBUGF("[Socket-to-VMNET i=%lld] Receiving from the socket %d", i,
           accept_fd);

    // ssize_t received = syscall(SYS_recvmsg_x, accept_fd, msgList, numMsg, 0);
    ssize_t received = recvmsg_x(accept_fd, msgList, numMsg, 0);
		if (received <= 0) {
			fprintf(stderr, "recvmsg_x() failed: %s\n", strerror(errno));
      perror("recvmsg_x");
      goto done;
		}
    if (!state->connected) {
      dispatch_semaphore_wait(state->sem, DISPATCH_TIME_FOREVER);
      memcpy(&state->remote_addr, msgList[0].msg_name, sizeof(state->remote_addr));
      dispatch_semaphore_signal(state->sem);
    }

    if (received < 0) {
      perror("read");
      goto done;
    }
    if (received == 0) {
      // EOF according to man page of read.
      goto done;
    }
    if (!state->connected) fprintf(stdout, "%s connected\n", state->remote_addr.sun_path);
    state->connected = true;
    state->tx+=received;
		// for (unsigned int ii = 0; ii < (u_int)received; ii++) {
      DEBUGF("[Socket-to-VMNET i=%lld] Received from the socket %d: %ld pkts", i,
            accept_fd, received);
      struct iovec iov[received];
      struct vmpktdesc pkts[received];
      for (unsigned int ii = 0; ii < (u_int)received; ii++) {
        iov[ii].iov_base = msgList[ii].msg_iov->iov_base;
        iov[ii].iov_len = msgList[ii].msg_datalen;
        pkts[ii].vm_pkt_iov = &iov[ii];
        pkts[ii].vm_pkt_size = iov[ii].iov_len;
        // pkts[ii].vm_pkt_iov = msgList[ii].msg_iov;
        // pkts[ii].vm_pkt_size = msgList[ii].msg_datalen;
        pkts[ii].vm_pkt_iovcnt = 1;
        pkts[ii].vm_flags = 0;
      }
      int written_count = received;
      DEBUGF("[Socket-to-VMNET i=%lld] Sending to VMNET: %ld bytes", i,
            received);
      vmnet_return_t write_status = vmnet_write(iface, pkts, &written_count);
      print_vmnet_status(__FUNCTION__, write_status);
      if (write_status != VMNET_SUCCESS) {
        perror("vmnet_write");
        // goto done;
      }
      // printf("\r[Socket-to-VMNET i=%lld] Sent to VMNET: %ld pkts", i,
      //       written_count);
      DEBUGF("[Socket-to-VMNET i=%lld] Sent to VMNET: %d pkts", i,
            written_count);
    // }
    // if ( state->connected  && (i%2000==0)  ) {
    //   fprintf(stdout, "\rguest tx:%lld rx:%lld", state->tx, state->rx);
    //   fflush(stdout);
    // }
  }
done:
  printf("Closing a connection (fd %d)\n", accept_fd);
  state_remove_socket_fd(state, accept_fd);
  close(accept_fd);

out:
	if (msgList) free(msgList);
	if (srcAddrs) free(srcAddrs);
	if (vec) free(vec);
	if (buffers) free(buffers);
	if (cmsgBuf) free(cmsgBuf);
}

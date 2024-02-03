#ifndef SOCKET_VMNET_CLI_H
#define SOCKET_VMNET_CLI_H

#include <uuid/uuid.h>

#include <vmnet/vmnet.h>

struct cli_options {
  // --socket-group
  char *socket_group;
  // --vmnet-gateway, corresponds to vmnet_start_address_key
  char *vmnet_gateway;
  // --vmnet-mask, corresponds to vmnet_subnet_mask_key
  char *vmnet_mask;
  // --vmnet-interface-id, corresponds to vmnet_interface_id_key
  uuid_t vmnet_interface_id;
  // arg
  char *socket_path;
};

void cli_options_destroy(struct cli_options *);

#endif /* SOCKET_VMNET_CLI_H */

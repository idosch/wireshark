/* packet-netlink-devlink.c
 * Routines for netlink-devlink dissection
 * Based on netlink-route dissector
 * Copyright 2019, Ido Schimmel <idosch@mellanox.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * devlink (device netlink) is a netlink-based protocol to configure
 * device-specific attributes. For example, the shared buffers of a network
 * switch. This is in contrast to netdev-specific configuration (e.g., MTU)
 * that is performed using rtnetlink.
 *
 * Relevant header file:
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/devlink.h
 *
 * Man page:
 * man 8 devlink
 */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>

#include "packet-netlink.h"

void proto_register_netlink_devlink(void);
void proto_reg_handoff_netlink_devlink(void);

enum ws_devlink_commands {
	WS_DEVLINK_CMD_UNSPEC			= 0,
	WS_DEVLINK_CMD_GET			= 1,
	WS_DEVLINK_CMD_SET			= 2,
	WS_DEVLINK_CMD_NEW			= 3,
	WS_DEVLINK_CMD_DEL			= 4,
	WS_DEVLINK_CMD_PORT_GET			= 5,
	WS_DEVLINK_CMD_PORT_SET			= 6,
	WS_DEVLINK_CMD_PORT_NEW			= 7,
	WS_DEVLINK_CMD_PORT_DEL			= 8,
	WS_DEVLINK_CMD_PORT_SPLIT		= 9,
	WS_DEVLINK_CMD_PORT_UNSPLIT		= 11,
	WS_DEVLINK_CMD_TRAP_GET			= 61,
	WS_DEVLINK_CMD_TRAP_SET			= 62,
	WS_DEVLINK_CMD_TRAP_NEW			= 63,
	WS_DEVLINK_CMD_TRAP_DEL			= 64,
	WS_DEVLINK_CMD_TRAP_REPORT		= 65,
	WS_DEVLINK_CMD_TRAP_GROUP_GET		= 66,
	WS_DEVLINK_CMD_TRAP_GROUP_SET		= 67,
	WS_DEVLINK_CMD_TRAP_GROUP_NEW		= 68,
	WS_DEVLINK_CMD_TRAP_GROUP_DEL		= 69,
};

enum ws_devlink_attrs {
	WS_DEVLINK_ATTR_UNSPEC				= 0,
	WS_DEVLINK_ATTR_BUS_NAME			= 1,
	WS_DEVLINK_ATTR_DEV_NAME			= 2,
	WS_DEVLINK_ATTR_PORT_INDEX			= 3,
	WS_DEVLINK_ATTR_PORT_TYPE			= 4,
	WS_DEVLINK_ATTR_PORT_DESIRED_TYPE		= 5,
	WS_DEVLINK_ATTR_PORT_NETDEV_IFINDEX		= 6,
	WS_DEVLINK_ATTR_PORT_NETDEV_NAME		= 7,
	WS_DEVLINK_ATTR_PORT_IBDEV_NAME			= 8,
	WS_DEVLINK_ATTR_PORT_SPLIT_COUNT		= 9,
	WS_DEVLINK_ATTR_PORT_SPLIT_GROUP		= 10,
	WS_DEVLINK_ATTR_PAD				= 61,
	WS_DEVLINK_ATTR_PORT_FLAVOUR			= 77,
	WS_DEVLINK_ATTR_PORT_NUMBER			= 78,
	WS_DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER	= 79,
	WS_DEVLINK_ATTR_STATS				= 127,
	WS_DEVLINK_ATTR_TRAP_NAME			= 128,
	WS_DEVLINK_ATTR_TRAP_REPORT_ENABLED		= 129,
	WS_DEVLINK_ATTR_TRAP_ACTION			= 130,
	WS_DEVLINK_ATTR_TRAP_TYPE			= 131,
	WS_DEVLINK_ATTR_TRAP_GENERIC			= 132,
	WS_DEVLINK_ATTR_TRAP_METADATA			= 133,
	WS_DEVLINK_ATTR_TRAP_TIMESTAMP			= 134,
	WS_DEVLINK_ATTR_TRAP_IN_PORT			= 135,
	WS_DEVLINK_ATTR_TRAP_PAYLOAD			= 136,
	WS_DEVLINK_ATTR_TRAP_GROUP_NAME			= 137,
};

enum ws_devlink_port_type {
	WS_DEVLINK_PORT_TYPE_NOTSET,
	WS_DEVLINK_PORT_TYPE_AUTO,
	WS_DEVLINK_PORT_TYPE_ETH,
	WS_DEVLINK_PORT_TYPE_IB,
};

enum {
	WS_DEVLINK_PORT_FLAVOUR_PHYSICAL,
	WS_DEVLINK_PORT_FLAVOUR_CPU,
	WS_DEVLINK_PORT_FLAVOUR_DSA,
};

enum {
	WS_DEVLINK_TRAP_ACTION_DROP,
	WS_DEVLINK_TRAP_ACTION_TRAP,
};

enum {
	WS_DEVLINK_TRAP_TYPE_DROP,
	WS_DEVLINK_TRAP_TYPE_EXCEPTION,
};

enum ws_devlink_attrs_stats {
	WS_DEVLINK_ATTR_STATS_RX_PACKETS,
	WS_DEVLINK_ATTR_STATS_RX_BYTES,
};

enum ws_devlink_attrs_trap_metadata_type {
	WS_DEVLINK_ATTR_TRAP_METADATA_TYPE_IN_PORT,
};

struct netlink_devlink_info {
	packet_info *pinfo;
	struct packet_netlink_data *data;
	int encoding; /* copy of data->encoding */
	enum ws_devlink_port_type devlink_port_type;
};

static int proto_netlink_devlink = -1;

static dissector_handle_t netlink_devlink_handle;
static dissector_handle_t eth_handle;

static header_field_info *hfi_netlink_devlink = NULL;

#define NETLINK_DEVLINK_HFI_INIT HFI_INIT(proto_netlink_devlink)

static gint ett_devlink = -1;
static gint ett_devlink_attrs = -1;
static gint ett_devlink_attrs_stats = -1;
static gint ett_devlink_attrs_trap_metadata = -1;
static gint ett_devlink_attrs_trap_in_port = -1;

static const value_string ws_devlink_commands_vals[] = {
	{ WS_DEVLINK_CMD_UNSPEC,		"Unspecified command" },
	{ WS_DEVLINK_CMD_GET,			"Get device info" },
	{ WS_DEVLINK_CMD_SET,			"Set device info" },
	{ WS_DEVLINK_CMD_NEW,			"Create device" },
	{ WS_DEVLINK_CMD_DEL,			"Delete device" },
	{ WS_DEVLINK_CMD_PORT_GET,		"Get port info" },
	{ WS_DEVLINK_CMD_PORT_SET,		"Set port info" },
	{ WS_DEVLINK_CMD_PORT_NEW,		"Create port" },
	{ WS_DEVLINK_CMD_PORT_DEL,		"Delete port" },
	{ WS_DEVLINK_CMD_PORT_SPLIT,		"Split port" },
	{ WS_DEVLINK_CMD_PORT_UNSPLIT,		"Unsplit port" },
	{ WS_DEVLINK_CMD_TRAP_GET,		"Get trap info" },
	{ WS_DEVLINK_CMD_TRAP_SET,		"Set trap info" },
	{ WS_DEVLINK_CMD_TRAP_NEW,		"Create trap" },
	{ WS_DEVLINK_CMD_TRAP_DEL,		"Delete trap" },
	{ WS_DEVLINK_CMD_TRAP_REPORT,		"Trap report" },
	{ WS_DEVLINK_CMD_TRAP_GROUP_GET,	"Get trap group info" },
	{ WS_DEVLINK_CMD_TRAP_GROUP_SET,	"Set trap group info" },
	{ WS_DEVLINK_CMD_TRAP_GROUP_NEW,	"Create trap group" },
	{ WS_DEVLINK_CMD_TRAP_GROUP_DEL,	"Delete trap group" },
	{ 0, NULL },
};

static value_string_ext ws_devlink_commands_vals_ext = VALUE_STRING_EXT_INIT(ws_devlink_commands_vals);

static const value_string ws_devlink_attrs_vals[] = {
	{ WS_DEVLINK_ATTR_UNSPEC,			"Unspecified" },
	{ WS_DEVLINK_ATTR_BUS_NAME,			"Bus name" },
	{ WS_DEVLINK_ATTR_DEV_NAME,			"Device name" },
	{ WS_DEVLINK_ATTR_PORT_INDEX,			"Port index" },
	{ WS_DEVLINK_ATTR_PORT_TYPE,			"Port type" },
	{ WS_DEVLINK_ATTR_PORT_DESIRED_TYPE,		"Port desired type" },
	{ WS_DEVLINK_ATTR_PORT_NETDEV_IFINDEX,		"Net device index" },
	{ WS_DEVLINK_ATTR_PORT_NETDEV_NAME,		"Net device name" },
	{ WS_DEVLINK_ATTR_PORT_IBDEV_NAME,		"Infiniband device name" },
	{ WS_DEVLINK_ATTR_PORT_SPLIT_COUNT,		"Port split count" },
	{ WS_DEVLINK_ATTR_PORT_SPLIT_GROUP,		"Port split group" },
	{ WS_DEVLINK_ATTR_PAD,				"Pad" },
	{ WS_DEVLINK_ATTR_PORT_FLAVOUR,			"Port flavour" },
	{ WS_DEVLINK_ATTR_PORT_NUMBER,			"Port number" },
	{ WS_DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER,	"Port split subport number" },
	{ WS_DEVLINK_ATTR_STATS,			"Statistics" },
	{ WS_DEVLINK_ATTR_TRAP_NAME,			"Trap name" },
	{ WS_DEVLINK_ATTR_TRAP_REPORT_ENABLED,		"Trap report status" },
	{ WS_DEVLINK_ATTR_TRAP_ACTION,			"Trap action" },
	{ WS_DEVLINK_ATTR_TRAP_TYPE,			"Trap type" },
	{ WS_DEVLINK_ATTR_TRAP_GENERIC,			"Generic trap" },
	{ WS_DEVLINK_ATTR_TRAP_METADATA,		"Trap metadata" },
	{ WS_DEVLINK_ATTR_TRAP_TIMESTAMP,		"Trap timestamp" },
	{ WS_DEVLINK_ATTR_TRAP_IN_PORT,			"Trap input port" },
	{ WS_DEVLINK_ATTR_TRAP_PAYLOAD,			"Trap payload" },
	{ WS_DEVLINK_ATTR_TRAP_GROUP_NAME,		"Trap group name" },
	{ 0, NULL },
};

static value_string_ext ws_devlink_attrs_vals_ext = VALUE_STRING_EXT_INIT(ws_devlink_attrs_vals);

static const value_string ws_devlink_port_type_vals[] = {
	{ WS_DEVLINK_PORT_TYPE_NOTSET,		"Not set" },
	{ WS_DEVLINK_PORT_TYPE_AUTO,		"Auto" },
	{ WS_DEVLINK_PORT_TYPE_ETH,		"Ethernet" },
	{ WS_DEVLINK_PORT_TYPE_IB,		"Infiniband" },
	{ 0, NULL },
};

static const value_string ws_devlink_port_flavour_vals[] = {
	{ WS_DEVLINK_PORT_FLAVOUR_PHYSICAL,	"Physical" },
	{ WS_DEVLINK_PORT_FLAVOUR_CPU,		"CPU" },
	{ WS_DEVLINK_PORT_FLAVOUR_DSA,		"DSA" },
	{ 0, NULL },
};

static const value_string ws_devlink_trap_action_vals[] = {
	{ WS_DEVLINK_TRAP_ACTION_DROP,		"Drop" },
	{ WS_DEVLINK_TRAP_ACTION_TRAP,		"Trap" },
	{ 0, NULL },
};

static const value_string ws_devlink_trap_type_vals[] = {
	{ WS_DEVLINK_TRAP_TYPE_DROP,		"Drop" },
	{ WS_DEVLINK_TRAP_TYPE_EXCEPTION,	"Exception" },
	{ 0, NULL },
};

static const value_string ws_devlink_attrs_stats_vals[] = {
	{ WS_DEVLINK_ATTR_STATS_RX_PACKETS,	"Rx packets" },
	{ WS_DEVLINK_ATTR_STATS_RX_BYTES,	"Rx bytes" },
	{ 0, NULL },
};

static const value_string ws_devlink_attrs_trap_metadata_vals[] = {
	{ WS_DEVLINK_ATTR_TRAP_METADATA_TYPE_IN_PORT,	"Input port" },
	{ 0, NULL },
};

static header_field_info hfi_devlink_commands NETLINK_DEVLINK_HFI_INIT =
	{ "Command", "devlink.cmd", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
	  &ws_devlink_commands_vals_ext, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_attrs NETLINK_DEVLINK_HFI_INIT =
	{ "Attribute type", "devlink.attr_type", FT_UINT16, BASE_DEC | BASE_EXT_STRING,
	  &ws_devlink_attrs_vals_ext, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_bus_name NETLINK_DEVLINK_HFI_INIT =
	{ "Bus name", "devlink.bus_name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_dev_name NETLINK_DEVLINK_HFI_INIT =
	{ "Device name", "devlink.dev_name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_port_index NETLINK_DEVLINK_HFI_INIT =
	{ "Port index", "devlink.port_index", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_port_type NETLINK_DEVLINK_HFI_INIT =
	{ "Port type", "devlink.port_type", FT_UINT16, BASE_DEC,
	  &ws_devlink_port_type_vals, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_port_desired_type NETLINK_DEVLINK_HFI_INIT =
	{ "Port desired type", "devlink.port_desired_type", FT_UINT16, BASE_DEC,
	  &ws_devlink_port_type_vals, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_port_netdev_index NETLINK_DEVLINK_HFI_INIT =
	{ "Port net device index", "devlink.port_netdev_index", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_port_netdev_name NETLINK_DEVLINK_HFI_INIT =
	{ "Port net device name", "devlink.port_netdev_name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_port_ibdev_name NETLINK_DEVLINK_HFI_INIT =
	{ "Port infiniband device name", "devlink.port_ibdev_name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_port_split_count NETLINK_DEVLINK_HFI_INIT =
	{ "Port split count", "devlink.port_split_count", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_port_split_group NETLINK_DEVLINK_HFI_INIT =
	{ "Port split group", "devlink.port_split_group", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_port_flavour NETLINK_DEVLINK_HFI_INIT =
	{ "Port flavour", "devlink.port_flavour", FT_UINT16, BASE_DEC,
	  &ws_devlink_port_flavour_vals, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_port_number NETLINK_DEVLINK_HFI_INIT =
	{ "Port number", "devlink.port_number", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_port_split_subport_number NETLINK_DEVLINK_HFI_INIT =
	{ "Port split subport number", "devlink.port_split_subport_number", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_trap_name NETLINK_DEVLINK_HFI_INIT =
	{ "Trap name", "devlink.trap_name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_trap_report NETLINK_DEVLINK_HFI_INIT =
	{ "Trap report", "devlink.trap_report", FT_BOOLEAN, 8,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_trap_action NETLINK_DEVLINK_HFI_INIT =
	{ "Trap action", "devlink.trap_action", FT_UINT8, BASE_DEC,
	  &ws_devlink_trap_action_vals, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_trap_type NETLINK_DEVLINK_HFI_INIT =
	{ "Trap type", "devlink.trap_type", FT_UINT8, BASE_DEC,
	  &ws_devlink_trap_type_vals, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_trap_generic NETLINK_DEVLINK_HFI_INIT =
	{ "Trap generic", "devlink.trap_generic", FT_NONE, BASE_NONE,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_attrs_stats NETLINK_DEVLINK_HFI_INIT =
	{ "Attribute type", "devlink.attr_stats_type", FT_UINT16, BASE_DEC,
	  &ws_devlink_attrs_stats_vals, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_stats_rx_packets NETLINK_DEVLINK_HFI_INIT =
	{ "Rx packets", "devlink.stats.rx_packets", FT_UINT64, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_stats_rx_bytes NETLINK_DEVLINK_HFI_INIT =
	{ "Rx bytes", "devlink.stats.rx_bytes", FT_UINT64, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_attrs_trap_metadata NETLINK_DEVLINK_HFI_INIT =
	{ "Attribute type", "devlink.attr_trap_metadata_type", FT_UINT16, BASE_DEC,
	  &ws_devlink_attrs_trap_metadata_vals, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_trap_metadata_in_port NETLINK_DEVLINK_HFI_INIT =
	{ "Input port", "devlink.trap_metadata_type.in_port", FT_NONE, BASE_NONE,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_trap_timestamp NETLINK_DEVLINK_HFI_INIT =
	{ "Trap timestamp", "devlink.trap_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_devlink_trap_group_name NETLINK_DEVLINK_HFI_INIT =
	{ "Trap group name", "devlink.trap_group_name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static int
dissect_devlink_attrs_stats(tvbuff_t *tvb, void *data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_devlink_attrs_stats type = (enum ws_devlink_attrs_stats) nla_type;
	struct netlink_devlink_info *info = (struct netlink_devlink_info *) data;

	switch (type) {
	case WS_DEVLINK_ATTR_STATS_RX_PACKETS:
		proto_tree_add_item(tree, &hfi_devlink_stats_rx_packets, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_STATS_RX_BYTES:
		proto_tree_add_item(tree, &hfi_devlink_stats_rx_bytes, tvb, offset, len, info->encoding);
		return 1;
	default:
		return 0;
	}
}

static int
dissect_devlink_attrs_trap_metadata(tvbuff_t *tvb, void *data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_devlink_attrs_trap_metadata_type type = (enum ws_devlink_attrs_trap_metadata_type) nla_type;
	struct netlink_devlink_info *info = (struct netlink_devlink_info *) data;

	switch (type) {
	case WS_DEVLINK_ATTR_TRAP_METADATA_TYPE_IN_PORT:
		proto_tree_add_item(tree, &hfi_devlink_trap_metadata_in_port, tvb, offset, len, info->encoding);
		return 1;
	default:
		return 0;
	}
}

static int
dissect_devlink_attrs(tvbuff_t *tvb, void *data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_devlink_attrs type = (enum ws_devlink_attrs) nla_type & NLA_TYPE_MASK;
	struct netlink_devlink_info *info = (struct netlink_devlink_info *) data;
	guint32 devlink_port_type;
	tvbuff_t *next_tvb;
	const guint8 *str;

	switch (type) {
	case WS_DEVLINK_ATTR_BUS_NAME:
		proto_tree_add_item_ret_string(tree, &hfi_devlink_bus_name, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
		proto_item_append_text(tree, ": %s", str);
		return 1;
	case WS_DEVLINK_ATTR_DEV_NAME:
		proto_tree_add_item_ret_string(tree, &hfi_devlink_dev_name, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
		proto_item_append_text(tree, ": %s", str);
		return 1;
	case WS_DEVLINK_ATTR_PORT_INDEX:
		proto_item_append_text(tree, ": %u", tvb_get_letohl(tvb, offset));
		proto_tree_add_item(tree, &hfi_devlink_port_index, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_PORT_TYPE:
		proto_tree_add_item_ret_uint(tree, &hfi_devlink_port_type, tvb, offset, len, info->encoding, &devlink_port_type);
		info->devlink_port_type = (enum ws_devlink_port_type) devlink_port_type;
		return 1;
	case WS_DEVLINK_ATTR_PORT_DESIRED_TYPE:
		proto_tree_add_item(tree, &hfi_devlink_port_desired_type, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_PORT_NETDEV_IFINDEX:
		proto_item_append_text(tree, ": %u", tvb_get_letohl(tvb, offset));
		proto_tree_add_item(tree, &hfi_devlink_port_netdev_index, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_PORT_NETDEV_NAME:
		proto_tree_add_item_ret_string(tree, &hfi_devlink_port_netdev_name, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
		proto_item_append_text(tree, ": %s", str);
		return 1;
	case WS_DEVLINK_ATTR_PORT_IBDEV_NAME:
		proto_tree_add_item_ret_string(tree, &hfi_devlink_port_ibdev_name, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
		proto_item_append_text(tree, ": %s", str);
		return 1;
	case WS_DEVLINK_ATTR_PORT_SPLIT_COUNT:
		proto_item_append_text(tree, ": %u", tvb_get_letohl(tvb, offset));
		proto_tree_add_item(tree, &hfi_devlink_port_split_count, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_PORT_SPLIT_GROUP:
		proto_item_append_text(tree, ": %u", tvb_get_letohl(tvb, offset));
		proto_tree_add_item(tree, &hfi_devlink_port_split_group, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_PORT_FLAVOUR:
		proto_tree_add_item(tree, &hfi_devlink_port_flavour, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_PORT_NUMBER:
		proto_item_append_text(tree, ": %u", tvb_get_letohl(tvb, offset));
		proto_tree_add_item(tree, &hfi_devlink_port_number, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER:
		proto_item_append_text(tree, ": %u", tvb_get_letohl(tvb, offset));
		proto_tree_add_item(tree, &hfi_devlink_port_split_subport_number, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_STATS:
		return dissect_netlink_attributes(tvb, &hfi_devlink_attrs_stats, ett_devlink_attrs_stats, info, info->data, tree, offset, len,
						  dissect_devlink_attrs_stats);
	case WS_DEVLINK_ATTR_TRAP_NAME:
		proto_tree_add_item_ret_string(tree, &hfi_devlink_trap_name, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
		proto_item_append_text(tree, ": %s", str);
		return 1;
	case WS_DEVLINK_ATTR_TRAP_REPORT_ENABLED:
		proto_tree_add_item(tree, &hfi_devlink_trap_report, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_TRAP_ACTION:
		proto_tree_add_item(tree, &hfi_devlink_trap_action, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_TRAP_TYPE:
		proto_tree_add_item(tree, &hfi_devlink_trap_type, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_TRAP_GENERIC:
		proto_tree_add_item(tree, &hfi_devlink_trap_generic, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_TRAP_METADATA:
		return dissect_netlink_attributes(tvb, &hfi_devlink_attrs_trap_metadata, ett_devlink_attrs_trap_metadata, info, info->data, tree,
						  offset, len, dissect_devlink_attrs_trap_metadata);
	case WS_DEVLINK_ATTR_TRAP_TIMESTAMP:
		proto_tree_add_item(tree, &hfi_devlink_trap_timestamp, tvb, offset, len, info->encoding);
		return 1;
	case WS_DEVLINK_ATTR_TRAP_IN_PORT:
		return dissect_netlink_attributes(tvb, &hfi_devlink_attrs, ett_devlink_attrs_trap_in_port, info, info->data, tree,
						  offset, len, dissect_devlink_attrs);
	case WS_DEVLINK_ATTR_TRAP_PAYLOAD:
		if (info->devlink_port_type == WS_DEVLINK_PORT_TYPE_ETH) {
			next_tvb = tvb_new_subset_length(tvb, offset, len);
			call_dissector(eth_handle, next_tvb, info->pinfo, tree);
		}
		return 1;
	case WS_DEVLINK_ATTR_TRAP_GROUP_NAME:
		proto_tree_add_item_ret_string(tree, &hfi_devlink_trap_group_name, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
		proto_item_append_text(tree, ": %s", str);
		return 1;
	default:
		return 0;
	}
}

static int
dissect_netlink_devlink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	genl_info_t *genl_info = (genl_info_t *)data;
	struct netlink_devlink_info info;
	proto_tree *nlmsg_tree;
	proto_item *pi;
	int offset;

	DISSECTOR_ASSERT(genl_info);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "devlink");
	col_clear(pinfo->cinfo, COL_INFO);

	/* Generic netlink header */
	offset = dissect_genl_header(tvb, genl_info, &hfi_devlink_commands);

	pi = proto_tree_add_item(tree, proto_registrar_get_nth(proto_netlink_devlink), tvb, offset, -1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_devlink);

	info.encoding = genl_info->encoding;
	info.pinfo = pinfo;
	info.data = genl_info->data;
	info.devlink_port_type = WS_DEVLINK_PORT_TYPE_NOTSET;

	offset = dissect_netlink_attributes(tvb, &hfi_devlink_attrs, ett_devlink_attrs, &info, genl_info->data, nlmsg_tree, offset, -1, dissect_devlink_attrs);

	return offset;
}

void
proto_register_netlink_devlink(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
		&hfi_devlink_commands,
		&hfi_devlink_attrs,
		&hfi_devlink_bus_name,
		&hfi_devlink_dev_name,
		&hfi_devlink_port_index,
		&hfi_devlink_port_type,
		&hfi_devlink_port_desired_type,
		&hfi_devlink_port_netdev_index,
		&hfi_devlink_port_netdev_name,
		&hfi_devlink_port_ibdev_name,
		&hfi_devlink_port_split_count,
		&hfi_devlink_port_split_group,
		&hfi_devlink_port_flavour,
		&hfi_devlink_port_number,
		&hfi_devlink_port_split_subport_number,
		&hfi_devlink_attrs_stats,
		&hfi_devlink_stats_rx_packets,
		&hfi_devlink_stats_rx_bytes,
		&hfi_devlink_trap_name,
		&hfi_devlink_trap_report,
		&hfi_devlink_trap_action,
		&hfi_devlink_trap_type,
		&hfi_devlink_trap_generic,
		&hfi_devlink_attrs_trap_metadata,
		&hfi_devlink_trap_metadata_in_port,
		&hfi_devlink_trap_timestamp,
		&hfi_devlink_trap_group_name,
	};
#endif

	static gint *ett[] = {
		&ett_devlink,
		&ett_devlink_attrs,
		&ett_devlink_attrs_stats,
		&ett_devlink_attrs_trap_metadata,
		&ett_devlink_attrs_trap_in_port,
	};

	proto_netlink_devlink = proto_register_protocol("Linux devlink (device netlink) protocol", "devlink", "devlink");
	hfi_netlink_devlink = proto_registrar_get_nth(proto_netlink_devlink);

	proto_register_fields(proto_netlink_devlink, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_devlink_handle = create_dissector_handle(dissect_netlink_devlink, proto_netlink_devlink);
}

void
proto_reg_handoff_netlink_devlink(void)
{
	dissector_add_string("genl.family", "devlink", netlink_devlink_handle);
	eth_handle = find_dissector_add_dependency("eth_maybefcs", proto_netlink_devlink);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */

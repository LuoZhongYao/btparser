// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <fcntl.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/mgmt.h"

#include "src/shared/util.h"
#include "src/shared/btsnoop.h"

#include "packet.h"
#include "tty.h"
#include "control.h"

static struct btsnoop *btsnoop_file = NULL;
static bool hcidump_fallback = false;
static bool decode_control = true;
static bool use_slip = false;
static uint16_t filter_index = HCI_DEV_NONE;

#define SLIP_SPECIAL_BYTE_END           0xC0
#define SLIP_SPECIAL_BYTE_ESC           0xDB

#define SLIP_ESCAPED_BYTE_END           0xDC
#define SLIP_ESCAPED_BYTE_ESC           0xDD

enum slip_state {
        SLIP_STATE_NORMAL = 0x00,
        SLIP_STATE_ESCAPED
};

struct control_data {
	int fd;
	uint16_t crc;
	uint16_t channel;
	uint16_t offset;
	enum slip_state state;
	unsigned char buf[BTSNOOP_MAX_PACKET_SIZE];
};

static const uint16_t crc_table[256] = {
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5,
        0x60c6, 0x70e7, 0x8108, 0x9129, 0xa14a, 0xb16b,
        0xc18c, 0xd1ad, 0xe1ce, 0xf1ef, 0x1231, 0x0210,
        0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
        0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c,
        0xf3ff, 0xe3de, 0x2462, 0x3443, 0x0420, 0x1401,
        0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b,
        0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6,
        0x5695, 0x46b4, 0xb75b, 0xa77a, 0x9719, 0x8738,
        0xf7df, 0xe7fe, 0xd79d, 0xc7bc, 0x48c4, 0x58e5,
        0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969,
        0xa90a, 0xb92b, 0x5af5, 0x4ad4, 0x7ab7, 0x6a96,
        0x1a71, 0x0a50, 0x3a33, 0x2a12, 0xdbfd, 0xcbdc,
        0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
        0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03,
        0x0c60, 0x1c41, 0xedae, 0xfd8f, 0xcdec, 0xddcd,
        0xad2a, 0xbd0b, 0x8d68, 0x9d49, 0x7e97, 0x6eb6,
        0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
        0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a,
        0x9f59, 0x8f78, 0x9188, 0x81a9, 0xb1ca, 0xa1eb,
        0xd10c, 0xc12d, 0xf14e, 0xe16f, 0x1080, 0x00a1,
        0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c,
        0xe37f, 0xf35e, 0x02b1, 0x1290, 0x22f3, 0x32d2,
        0x4235, 0x5214, 0x6277, 0x7256, 0xb5ea, 0xa5cb,
        0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
        0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447,
        0x5424, 0x4405, 0xa7db, 0xb7fa, 0x8799, 0x97b8,
        0xe75f, 0xf77e, 0xc71d, 0xd73c, 0x26d3, 0x36f2,
        0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9,
        0xb98a, 0xa9ab, 0x5844, 0x4865, 0x7806, 0x6827,
        0x18c0, 0x08e1, 0x3882, 0x28a3, 0xcb7d, 0xdb5c,
        0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0,
        0x2ab3, 0x3a92, 0xfd2e, 0xed0f, 0xdd6c, 0xcd4d,
        0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07,
        0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
        0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba,
        0x8fd9, 0x9ff8, 0x6e17, 0x7e36, 0x4e55, 0x5e74,
        0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

static uint16_t calc_crc_ccitt(uint8_t byte, uint16_t crc_old)
{
        uint8_t index;
        uint16_t crc;

        index = (uint8_t)(byte ^ (crc_old >> 8));
        crc = (uint16_t)(crc_table[index] ^ (crc_old << 8));

        return crc;
}

static void free_data(void *user_data)
{
	struct control_data *data = user_data;

	close(data->fd);

	free(data);
}

static void mgmt_index_added(uint16_t len, const void *buf)
{
	printf("@ Index Added\n");

	packet_hexdump(buf, len);
}

static void mgmt_index_removed(uint16_t len, const void *buf)
{
	printf("@ Index Removed\n");

	packet_hexdump(buf, len);
}

static void mgmt_unconf_index_added(uint16_t len, const void *buf)
{
	printf("@ Unconfigured Index Added\n");

	packet_hexdump(buf, len);
}

static void mgmt_unconf_index_removed(uint16_t len, const void *buf)
{
	printf("@ Unconfigured Index Removed\n");

	packet_hexdump(buf, len);
}

static void mgmt_ext_index_added(uint16_t len, const void *buf)
{
	const struct mgmt_ev_ext_index_added *ev = buf;

	if (len < sizeof(*ev)) {
		printf("* Malformed Extended Index Added control\n");
		return;
	}

	printf("@ Extended Index Added: %u (%u)\n", ev->type, ev->bus);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_ext_index_removed(uint16_t len, const void *buf)
{
	const struct mgmt_ev_ext_index_removed *ev = buf;

	if (len < sizeof(*ev)) {
		printf("* Malformed Extended Index Removed control\n");
		return;
	}

	printf("@ Extended Index Removed: %u (%u)\n", ev->type, ev->bus);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_controller_error(uint16_t len, const void *buf)
{
	const struct mgmt_ev_controller_error *ev = buf;

	if (len < sizeof(*ev)) {
		printf("* Malformed Controller Error control\n");
		return;
	}

	printf("@ Controller Error: 0x%2.2x\n", ev->error_code);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

#ifndef NELEM
#define NELEM(x) (sizeof(x) / sizeof((x)[0]))
#endif

static const char *config_options_str[] = {
	"external", "public-address",
};

static void mgmt_new_config_options(uint16_t len, const void *buf)
{
	uint32_t options;
	unsigned int i;

	if (len < 4) {
		printf("* Malformed New Configuration Options control\n");
		return;
	}

	options = get_le32(buf);

	printf("@ New Configuration Options: 0x%4.4x\n", options);

	if (options) {
		printf("%-12c", ' ');
		for (i = 0; i < NELEM(config_options_str); i++) {
			if (options & (1 << i))
				printf("%s ", config_options_str[i]);
		}
		printf("\n");
	}

	buf += 4;
	len -= 4;

	packet_hexdump(buf, len);
}

static const char *settings_str[] = {
	"powered", "connectable", "fast-connectable", "discoverable",
	"bondable", "link-security", "ssp", "br/edr", "hs", "le",
	"advertising", "secure-conn", "debug-keys", "privacy",
	"configuration", "static-addr", "phy", "wbs"
};

static void mgmt_new_settings(uint16_t len, const void *buf)
{
	uint32_t settings;
	unsigned int i;

	if (len < 4) {
		printf("* Malformed New Settings control\n");
		return;
	}

	settings = get_le32(buf);

	printf("@ New Settings: 0x%4.4x\n", settings);

	if (settings) {
		printf("%-12c", ' ');
		for (i = 0; i < NELEM(settings_str); i++) {
			if (settings & (1 << i))
				printf("%s ", settings_str[i]);
		}
		printf("\n");
	}

	buf += 4;
	len -= 4;

	packet_hexdump(buf, len);
}

static void mgmt_class_of_dev_changed(uint16_t len, const void *buf)
{
	const struct mgmt_ev_class_of_dev_changed *ev = buf;

	if (len < sizeof(*ev)) {
		printf("* Malformed Class of Device Changed control\n");
		return;
	}

	printf("@ Class of Device Changed: 0x%2.2x%2.2x%2.2x\n",
						ev->dev_class[2],
						ev->dev_class[1],
						ev->dev_class[0]);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_local_name_changed(uint16_t len, const void *buf)
{
	const struct mgmt_ev_local_name_changed *ev = buf;

	if (len < sizeof(*ev)) {
		printf("* Malformed Local Name Changed control\n");
		return;
	}

	printf("@ Local Name Changed: %s (%s)\n", ev->name, ev->short_name);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_new_link_key(uint16_t len, const void *buf)
{
	const struct mgmt_ev_new_link_key *ev = buf;
	const char *type;
	char str[18];
	static const char *types[] = {
		"Combination key",
		"Local Unit key",
		"Remote Unit key",
		"Debug Combination key",
		"Unauthenticated Combination key from P-192",
		"Authenticated Combination key from P-192",
		"Changed Combination key",
		"Unauthenticated Combination key from P-256",
		"Authenticated Combination key from P-256",
	};

	if (len < sizeof(*ev)) {
		printf("* Malformed New Link Key control\n");
		return;
	}

	if (ev->key.type < NELEM(types))
		type = types[ev->key.type];
	else
		type = "Reserved";

	ba2str(&ev->key.addr.bdaddr, str);

	printf("@ New Link Key: %s (%d) %s (%u)\n", str,
				ev->key.addr.type, type, ev->key.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_new_long_term_key(uint16_t len, const void *buf)
{
	const struct mgmt_ev_new_long_term_key *ev = buf;
	const char *type;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed New Long Term Key control\n");
		return;
	}

	/* LE SC keys are both for central and peripheral */
	switch (ev->key.type) {
	case 0x00:
		if (ev->key.central)
			type = "Central (Unauthenticated)";
		else
			type = "Peripheral (Unauthenticated)";
		break;
	case 0x01:
		if (ev->key.central)
			type = "Central (Authenticated)";
		else
			type = "Peripheral (Authenticated)";
		break;
	case 0x02:
		type = "SC (Unauthenticated)";
		break;
	case 0x03:
		type = "SC (Authenticated)";
		break;
	case 0x04:
		type = "SC (Debug)";
		break;
	default:
		type = "<unknown>";
		break;
	}

	ba2str(&ev->key.addr.bdaddr, str);

	printf("@ New Long Term Key: %s (%d) %s 0x%02x\n", str,
			ev->key.addr.type, type, ev->key.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_connected(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_connected *ev = buf;
	uint32_t flags;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Connected control\n");
		return;
	}

	flags = le32_to_cpu(ev->flags);
	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Connected: %s (%d) flags 0x%4.4x\n",
						str, ev->addr.type, flags);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_disconnected(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_disconnected *ev = buf;
	char str[18];
	uint8_t reason;
	uint16_t consumed_len;

	if (len < sizeof(struct mgmt_addr_info)) {
		printf("* Malformed Device Disconnected control\n");
		return;
	}

	if (len < sizeof(*ev)) {
		reason = MGMT_DEV_DISCONN_UNKNOWN;
		consumed_len = len;
	} else {
		reason = ev->reason;
		consumed_len = sizeof(*ev);
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Disconnected: %s (%d) reason %u\n", str, ev->addr.type,
									reason);

	buf += consumed_len;
	len -= consumed_len;

	packet_hexdump(buf, len);
}

static void mgmt_connect_failed(uint16_t len, const void *buf)
{
	const struct mgmt_ev_connect_failed *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Connect Failed control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Connect Failed: %s (%d) status 0x%2.2x\n",
					str, ev->addr.type, ev->status);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_pin_code_request(uint16_t len, const void *buf)
{
	const struct mgmt_ev_pin_code_request *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed PIN Code Request control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ PIN Code Request: %s (%d) secure 0x%2.2x\n",
					str, ev->addr.type, ev->secure);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_user_confirm_request(uint16_t len, const void *buf)
{
	const struct mgmt_ev_user_confirm_request *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed User Confirmation Request control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ User Confirmation Request: %s (%d) hint %d value %d\n",
			str, ev->addr.type, ev->confirm_hint, ev->value);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_user_passkey_request(uint16_t len, const void *buf)
{
	const struct mgmt_ev_user_passkey_request *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed User Passkey Request control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ User Passkey Request: %s (%d)\n", str, ev->addr.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_auth_failed(uint16_t len, const void *buf)
{
	const struct mgmt_ev_auth_failed *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Authentication Failed control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Authentication Failed: %s (%d) status 0x%2.2x\n",
					str, ev->addr.type, ev->status);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_found(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_found *ev = buf;
	uint32_t flags;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Found control\n");
		return;
	}

	flags = le32_to_cpu(ev->flags);
	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Found: %s (%d) rssi %d flags 0x%4.4x\n",
					str, ev->addr.type, ev->rssi, flags);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_discovering(uint16_t len, const void *buf)
{
	const struct mgmt_ev_discovering *ev = buf;

	if (len < sizeof(*ev)) {
		printf("* Malformed Discovering control\n");
		return;
	}

	printf("@ Discovering: 0x%2.2x (%d)\n", ev->discovering, ev->type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_blocked(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_blocked *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Blocked control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Blocked: %s (%d)\n", str, ev->addr.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_unblocked(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_unblocked *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Unblocked control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Unblocked: %s (%d)\n", str, ev->addr.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_unpaired(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_unpaired *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Unpaired control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Unpaired: %s (%d)\n", str, ev->addr.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_passkey_notify(uint16_t len, const void *buf)
{
	const struct mgmt_ev_passkey_notify *ev = buf;
	uint32_t passkey;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Passkey Notify control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	passkey = le32_to_cpu(ev->passkey);

	printf("@ Passkey Notify: %s (%d) passkey %06u entered %u\n",
				str, ev->addr.type, passkey, ev->entered);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_new_irk(uint16_t len, const void *buf)
{
	const struct mgmt_ev_new_irk *ev = buf;
	char addr[18], rpa[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed New IRK control\n");
		return;
	}

	ba2str(&ev->rpa, rpa);
	ba2str(&ev->key.addr.bdaddr, addr);

	printf("@ New IRK: %s (%d) %s\n", addr, ev->key.addr.type, rpa);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_new_csrk(uint16_t len, const void *buf)
{
	const struct mgmt_ev_new_csrk *ev = buf;
	const char *type;
	char addr[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed New CSRK control\n");
		return;
	}

	ba2str(&ev->key.addr.bdaddr, addr);

	switch (ev->key.type) {
	case 0x00:
		type = "Local Unauthenticated";
		break;
	case 0x01:
		type = "Remote Unauthenticated";
		break;
	case 0x02:
		type = "Local Authenticated";
		break;
	case 0x03:
		type = "Remote Authenticated";
		break;
	default:
		type = "<unknown>";
		break;
	}

	printf("@ New CSRK: %s (%d) %s (%u)\n", addr, ev->key.addr.type,
							type, ev->key.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_added(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_added *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Added control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Added: %s (%d) %d\n", str, ev->addr.type, ev->action);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_removed(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_removed *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Removed control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Removed: %s (%d)\n", str, ev->addr.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_new_conn_param(uint16_t len, const void *buf)
{
	const struct mgmt_ev_new_conn_param *ev = buf;
	char addr[18];
	uint16_t min, max, latency, timeout;

	if (len < sizeof(*ev)) {
		printf("* Malformed New Connection Parameter control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);
	min = le16_to_cpu(ev->min_interval);
	max = le16_to_cpu(ev->max_interval);
	latency = le16_to_cpu(ev->latency);
	timeout = le16_to_cpu(ev->timeout);

	printf("@ New Conn Param: %s (%d) hint %d min 0x%4.4x max 0x%4.4x "
		"latency 0x%4.4x timeout 0x%4.4x\n", addr, ev->addr.type,
		ev->store_hint, min, max, latency, timeout);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_advertising_added(uint16_t len, const void *buf)
{
	const struct mgmt_ev_advertising_added *ev = buf;

	if (len < sizeof(*ev)) {
		printf("* Malformed Advertising Added control\n");
		return;
	}

	printf("@ Advertising Added: %u\n", ev->instance);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_advertising_removed(uint16_t len, const void *buf)
{
	const struct mgmt_ev_advertising_removed *ev = buf;

	if (len < sizeof(*ev)) {
		printf("* Malformed Advertising Removed control\n");
		return;
	}

	printf("@ Advertising Removed: %u\n", ev->instance);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

void control_message(uint16_t opcode, const void *data, uint16_t size)
{
	if (!decode_control)
		return;

	switch (opcode) {
	case MGMT_EV_INDEX_ADDED:
		mgmt_index_added(size, data);
		break;
	case MGMT_EV_INDEX_REMOVED:
		mgmt_index_removed(size, data);
		break;
	case MGMT_EV_CONTROLLER_ERROR:
		mgmt_controller_error(size, data);
		break;
	case MGMT_EV_NEW_SETTINGS:
		mgmt_new_settings(size, data);
		break;
	case MGMT_EV_CLASS_OF_DEV_CHANGED:
		mgmt_class_of_dev_changed(size, data);
		break;
	case MGMT_EV_LOCAL_NAME_CHANGED:
		mgmt_local_name_changed(size, data);
		break;
	case MGMT_EV_NEW_LINK_KEY:
		mgmt_new_link_key(size, data);
		break;
	case MGMT_EV_NEW_LONG_TERM_KEY:
		mgmt_new_long_term_key(size, data);
		break;
	case MGMT_EV_DEVICE_CONNECTED:
		mgmt_device_connected(size, data);
		break;
	case MGMT_EV_DEVICE_DISCONNECTED:
		mgmt_device_disconnected(size, data);
		break;
	case MGMT_EV_CONNECT_FAILED:
		mgmt_connect_failed(size, data);
		break;
	case MGMT_EV_PIN_CODE_REQUEST:
		mgmt_pin_code_request(size, data);
		break;
	case MGMT_EV_USER_CONFIRM_REQUEST:
		mgmt_user_confirm_request(size, data);
		break;
	case MGMT_EV_USER_PASSKEY_REQUEST:
		mgmt_user_passkey_request(size, data);
		break;
	case MGMT_EV_AUTH_FAILED:
		mgmt_auth_failed(size, data);
		break;
	case MGMT_EV_DEVICE_FOUND:
		mgmt_device_found(size, data);
		break;
	case MGMT_EV_DISCOVERING:
		mgmt_discovering(size, data);
		break;
	case MGMT_EV_DEVICE_BLOCKED:
		mgmt_device_blocked(size, data);
		break;
	case MGMT_EV_DEVICE_UNBLOCKED:
		mgmt_device_unblocked(size, data);
		break;
	case MGMT_EV_DEVICE_UNPAIRED:
		mgmt_device_unpaired(size, data);
		break;
	case MGMT_EV_PASSKEY_NOTIFY:
		mgmt_passkey_notify(size, data);
		break;
	case MGMT_EV_NEW_IRK:
		mgmt_new_irk(size, data);
		break;
	case MGMT_EV_NEW_CSRK:
		mgmt_new_csrk(size, data);
		break;
	case MGMT_EV_DEVICE_ADDED:
		mgmt_device_added(size, data);
		break;
	case MGMT_EV_DEVICE_REMOVED:
		mgmt_device_removed(size, data);
		break;
	case MGMT_EV_NEW_CONN_PARAM:
		mgmt_new_conn_param(size, data);
		break;
	case MGMT_EV_UNCONF_INDEX_ADDED:
		mgmt_unconf_index_added(size, data);
		break;
	case MGMT_EV_UNCONF_INDEX_REMOVED:
		mgmt_unconf_index_removed(size, data);
		break;
	case MGMT_EV_NEW_CONFIG_OPTIONS:
		mgmt_new_config_options(size, data);
		break;
	case MGMT_EV_EXT_INDEX_ADDED:
		mgmt_ext_index_added(size, data);
		break;
	case MGMT_EV_EXT_INDEX_REMOVED:
		mgmt_ext_index_removed(size, data);
		break;
	case MGMT_EV_ADVERTISING_ADDED:
		mgmt_advertising_added(size, data);
		break;
	case MGMT_EV_ADVERTISING_REMOVED:
		mgmt_advertising_removed(size, data);
		break;
	default:
		printf("* Unknown control (code %d len %d)\n", opcode, size);
		packet_hexdump(data, size);
		break;
	}
}

static bool parse_drops(uint8_t **data, uint8_t *len, uint8_t *drops,
							uint32_t *total)
{
	if (*len < 1)
		return false;

	*drops = **data;
	*total += *drops;
	(*data)++;
	(*len)--;

	return true;
}

static bool tty_parse_header(uint8_t *hdr, uint8_t len, struct timeval **tv,
				struct timeval *ctv, uint32_t *drops)
{
	uint8_t cmd = 0;
	uint8_t evt = 0;
	uint8_t acl_tx = 0;
	uint8_t acl_rx = 0;
	uint8_t sco_tx = 0;
	uint8_t sco_rx = 0;
	uint8_t other = 0;
	uint32_t total = 0;
	uint32_t ts32;

	while (len) {
		uint8_t type = hdr[0];

		hdr++; len--;

		switch (type) {
		case TTY_EXTHDR_COMMAND_DROPS:
			if (!parse_drops(&hdr, &len, &cmd, &total))
				return false;
			break;
		case TTY_EXTHDR_EVENT_DROPS:
			if (!parse_drops(&hdr, &len, &evt, &total))
				return false;
			break;
		case TTY_EXTHDR_ACL_TX_DROPS:
			if (!parse_drops(&hdr, &len, &acl_tx, &total))
				return false;
			break;
		case TTY_EXTHDR_ACL_RX_DROPS:
			if (!parse_drops(&hdr, &len, &acl_rx, &total))
				return false;
			break;
		case TTY_EXTHDR_SCO_TX_DROPS:
			if (!parse_drops(&hdr, &len, &sco_tx, &total))
				return false;
			break;
		case TTY_EXTHDR_SCO_RX_DROPS:
			if (!parse_drops(&hdr, &len, &sco_rx, &total))
				return false;
			break;
		case TTY_EXTHDR_OTHER_DROPS:
			if (!parse_drops(&hdr, &len, &other, &total))
				return false;
			break;
		case TTY_EXTHDR_TS32:
			if (len < sizeof(ts32))
				return false;
			ts32 = get_le32(hdr);
			hdr += sizeof(ts32); len -= sizeof(ts32);
			/* ts32 is in units of 1/10th of a millisecond */
			ctv->tv_sec = ts32 / 10000;
			ctv->tv_usec = (ts32 % 10000) * 100;
			*tv = ctv;
			break;
		default:
			printf("Unknown extended header type %u\n", type);
			return false;
		}
	}

	if (total) {
		*drops += total;
		printf("* Drops: cmd %u evt %u acl_tx %u acl_rx %u sco_tx %u "
			"sco_rx %u other %u\n", cmd, evt, acl_tx, acl_rx,
			sco_tx, sco_rx, other);
	}

	return true;
}

static void process_data(struct control_data *data)
{
	while (data->offset >= sizeof(struct tty_hdr)) {
		struct tty_hdr *hdr = (struct tty_hdr *) data->buf;
		uint16_t pktlen, opcode, data_len;
		struct timeval *tv = NULL;
		struct timeval ctv;
		uint32_t drops = 0;

		data_len = le16_to_cpu(hdr->data_len);

		if (data_len + 2 > sizeof(data->buf)) {
			fprintf(stderr, "Received corrupted data from TTY\n");
			data->offset -= 2;
			memmove(data->buf, data->buf + 2, data->offset);
			continue;
		}

		if (data->offset < 2 + data_len)
			return;

		if (data->offset < sizeof(*hdr) + hdr->hdr_len) {
			fprintf(stderr, "Received corrupted data from TTY\n");
			goto _drop;
		}

		if (!tty_parse_header(hdr->ext_hdr, hdr->hdr_len,
							&tv, &ctv, &drops))
			fprintf(stderr, "Unable to parse extended header\n");

		opcode = le16_to_cpu(hdr->opcode);
		pktlen = data_len - 4 - hdr->hdr_len;

		btsnoop_write_hci(btsnoop_file, tv, 0, opcode, drops,
					hdr->ext_hdr + hdr->hdr_len, pktlen);
		packet_monitor(tv, NULL, 0, opcode,
					hdr->ext_hdr + hdr->hdr_len, pktlen);

_drop:
		data->offset -= 2 + data_len;

		if (data->offset > 0)
			memmove(data->buf, data->buf + 2 + data_len,
								data->offset);
	}
}

void control_disable_decoding(void)
{
	decode_control = false;
}

void control_filter_index(uint16_t index)
{
	filter_index = index;
}

void control_enable_slip(void)
{
	use_slip = true;
}

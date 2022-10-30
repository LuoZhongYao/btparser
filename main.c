#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <emscripten.h>
#include "pt-1.4/pt.h"
#include "parser/parser.h"

#define HCI_COMMAND_PKT     0x01
#define HCI_ACLDATA_PKT     0x02
#define HCI_SCODATA_PKT     0x03
#define HCI_EVENT_PKT       0x04
#define HCI_DIAG_PKT        0xf0
#define HCI_VENDOR_PKT      0xff

#define HCI_COMMAND_HDR_SIZE 3
#define HCI_EVENT_HDR_SIZE   2
#define HCI_ACL_HDR_SIZE     4
#define HCI_SCO_HDR_SIZE     3

#define HCI_MAX_ACL_SIZE    1024
#define HCI_MAX_SCO_SIZE    255
#define HCI_MAX_COMMAND_SIZE 260
#define HCI_MAX_EVENT_SIZE   260
#define HCI_MAX_FRAME_SIZE  (HCI_MAX_ACL_SIZE + 4)
static const uint64_t BTSNOOP_EPOCH_DELTA = 0x00dcddb30f2f8000ULL;
static bool use_h5 = false;
static bool h4_save = false;
//static bool use_h5_btsnoop = false;

static const struct h4_pkt_match {
    uint8_t type;
    uint8_t hlen;
    uint8_t loff;
    uint8_t lsize;
    uint16_t maxlen;
} h4_pkts [] = {
	{0, 0, 0, 0, 0 },   /* 0 */
	{
		.type = HCI_COMMAND_PKT,
		.hlen = HCI_COMMAND_HDR_SIZE,
		.loff = 2,
		.lsize = 1,
		.maxlen = HCI_MAX_COMMAND_SIZE,
	},   /* hci command */

	{
		.type = HCI_ACLDATA_PKT, 
		.hlen = HCI_ACL_HDR_SIZE, 
		.loff = 2, 
		.lsize = 2, 
		.maxlen = HCI_MAX_FRAME_SIZE 
	},  /* acl data*/

	{
		.type = HCI_SCODATA_PKT, 
		.hlen = HCI_SCO_HDR_SIZE, 
		.loff = 2, 
		.lsize = 1, 
		.maxlen = HCI_MAX_SCO_SIZE
	},  /* sco data */

	{
		.type = HCI_EVENT_PKT, 
		.hlen = HCI_EVENT_HDR_SIZE, 
		.loff = 1, 
		.lsize = 1, 
		.maxlen = HCI_MAX_EVENT_SIZE
	}  /* hci event */
};

struct context
{
	bool in;
	struct pt pt;
	unsigned flags;
	unsigned curn;
	unsigned readn;
	unsigned h5n;
	struct frame frm;
	unsigned char buf[65535];
	unsigned char h5b[65535];
};

#define READ_BYTE(h4, buf, length) \
    do {\
        PT_WAIT_UNTIL(&h4->pt, length > 0);\
        int total = (h4->curn + length < h4->readn) ? length : h4->readn - h4->curn;\
        memcpy(h4->buf + h4->curn, buf, total);\
        buf += total; \
        length -= total; \
        h4->curn += total;\
    } while(h4->curn < h4->readn)

static unsigned short h4_pkt_len(const unsigned char *pkt, const struct h4_pkt_match *match)
{
    switch(match->lsize) {
    case 0:
        return 0;
    break;
    
    case 1: {
        return pkt[match->loff + 1];
    } break;

    case 2: {
        return pkt[match->loff + 1] | pkt[match->loff + 2] << 8;
    } break;

    }
    return USHRT_MAX;
}


static PT_THREAD(h4_process(struct context *c, const void *buf, unsigned size))
{
	int rn = 0;
	unsigned dlen;

	PT_BEGIN(&c->pt);

	while (1) {
		c->readn = 1;
		c->curn = 0;
		READ_BYTE(c, buf, size);

		if (c->buf[0] > HCI_EVENT_PKT || c->buf[0] < HCI_COMMAND_PKT) {
			fprintf(stderr, "(%s) Invalid package type: %02x\n", c->in ? "RX" : "TX", c->buf[0]);
			continue;
		}

		if (c->buf[0] == HCI_EVENT_PKT)
			c->in = true;
		if (c->buf[0] == HCI_COMMAND_PKT)
			c->in = false;

		c->readn += h4_pkts[c->buf[0]].hlen;
		READ_BYTE(c, buf, size);
		dlen = h4_pkt_len(c->buf, h4_pkts + c->buf[0]);
		if (dlen > HCI_MAX_FRAME_SIZE) {
			fprintf(stderr, "(%s) Invalid packet\n", c->in ? "RX" : "TX");
			continue;
		}

		c->readn += dlen;
		READ_BYTE(c, buf, size);

		c->frm.in = c->in;
		c->frm.data_len = c->readn;
		c->frm.ptr = c->frm.data;
		c->frm.len = c->frm.data_len;
		hci_dump(0, &c->frm);
	}

	PT_END(&c->pt);
}
#undef READ_BYTE

#define H5_HDR_SEQ(hdr)		((hdr)[0] & 0x07)
#define H5_HDR_ACK(hdr)		(((hdr)[0] >> 3) & 0x07)
#define H5_HDR_CRC(hdr)		(((hdr)[0] >> 6) & 0x01)
#define H5_HDR_RELIABLE(hdr)	(((hdr)[0] >> 7) & 0x01)
#define H5_HDR_PKT_TYPE(hdr)	((hdr)[1] & 0x0f)
#define H5_HDR_LEN(hdr)		((((hdr)[1] >> 4) & 0x0f) + ((hdr)[2] << 4))

#define HCI_3WIRE_ACK_PKT   0
#define HCI_3WIRE_LINK_PKT 15

#define SLIP_DELIMITER	0xc0
#define SLIP_ESC	0xdb
#define SLIP_ESC_DELIM	0xdc
#define SLIP_ESC_ESC	0xdd

#define H5_RX_ESC		0x01
#define H5_TX_ACK_REQ	0x02
#define H5_LINK_FLAG(n)	(1 << (n - 1))

static inline int unslip_one_byte(struct context *c, uint8_t ch)
{
	uint8_t byte = ch;
	if (!(c->flags & H5_RX_ESC) && ch == SLIP_ESC) {
		c->flags |= H5_RX_ESC;
		return 0;
	}
	
	if (ch == SLIP_DELIMITER)
		goto _err;

	if (c->flags & H5_RX_ESC) {
		c->flags &= ~H5_RX_ESC;
		switch (ch) {
		case SLIP_ESC_DELIM:
			byte = SLIP_DELIMITER;
		break;

		case SLIP_ESC_ESC:
			byte = SLIP_ESC;
		break;

		default:
_err:
			fprintf(stderr, "(%s) unslip byte error: %02x\n", c->in ? "RX" : "TX", ch);
			return 1;
		break;
		}
	}
	c->buf[c->curn++] = byte;
	return 0;
}

static inline void hci_3wire_recv_frame(struct context *c)
{
	const uint8_t *data;
	switch (H5_HDR_PKT_TYPE(c->buf)) {
	case HCI_COMMAND_PKT: 
		c->in = false;
		goto frmdump;

	case HCI_EVENT_PKT:
		c->in = true;
		goto frmdump;

	case HCI_ACLDATA_PKT:
	case HCI_SCODATA_PKT:
frmdump:
		c->buf[3] = H5_HDR_PKT_TYPE(c->buf);

		c->frm.in = c->in;
		c->frm.data_len = c->readn - 3;
		c->frm.data = c->buf + 3;
		c->frm.ptr = c->frm.data;
		c->frm.len = c->frm.data_len;
		hci_dump(0, &c->frm);
		break;

	case HCI_3WIRE_ACK_PKT:
		printf("[%s] 3wire ack pkt\n", c->in ? "RX" : "TX");
		break;

	case HCI_3WIRE_LINK_PKT:
		data = c->buf + 4;
		if (data[0] == 0x01 && data[1] == 0x7e) { /* sync req */
			printf("[%s] 3wire sync req\n", c->in ? "RX" : "TX");
		} else if (data[0] == 0x02 && data[1] == 0x7d) {	/* sync rsp */
			printf("[%s] 3wire sync rsp\n", c->in ? "RX" : "TX");
		} else if (data[0] == 0x03 && data[1] == 0xfc) {	/* conf req */
			printf("[%s] 3wire conf req\n", c->in ? "RX" : "TX");
		} else if (data[0] == 0x04 && data[1] == 0x7b) {	/* conf rsp */
			printf("[%s] 3wire conf rsp\n", c->in ? "RX" : "TX");
		} else if (data[0] == 0x05 && data[1] == 0xfa) {	/* sleep req */
			printf("[%s] 3wire sleep req\n", c->in ? "RX" : "TX");
		} else if (data[0] == 0x06 && data[1] == 0xf9) {	/* woken req */
			printf("[%s] 3wire woken req\n", c->in ? "RX" : "TX");
		} else if (data[0] == 0x07 && data[1] == 0x78) {	/* wakeup req */
			printf("[%s] 3wire wakeup req\n", c->in ? "RX" : "TX");
		}
		break;
	}
}
#define unslip_one_byte(c, ch) ({int var = unslip_one_byte(c, ch); if(var) printf("(c = %d, r = %d)-----> %s:%d\n", c->curn, c-> readn, __func__, __LINE__); var; })

#define READ_BYTE(c, buf, length) \
		do { \
			while(c->curn < c->readn) { \
				uint8_t ch;\
				PT_WAIT_UNTIL(&c->pt, length > 0);\
				ch = *buf++; \
				length--;\
				c->h5b[c->h5n++] = ch;\
				if (unslip_one_byte(c, ch) == 1) \
					goto again; \
			}\
		} while(0)


static PT_THREAD(h5_process(struct context *c, const uint8_t *buf, unsigned size))
{
	uint8_t ch;
	PT_BEGIN(&c->pt);

	while (1) {
again:
		do {
			PT_WAIT_UNTIL(&c->pt,  size > 0);
			size--;
		} while (*buf++ != SLIP_DELIMITER);

		do {
			PT_WAIT_UNTIL(&c->pt, size > 0);
			size--;
		} while ((ch = *buf++) == SLIP_DELIMITER);

		c->flags &= ~H5_RX_ESC;

		c->readn = 4;
		c->curn = 0;
		c->h5n = 0;

		c->h5b[c->h5n++] = ch;
		if (unslip_one_byte(c, ch) == 1)
			goto again;

		READ_BYTE(c, buf, size);

		if (((c->buf[0] + c->buf[1] + c->buf[2] + c->buf[3]) & 0xff) != 0xff) {
			fprintf(stderr, "(%s) header crc error\n", c->in ? "RX" : "TX");
			goto again;
		}

		c->readn += H5_HDR_LEN(c->buf);
		READ_BYTE(c, buf, size);
		if (H5_HDR_CRC(c->buf)) {
			c->readn += 2;
			READ_BYTE(c, buf, size);
			c->readn -= 2;
		}

		hci_3wire_recv_frame(c);
	}

	PT_END(&c->pt);
}

static struct context *parse_new(bool in)
{
	struct context *c = calloc(sizeof(struct context), 1);
	c->in = in;
	c->frm.in = false;
	c->frm.data = c->buf;
	PT_INIT(&c->pt);

	return c;
}

EMSCRIPTEN_KEEPALIVE void hci_init_parser(unsigned long flags)
{
	init_parser(flags, ~0L, 0, 0, -1, -1);
}

EMSCRIPTEN_KEEPALIVE void hci_3wire_parse(const void *buf, size_t size, bool in)
{
	struct context *c = parse_new(in);
	h5_process(c, buf, size);
	free(c);
}

EMSCRIPTEN_KEEPALIVE void hci_4wire_parse(const void *buf, size_t size, bool in)
{
	struct context *c = parse_new(in);
	h4_process(c, buf, size);
	free(c);
}

EMSCRIPTEN_KEEPALIVE void del(void *ptr)
{
	free(ptr);
}

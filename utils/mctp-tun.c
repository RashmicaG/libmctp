/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <endian.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/uio.h>

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>

#include "container_of.h"
#include "libmctp.h"
#include "libmctp-astlpc.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "utils/mctp-capture.h"
#include "mctp.h"

#ifndef ETH_P_MCTP
#define ETH_P_MCTP     0x00fa
#endif

static const size_t MAX_MTU = 64 * 1024;


// todo: put in sep tun binding file
struct mctp_binding_raw {
       struct mctp_binding      binding;
       int tun_fd;
       void *tun_buf;
       size_t tun_buf_size;
};

struct mctp_nl {
	// socket for queries
	int	sd;
};
struct ctx {
       struct mctp *mctp;
       struct mctp_binding_astlpc *astlpc;
       struct mctp_binding_raw *tun;
       int tun_fd;
       void *tun_buf;
       size_t tun_buf_size;
	struct {
		struct capture ast_binding;
		struct capture raw_binding;
		struct capture socket;
	} pcap;
	struct mctp_nl			*nl;
	bool			verbose;
};

struct mctp_binding *mctp_binding_raw_core(struct mctp_binding_raw *b)
{
      return &b->binding;
}

#define binding_to_raw(b) \
        container_of(b, struct mctp_binding_raw, binding)

int mctp_raw_init_pollfd(struct mctp_binding_raw *b, struct pollfd *pollfd)
{
	pollfd->fd = b->tun_fd;
	pollfd->events = POLLIN;
}

static int mctp_binding_raw_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct mctp_binding_raw *binding = binding_to_raw(b);
	struct mctp *mctp = b->mctp;
	int wlen = 0;
	struct tun_pi tun_pi;
	struct iovec iov[2];
	
	tun_pi.flags = 0;
	tun_pi.proto = htobe16(ETH_P_MCTP);
	
	iov[0].iov_base = &tun_pi;
	iov[0].iov_len = sizeof(tun_pi);
	iov[1].iov_base = mctp_pktbuf_hdr(pkt);
	iov[1].iov_len = mctp_pktbuf_size(pkt);
	
	wlen = writev(binding->tun_fd, iov, 2);
	if (wlen != sizeof(tun_pi) + mctp_pktbuf_size(pkt)) {
		warnx("tun short write (wrote %zd, expected %zd)",
		      wlen, sizeof(tun_pi) + mctp_pktbuf_size(pkt));
		return -1;
	}
//	mctp_capture_socket(mctp, mctp_pktbuf_hdr(pkt), mctp_pktbuf_size(pkt));
//	if (mctp->capture)
//	if (ctx->pcap.socket.path)
//		mctp->capture(mctp->capture_data, mctp_pktbuf_hdr(pkt), mctp_pktbuf_size(pkt));
//		capture_socket(ctx->pcap.socket.dumper, ctx->tun->tun_buf, rlen);

	return 0;
}

static struct mctp_binding_raw *mctp_tun_init()
{
       struct mctp_binding_raw *tun;

       tun = __mctp_alloc(sizeof(*tun));
       memset(tun, 0, sizeof(*tun));
       tun->binding.name = "tun";
       tun->binding.pkt_size = MCTP_PACKET_SIZE(32*1024);
       tun->binding.version = 1;
       tun->binding.pkt_header = 4;
       tun->binding.pkt_trailer = 4;
       tun->binding.tx = mctp_binding_raw_tx;
       return tun;
}

static int tun_init(struct mctp_binding_raw *tun)
{
       struct ifreq ifreq;
       int fd, rc;

       fd = open("/dev/net/tun", O_RDWR);
       if (fd < 0) {
               warn("can't open tun device");
               return -1;
       }

       memset(&ifreq, 0, sizeof(ifreq));
       ifreq.ifr_flags = IFF_TUN;

       rc = ioctl(fd, TUNSETIFF, &ifreq);
       if (rc) {
               warn("ioctl(TUNSETIFF)");
               return -1;
       }

       printf("tun interface created: %s\n", ifreq.ifr_name);

       tun->tun_fd = fd;
       return 0;
}

int tun_read(struct ctx *ctx)
{
       struct tun_pi tun_pi;
       struct iovec iov[2];
       ssize_t rlen;
	struct mctp_binding_raw *tun;
	tun = ctx->tun;

       iov[0].iov_base = &tun_pi;
       iov[0].iov_len = sizeof(tun_pi);
       iov[1].iov_base = tun->tun_buf;
       iov[1].iov_len = tun->tun_buf_size;

       rlen = readv(tun->tun_fd, iov, 2);
       if (rlen < 0) {
               warn("tun read failed");
               return -1;
       }

       if (rlen < sizeof(tun_pi)) {
               warn("tun short read header (%zd bytes)", rlen);
               return -1;
       }

       if (tun_pi.proto != htobe16(ETH_P_MCTP))
               return 0;

       if (rlen < sizeof(tun_pi) + 4) {
               warn("tun short read (%zd bytes)", rlen);
               return -1;
       }

	rlen -= sizeof(tun_pi);
	struct mctp_pktbuf *pkt;

	pkt = mctp_pktbuf_alloc(&tun->binding, rlen);
	if (!pkt) {
               warn("couldn't allocate packet of size (%zd bytes)", rlen);
               return -1;
	}
	memcpy(mctp_pktbuf_hdr(pkt), tun->tun_buf, rlen);
	mctp_bus_rx(&tun->binding, pkt);

// possibly the correct / better way to do this
//	pkt = mctp_pktbuf_alloc(&tun->binding, 0);
//	mctp_pktbuf_push(pkt, tun->tun_buf, rlen);

	if (ctx->pcap.socket.path)
		capture_socket(ctx->pcap.socket.dumper, ctx->tun->tun_buf, rlen);
       return 0;
}


//daemon stuff below

static const struct option options[] = {
	{ "capture-astlpc-binding", required_argument, 0, 'b' },
	{ "capture-raw-binding", required_argument, 0, 'r' },
	{ "capture-socket", required_argument, 0, 's' },
	//{ "verbose", no_argument, 0, 'v' },
	{ 0 },
};

static void usage(const char *progname)
{
	unsigned int i;

	fprintf(stderr, "usage: %s [params]\n", progname);
}

//
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <linux/if_link.h> 
//#include <linux/if.h> 
//#include <linux/netlink.h>
//#include <net/if.h>
void mctp_nl_close(struct mctp_nl *nl)
{
	close(nl->sd);
	free(nl);
}


static int open_nl_socket(void)
{
	struct sockaddr_nl addr;
	int opt, rc, sd = -1;

	rc = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rc < 0)
		goto err;
	sd = rc;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	rc = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc)
		goto err;

	opt = 1;
	rc = setsockopt(sd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
			&opt, sizeof(opt));
	if (rc) {
		rc = -errno;
		goto err;
	}

	opt = 1;
	rc = setsockopt(sd, SOL_NETLINK, NETLINK_EXT_ACK, &opt, sizeof(opt));
	if (rc)
	{
		rc = -errno;
		goto err;
	}
	return sd;
err:
	if (sd >= 0) {
		close(sd);
	}
	return rc;
}

struct mctp_nl * mctp_nl_new(bool verbose)
{
	int rc;
	struct mctp_nl *nl;

	nl = calloc(1, sizeof(*nl));
	if (!nl) {
		warn("calloc failed");
		return NULL;
	}

	nl->sd = -1;

	nl->sd = open_nl_socket();
	if (nl->sd < 0)
		goto err;

	return nl;
err:
	mctp_nl_close(nl);
	return NULL;
}
/* Returns the space used */
size_t mctp_put_rtnlmsg_attr(struct rtattr **prta, size_t *rta_len,
	unsigned short type, const void* value, size_t val_len)
{
	struct rtattr *rta = *prta;
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(val_len);
	memcpy(RTA_DATA(rta), value, val_len);
	*prta = RTA_NEXT(*prta, *rta_len);
	return RTA_SPACE(val_len);
}
int mctp_nl_send(struct mctp_nl *nl, struct nlmsghdr *msg)
{
	struct sockaddr_nl addr;
	int rc;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;

	rc = sendto(nl->sd, msg, msg->nlmsg_len, 0,
			(struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0)
		return rc;

	if (rc != (int)msg->nlmsg_len)
		warnx("sendto: short send (%d, expected %d)",
				rc, msg->nlmsg_len);

	if (msg->nlmsg_flags & NLM_F_ACK) {
		warnx("MSG ACK SET\n");
	}
	return 0;
}

int mctp_nl_ifindex_byname(const struct mctp_nl *nl, const char *ifname)
{
	struct ifreq ifr;
	size_t ifname_len=strlen(ifname);
	memcpy(ifr.ifr_name, ifname, ifname_len);
    	ifr.ifr_name[ifname_len] = 0;
	//int fd = socket(AF_UNIX,SOCK_DGRAM,0);
	//if (fd == -1) {
    	//	warn("socket failed %s",strerror(errno));
	//	return -1;
	//}
	if (ioctl(nl->sd ,SIOCGIFINDEX, &ifr) == -1) {
    		warn("ioctl failed %s",strerror(errno));
		return -1;
	}
	return ifr.ifr_ifindex;
}


static int do_link_set(struct ctx *ctx, int ifindex, bool have_updown, bool up,
		uint32_t mtu, bool have_net, uint32_t net) {
	struct {
		struct nlmsghdr		nh;
		struct ifinfomsg	ifmsg;
		/* Space for all attributes */
		uint8_t			rta_buff[200];
	} msg = {0};
	struct rtattr *rta;
	size_t rta_len;

	msg.nh.nlmsg_type = RTM_NEWLINK;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	msg.ifmsg.ifi_index = ifindex;

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));
	rta_len = sizeof(msg.rta_buff);
	rta = (void*)msg.rta_buff;

	if (have_updown) {
		msg.ifmsg.ifi_change |= IFF_UP;
		if (up)
			msg.ifmsg.ifi_flags |= IFF_UP;
	}

	if (mtu)
		msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len,
			IFLA_MTU, &mtu, sizeof(mtu));

	if (have_net) {
		/* Nested
		IFLA_AF_SPEC
			AF_MCTP
				IFLA_MCTP_NET
				... future device properties
		*/
		struct rtattr *rta1, *rta2;
		size_t rta_len1, rta_len2, space1, space2;
		uint8_t buff1[100], buff2[100];

		rta2 = (void*)buff2;
		rta_len2 = sizeof(buff2);
		space2 = 0;
		if (have_net)
			space2 += mctp_put_rtnlmsg_attr(&rta2, &rta_len2,
				IFLA_MCTP_NET, &net, sizeof(net));
		rta1 = (void*)buff1;
		rta_len1 = sizeof(buff1);
		space1 = mctp_put_rtnlmsg_attr(&rta1, &rta_len1,
			AF_MCTP|NLA_F_NESTED, buff2, space2);
		msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len,
			IFLA_AF_SPEC|NLA_F_NESTED, buff1, space1);
	}

	return mctp_nl_send(ctx->nl, &msg.nh);
}


//
int main(int argc, char * const *argv)
{
        struct ctx _ctx, *ctx;
        int rc;

	ctx = &_ctx;

        ctx->mctp = mctp_init();
	ctx->pcap.raw_binding.path = NULL;
	ctx->pcap.ast_binding.path = NULL;
	ctx->pcap.socket.path = NULL;

	for (;;) {
		rc = getopt_long(argc, argv, "b:es::v", options, NULL);
		if (rc == -1)
			break;
		switch (rc) {
		case 'b':
			ctx->pcap.ast_binding.path = optarg;
			break;
		case 'r':
			ctx->pcap.raw_binding.path = optarg;
			break;
		case 's':
			ctx->pcap.socket.path = optarg;
			break;
		case 'v':
			ctx->verbose = true;
			break;
		default:
			fprintf(stderr, "Invalid argument\n");
			return EXIT_FAILURE;
		}
	}
	if (ctx->pcap.ast_binding.path || ctx->pcap.raw_binding.path  || ctx->pcap.socket.path) {
		if (capture_init()) {
			rc = EXIT_FAILURE;
			goto cleanup_mctp;
		}
	}
	/* Set max message size to something more reasonable than 64k */
	mctp_set_max_message_size(ctx->mctp, 32768*10);

	/* Setup netlink */
	ctx->nl = mctp_nl_new(ctx->verbose);

       /* Setup astlpc binding */
       ctx->astlpc = mctp_astlpc_init_fileio();
       if (!ctx->astlpc)
               errx(EXIT_FAILURE, "can't init astlpc hardware transport");

       /* Setup raw binding */
       ctx->tun = mctp_tun_init();
       rc = tun_init(ctx->tun);
       if (rc)
               errx(EXIT_FAILURE, "can't init tun device");

       ctx->tun->tun_buf_size = MAX_MTU;
       ctx->tun->tun_buf = malloc(ctx->tun->tun_buf_size);
       if (!ctx->tun->tun_buf)
               errx(EXIT_FAILURE, "malloc");

       /* Connect the two bindings */
       rc = mctp_bridge_busses(ctx->mctp, mctp_binding_astlpc_core(ctx->astlpc), mctp_binding_raw_core(ctx->tun));
       if (rc)
               errx(EXIT_FAILURE, "can't connect lpc and tun bindings");

	/* Enable bindings */
        mctp_binding_set_tx_enabled(mctp_binding_astlpc_core(ctx->astlpc), true);
        mctp_binding_set_tx_enabled(mctp_binding_raw_core(ctx->tun), true);

	/* Init capture bindings  */
	if (ctx->pcap.ast_binding.path) {
		rc = capture_prepare(&ctx->pcap.ast_binding);
		if (rc == -1) {
			fprintf(stderr, "Failed to initialise capture for ast binding: %d\n", rc);
			rc = EXIT_FAILURE;
			goto cleanup_mctp;
		}

		mctp_set_capture_handler(mctp_binding_astlpc_core(ctx->astlpc), capture_binding,
					 ctx->pcap.ast_binding.dumper);
	}
	if (ctx->pcap.raw_binding.path) {
		rc = capture_prepare(&ctx->pcap.raw_binding);
		if (rc == -1) {
			fprintf(stderr, "Failed to initialise capture for raw binding: %d\n", rc);
			rc = EXIT_FAILURE;
			goto cleanup_mctp;
		}

		mctp_set_capture_handler(mctp_binding_raw_core(ctx->tun), capture_binding,
					 ctx->pcap.raw_binding.dumper);
	}

	if (ctx->pcap.socket.path) {
		rc = capture_prepare(&ctx->pcap.socket);
		if (rc == -1) {
			fprintf(stderr, "Failed to initialise capture: %d\n", rc);
			rc = EXIT_FAILURE;
			goto cleanup_pcap_binding;
		}
//		mctp_set_capture_handler(ctx->mctp, capture_socket,
//					 ctx->pcap.binding.socket.dumper);
	}
	
	/* Get ifindex for tun0 */
	int ifindex = mctp_nl_ifindex_byname(ctx->nl, "tun0");

	struct pollfd pollfds[2];
	uint32_t current_mtu = MCTP_PACKET_SIZE(mctp_binding_astlpc_core(ctx->astlpc)->pkt_size);
	uint32_t new_mtu = 0;
	for (;;) {
		// should these be inside or outside the for loop?
		mctp_raw_init_pollfd(ctx->tun, &pollfds[0]);
		mctp_astlpc_init_pollfd(ctx->astlpc, &pollfds[1]);
	//	pollfds[1].fd = mctp_astlpc_get_fd(ctx->astlpc);
	//	pollfds[1].events = POLLIN | POLLOUT;


               rc = poll(pollfds, 2, -1);
               if (rc < 0)
                       err(EXIT_FAILURE, "poll");

               if (!rc)
                       continue;

               if (pollfds[0].revents) {
                       rc = tun_read(ctx);
                       if (rc)
			fprintf(stderr, "tun_read failed \n");
                       if (rc)
                               break;
               }

               if (pollfds[1].revents) {
                       rc = mctp_astlpc_poll(ctx->astlpc);
                       if (rc)
			fprintf(stderr, "mctp_astlpc_poll failed \n");
                       if (rc)
                               break;
               }
		//If MTU has changed, update kernel MTU
		//astlpc->resquested_mtu
		new_mtu = MCTP_PACKET_SIZE(mctp_binding_astlpc_core(ctx->astlpc)->pkt_size);
		if (new_mtu != current_mtu)
		{
			fprintf(stderr, "MTU change request from %d to %d\n", current_mtu, new_mtu);
			fprintf(stderr, "reqeusted MTU %d, sizeof mctp_hdr %d\n", mctp_binding_astlpc_core(ctx->astlpc)->mtu, sizeof(struct mctp_hdr));
			// somehow ->mtu and MCTP_PACKET_SIZE(->pkt_size are 8 diff but sizeof struct mctp_hdr is 4)
			do_link_set(ctx, ifindex, true, true, new_mtu, false, 0);
			current_mtu = new_mtu;
		}
//sz = astlpc->proto->packet_size(MCTP_PACKET_SIZE(mtu));
//astlpc->binding.pkt_size = MCTP_PACKET_SIZE(mtu);
//max_payload_len = MCTP_BODY_SIZE(bus->binding->pkt_size);
       }
	
	fprintf(stderr, "Shouldn't get here. rc: %d\n", rc);

cleanup_pcap_socket:
	if (ctx->pcap.socket.path)
		capture_close(&ctx->pcap.socket);

cleanup_pcap_binding:
	if (ctx->pcap.ast_binding.path)
		capture_close(&ctx->pcap.ast_binding);
	if (ctx->pcap.raw_binding.path)
		capture_close(&ctx->pcap.raw_binding);
cleanup_bindings:
	mctp_astlpc_destroy(ctx->astlpc);
	//todo write raw destroy

	rc = rc ? EXIT_FAILURE : EXIT_SUCCESS;
cleanup_mctp:

	return rc;
}


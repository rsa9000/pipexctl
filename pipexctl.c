/**
 * Standalone pipex(4) control utility
 *
 * Copyright (c) 2016 Sergey Ryazanov <ryazanov.s.a@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <net/if.h>
#include <net/pipex.h>

static int parse_addrport(const char *str, struct sockaddr_storage *ss)
{
	char buf[20], *p, *endp;
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	unsigned long lval;

	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;

	p = strchr(str, ':');
	if (!p || p == str || p - str > sizeof(buf))
		return 0;

	strncpy(buf, str, p - str);
	buf[p - str] = '\0';

	if (inet_aton(buf, &sin->sin_addr) != 1)
		return 0;

	errno = 0;
	lval = strtoul(p + 1, &endp, 10);
	if (lval > 0xffff || *endp != '\0' || errno)
		return 0;
	sin->sin_port = lval;

	return 1;
}

static int cmd_getmode(int fd, int argc, char *argv[])
{
	int val;

	if (ioctl(fd, PIPEXGMODE, &val) < 0) {
		fprintf(stderr, "ioctl(PIPEXGMODE): %s\n", strerror(errno));
		return -1;
	}

	printf("pipex: %s\n", val ? "on" : "off");

	return 0;
}

static int cmd_setmode(int fd, int argc, char *argv[])
{
	int val;

	if (argc < 1) {
		fprintf(stderr, "No mode specified\n");
		return -1;
	}

	if (strcasecmp(argv[0], "on") == 0 ||
	    strncasecmp(argv[0], "en", 2) == 0 ||
	    strcmp(argv[0], "1") == 0 ||
	    strcasecmp(argv[0], "true") == 0) {
		val = 1;
	} else if (strcasecmp(argv[0], "off") == 0 ||
		   strncasecmp(argv[0], "dis", 3) == 0 ||
		   strcmp(argv[0], "0") == 0 ||
		   strcasecmp(argv[0], "false") == 0) {
		val = 0;
	} else {
		fprintf(stderr, "Unknown mode -- %s\n", argv[0]);
		return -1;
	}

	if (ioctl(fd, PIPEXSMODE, &val) < 0) {
		fprintf(stderr, "ioctl(PIPEXSMODE): %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int cmd_addsess(int fd, int argc, char *argv[])
{
	struct pipex_session_req req;
	unsigned long lval;
	char *endp;

	memset(&req, 0x00, sizeof(req));

	if (argc < 1) {
		fprintf(stderr, "Tunnel protocol not specified\n");
		return -1;
	}

	if (strcasecmp(argv[0], "l2tp") == 0) {
		req.pr_protocol = PIPEX_PROTO_L2TP;
	} else if (strcasecmp(argv[0], "pptp") == 0) {
		fprintf(stderr, "PPTP is not supported now, sorry\n");
		return -1;
	} else if (strcasecmp(argv[0], "pppoe") == 0) {
		fprintf(stderr, "PPPoE is not supported now, sorry\n");
		return -1;
	} else {
		fprintf(stderr, "Unknown tunnel protocol (expect l2tp, pptp or pppoe) -- %s\n",
			argv[0]);
		return -1;
	}

	errno = 0;

	if (argc < 2) {
		fprintf(stderr, "Session-Id is not specified\n");
		return -1;
	}
	lval = strtoul(argv[1], &endp, 0);
	if (lval > 0xffff || *endp != '\0' || errno) {
		fprintf(stderr, "Invalid Session-Id value -- %s\n", argv[1]);
		return -1;
	}
	req.pr_session_id = lval;

	if (argc < 3) {
		fprintf(stderr, "Peer Session-Id is not specified\n");
		return -1;
	}
	lval = strtoul(argv[2], &endp, 0);
	if (lval > 0xffff || *endp != '\0' || errno) {
		fprintf(stderr, "Invalid peer Session-Id value -- %s\n", argv[2]);
		return -1;
	}
	req.pr_peer_session_id = lval;

	req.pr_ppp_flags |= PIPEX_PPP_PFC_ACCEPTED;
	req.pr_ppp_flags |= PIPEX_PPP_HAS_ACF;

	if (argc < 4) {
		fprintf(stderr, "Src address is not specified\n");
		return -1;
	} else if (inet_aton(argv[3], &req.pr_ip_srcaddr) != 1) {
		fprintf(stderr, "Invalid src address -- %s\n", argv[3]);
		return -1;
	}

	if (argc < 5) {
		fprintf(stderr, "Framed address is not specified\n");
		return -1;
	} else if (inet_aton(argv[4], &req.pr_ip_address) != 1) {
		fprintf(stderr, "Invalid framed address -- %s\n", argv[4]);
		return -1;
	}

	if (argc < 6) {
		fprintf(stderr, "Framed netmask is not specified\n");
		return -1;
	} else if (inet_aton(argv[5], &req.pr_ip_netmask) != 1) {
		fprintf(stderr, "Invalid framed netmask -- %s\n", argv[5]);
		return -1;
	}

	if (argc < 7) {
		fprintf(stderr, "Local address is not specified\n");
		return -1;
	} else if (parse_addrport(argv[6], &req.pr_local_address) != 1) {
		fprintf(stderr, "Invalid local address -- %s\n", argv[6]);
		return -1;
	}

	if (argc < 8) {
		fprintf(stderr, "Peer address is not specified\n");
		return -1;
	} else if (parse_addrport(argv[7], &req.pr_peer_address) != 1) {
		fprintf(stderr, "Invalid peer address -- %s\n", argv[7]);
		return -1;
	}

	if (req.pr_protocol == PIPEX_PROTO_L2TP) {
		if (argc < 9) {
			fprintf(stderr, "L2TP Tunnel-Id is not specified\n");
			return -1;
		}
		lval = strtoul(argv[8], &endp, 0);
		if (lval > 0xffff || *endp != '\0' || errno) {
			fprintf(stderr, "Invalid L2TP Tunnel-Id -- %s\n", argv[8]);
			return -1;
		}
		req.pr_proto.l2tp.tunnel_id = lval;

		if (argc < 10) {
			fprintf(stderr, "L2TP peer Tunnel-Id is not specified\n");
			return -1;
		}
		lval = strtoul(argv[9], &endp, 0);
		if (lval > 0xffff || *endp != '\0' || errno) {
			fprintf(stderr, "Invalid L2TP peer Tunnel-Id -- %s\n", argv[9]);
			return -1;
		}
		req.pr_proto.l2tp.peer_tunnel_id = lval;
	}

	if (ioctl(fd, PIPEXASESSION, &req) < 0) {
		fprintf(stderr, "ioctl(PIPEXASESSION): %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int cmd_delsess(int fd, int argc, char *argv[])
{
	struct pipex_session_stat_req req;
	unsigned long lval;
	char *endp;

	memset(&req, 0x00, sizeof(req));

	if (argc < 1) {
		fprintf(stderr, "Tunnel protocol not specified\n");
		return -1;
	}

	if (strcasecmp(argv[0], "l2tp") == 0) {
		req.psr_protocol = PIPEX_PROTO_L2TP;
	} else if (strcasecmp(argv[0], "pptp") == 0) {
		req.psr_protocol = PIPEX_PROTO_PPTP;
	} else if (strcasecmp(argv[0], "pppoe") == 0) {
		req.psr_protocol = PIPEX_PROTO_PPPOE;
	} else {
		fprintf(stderr, "Unknown tunnel protocol (expect l2tp, pptp or pppoe) -- %s\n",
			argv[0]);
		return -1;
	}

	errno = 0;

	if (argc < 2) {
		fprintf(stderr, "Session-Id is not specified\n");
		return -1;
	}
	lval = strtoul(argv[1], &endp, 0);
	if (lval > 0xffff || *endp != '\0' || errno) {
		fprintf(stderr, "Invalid Session-Id value -- %s\n", argv[1]);
		return -1;
	}
	req.psr_session_id = lval;

	if (ioctl(fd, PIPEXDSESSION, &req) < 0) {
		fprintf(stderr, "ioctl(PIPEXDSESSION): %s\n", strerror(errno));
		return -1;
	}

	printf("ipackets: %"PRIu32"\n", req.psr_stat.ipackets);
	printf("ierrros : %"PRIu32"\n", req.psr_stat.ierrors);
	printf("ibytes  : %"PRIu64"\n", req.psr_stat.ibytes);
	printf("opackets: %"PRIu32"\n", req.psr_stat.opackets);
	printf("oerrros : %"PRIu32"\n", req.psr_stat.oerrors);
	printf("obytes  : %"PRIu64"\n", req.psr_stat.obytes);
	printf("idletime: %"PRIu32" s\n", req.psr_stat.idle_time);

	return 0;
}

static int cmd_getstat(int fd, int argc, char *argv[])
{
	struct pipex_session_stat_req req;
	unsigned long lval;
	char *endp;

	memset(&req, 0x00, sizeof(req));

	if (argc < 1) {
		fprintf(stderr, "Tunnel protocol not specified\n");
		return -1;
	}

	if (strcasecmp(argv[0], "l2tp") == 0) {
		req.psr_protocol = PIPEX_PROTO_L2TP;
	} else if (strcasecmp(argv[0], "pptp") == 0) {
		req.psr_protocol = PIPEX_PROTO_PPTP;
	} else if (strcasecmp(argv[0], "pppoe") == 0) {
		req.psr_protocol = PIPEX_PROTO_PPPOE;
	} else {
		fprintf(stderr, "Unknown tunnel protocol (expect l2tp, pptp or pppoe) -- %s\n",
			argv[0]);
		return -1;
	}

	errno = 0;

	if (argc < 2) {
		fprintf(stderr, "Session-Id is not specified\n");
		return -1;
	}
	lval = strtoul(argv[1], &endp, 0);
	if (lval > 0xffff || *endp != '\0' || errno) {
		fprintf(stderr, "Invalid Session-Id value -- %s\n", argv[1]);
		return -1;
	}
	req.psr_session_id = lval;

	if (ioctl(fd, PIPEXGSTAT, &req) < 0) {
		fprintf(stderr, "ioctl(PIPEXGSTAT): %s\n", strerror(errno));
		return -1;
	}

	printf("ipackets: %"PRIu32"\n", req.psr_stat.ipackets);
	printf("ierrros : %"PRIu32"\n", req.psr_stat.ierrors);
	printf("ibytes  : %"PRIu64"\n", req.psr_stat.ibytes);
	printf("opackets: %"PRIu32"\n", req.psr_stat.opackets);
	printf("oerrros : %"PRIu32"\n", req.psr_stat.oerrors);
	printf("obytes  : %"PRIu64"\n", req.psr_stat.obytes);
	printf("idletime: %"PRIu32" s\n", req.psr_stat.idle_time);

	return 0;
}

int main(int argc, char *argv[])
{
	int fd, err;

	if (argc < 3) {
		printf(
			"Usage:\n"
			"  pipexctl <dev> <cmd> [<cmd options>]\n"
			"\n"
			"Where:\n"
			"  <dev> is the device associated with target interface,\n"
			"  e.g. /dev/tun0 for tun0, /dev/ttyp0 for ppp0, etc.\n"
			"  <cmd> is the command, which should be executed with\n"
			"  appropriate options (see below)\n"
			"\n"
			"Commands:\n"
			"  getmode\n"
			"  setmode {on | off}\n"
			"  addsess {l2tp | pptp | pppoe} <sess-id> <peer-sess-id> <src-addr> <framed-addr> <framed-netmask> <local-addr> <peer-addr>\n"
			"      l2tp specific options: <tun-id> <peer-tun-id>\n"
			"  delsess {l2tp | pptp | pppoe} <sess-id>\n"
			"  getstat {l2tp | pptp | pppoe} <sess-id>\n"
			"\n"
			"See pipex(4) to get detailed description of commands and options.\n"
			"\n"
		);

		return EXIT_SUCCESS;
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", argv[1], strerror(errno));
		return EXIT_FAILURE;
	}

	argc -= 3;
	argv += 3;

	if (strcmp(argv[-1], "getmode") == 0) {
		err = cmd_getmode(fd, argc, argv);
	} else if (strcmp(argv[-1], "setmode") == 0) {
		err = cmd_setmode(fd, argc, argv);
	} else if (strcmp(argv[-1], "addsess") == 0) {
		err = cmd_addsess(fd, argc, argv);
	} else if (strcmp(argv[-1], "delsess") == 0) {
		err = cmd_delsess(fd, argc, argv);
	} else if (strcmp(argv[-1], "getstat") == 0) {
		err = cmd_getstat(fd, argc, argv);
	} else {
		fprintf(stderr, "unknown command -- %s\n", argv[-1]);
		err = -1;
	}

	close(fd);

	return err == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

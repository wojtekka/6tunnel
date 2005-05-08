/*
 * 6tunnel v0.10-rc1
 * (C) Copyright 2000-2002 by Wojtek Kaniewski <wojtekka@bydg.pdi.net>
 *
 * Modified by:
 *   Tomek Lipski <lemur@irc.pl>, thx to KeFiR@IRCnet
 *   Dariusz Jackowski <ascent@linux.pl>
 *   awayzzz <awayzzz@digibel.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <pwd.h>
#include <time.h>

#define debug(x...) \
{ \
	if (verbose) \
		printf(x); \
}

struct ip_map {
	char *ipv4_addr;
	char *ipv6_addr;
	struct ip_map *next;
};

struct ip_map *maps = NULL;
int maps_count = 0, verbose = 0, conn_count = 0;
int remote_port, verbose, hint = AF_INET6, hexdump = 0;
char *remote_host, *source_host = NULL, *ircpass = NULL;
char *ircsendpass = NULL, remote[128];

char *xmalloc(int size)
{
	char *tmp;

	if (!(tmp = malloc(size))) {
		perror("malloc");
		exit(1);
	}

	return tmp;
}

char *xrealloc(char *ptr, int size)
{
	char *tmp;

	if (!(tmp = realloc(ptr, size))) {
		perror("realloc");
		exit(1);
	}

	return tmp;
}

char *xstrdup(const char *str)
{
	char *tmp;

	if (!(tmp = strdup(str))) {
		perror("strdup");
		exit(1);
	}

	return tmp;
}

struct sockaddr *resolve_host(const char *name, int hint)
{
	struct addrinfo *ai = NULL, hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = hint;

	if (!getaddrinfo(name, NULL, &hints, &ai) && ai) {
		char *tmp;

		tmp = xmalloc(ai->ai_addrlen);
		memcpy(tmp, ai->ai_addr, ai->ai_addrlen);

		freeaddrinfo(ai);

		return (struct sockaddr*) tmp;
	}

	return NULL;
}

void print_hexdump(const char *buf, int len)
{
	int i, j;
  
	for (i = 0; i < ((len / 16) + ((len % 16) ? 1 : 0)); i++) {
		printf("%.4x: ", i * 16);

		for (j = 0; j < 16; j++) {
			if (i * 16 + j < len)
				printf("%.2x ", buf[i*16+j]);
			else
				printf("   ");
			if (j == 7)
				printf(" ");
		}
		
		printf(" ");
		
		for (j = 0; j < 16; j++) {
			if (i * 16 + j < len) {
				char ch = buf[i * 16 + j];

				printf("%c", (isprint(ch)) ? ch : '.');
			}
		}

		printf("\n");
	}
}

void make_tunnel(int rsock)
{
	char buf[4096], *outbuf = NULL, *inbuf = NULL;
	int sock = -1, outlen = 0, inlen = 0;
	struct sockaddr *sa = NULL;

	if (ircpass) {
		int i, ret;

		for (i = 0; i < sizeof(buf) - 1; i++) {
			if ((ret = read(rsock, buf + i, 1)) < 1)
				goto cleanup;
			if (buf[i] == '\n')
				break;
		}

		buf[i] = 0;
		
		if (i > 0 && buf[i - 1] == '\r')
			buf[i - 1] = 0;

		if (i == 4095 || strncasecmp(buf, "PASS ", 5)) {
			char *tmp;

			debug("<%d> irc proxy auth failed - junk\n", rsock);

			tmp = "ERROR :Closing link: Make your client send password first\r\n";
			write(rsock, tmp, strlen(tmp));
			
			goto cleanup;
		}

		if (strcmp(buf + 5, ircpass)) {
			char *tmp;

			debug("<%d> irc proxy auth failed - password incorrect\n", rsock);
			tmp = ":6tunnel 464 * :Password incorrect\r\nERROR :Closing link: Password incorrect\r\n";
			write(rsock, tmp, strlen(tmp));
			
			goto cleanup;
		}
		
		debug("<%d> irc proxy auth succeded\n", rsock);
	}
  
	if (!(sa = resolve_host(remote_host, hint))) {
		debug("<%d> unable to resolve %s\n", rsock, remote_host);
		goto cleanup;
	}

	sock = socket(sa->sa_family, SOCK_STREAM, 0);

	free(sa);
	sa = NULL;

	if (source_host) {
		if (!(sa = resolve_host(source_host, hint))) {
			debug("<%d> unable to resolve source host (%s)\n", rsock, source_host);
			goto cleanup;
		}

		if (bind(sock, sa, (hint == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) {
			debug("<%d> unable to bind to source host (%s)\n", rsock, source_host);
			goto cleanup;
		}

		free(sa);
		sa = NULL;
	}

	sa = resolve_host(remote_host, hint);

	((struct sockaddr_in*) sa)->sin_port = htons(remote_port);

	if (connect(sock, sa, (sa->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) {
		debug("<%d> connection refused (%s,%d)\n", rsock, remote_host, remote_port);
		goto cleanup;
	}

	free(sa);
	sa = NULL;

	debug("<%d> connected to %s,%d\n", rsock, remote_host, remote_port);

	if (ircsendpass) {
		snprintf(buf, 4096, "PASS %s\r\n", ircsendpass);
		write(sock, buf, strlen(buf));
	}

	for (;;) {
		fd_set rds, wds;
		int ret, sent;

		FD_ZERO(&rds);
		FD_SET(sock, &rds);
		FD_SET(rsock, &rds);

		FD_ZERO(&wds);
		if (outbuf && outlen)
			FD_SET(rsock, &wds);
		if (inbuf && inlen)
			FD_SET(sock, &wds);
    
		ret = select((sock > rsock) ? (sock + 1) : (rsock + 1), &rds, &wds, NULL, NULL);

		if (FD_ISSET(rsock, &wds)) {
			sent = write(rsock, outbuf, outlen);

			if (sent < 1)
				goto cleanup;

			if (sent == outlen) {
				free(outbuf);
				outbuf = NULL;
				outlen = 0;
			} else {
				memmove(outbuf, outbuf + sent, outlen - sent);
				outlen -= sent;
			}
		}

		if (FD_ISSET(sock, &wds)) {
			sent = write(sock, inbuf, inlen);

			if (sent < 1)
				goto cleanup;

			if (sent == inlen) {
				free(inbuf);
				inbuf = NULL;
				inlen = 0;
			} else {
				memmove(inbuf, inbuf + sent, inlen - sent);
				inlen -= sent;
			}
		}

		if (FD_ISSET(sock, &rds)) {
			if ((ret = read(sock, buf, 4096)) < 1)
				goto cleanup;

			if (hexdump) {
				printf("<%d> recvfrom %s,%d\n", rsock, remote_host, remote_port);
				print_hexdump(buf, ret);
			}
			
			sent = write(rsock, buf, ret);

			if (sent < 1)
				goto cleanup;
			
			if (sent < ret) {
				outbuf = xrealloc(outbuf, outlen + ret - sent);
				memcpy(outbuf + outlen, buf + sent, ret - sent);
				outlen = ret - sent;
			}
		}

		if (FD_ISSET(rsock, &rds)) {
			if ((ret = read(rsock, buf, 4096)) < 1)
				goto cleanup;

			if (hexdump) {
				printf("<%d> sendto %s,%d\n", rsock, remote_host, remote_port);
				print_hexdump(buf, ret);
			}

			sent = write(sock, buf, ret);

			if (sent < 1)
				goto cleanup;

			if (sent < ret) {
				inbuf = xrealloc(inbuf, inlen + ret - sent);
				memcpy(inbuf + inlen, buf + sent, ret - sent);
				inlen = ret - sent;
			}
		}
	}


cleanup:
	if (sa)
		free(sa);

	if (sock != -1) {
		shutdown(sock, 2);
		close(sock);
	}
	
	shutdown(rsock, 2);
	close(rsock);
}

void usage(const char *arg0)
{
	fprintf(stderr,
			
"usage: %s [-146dqvh] [-s sourcehost] [-l localhost] [-i pass]\n"
"           [-I pass] [-m mapfile] [-L limit] [-A filename]\n"
"           localport remotehost [remoteport]\n"
"\n"	   
"  -1  allow only one connection and quit\n"
"  -4  preffer IPv4 endpoints\n"
"  -6  bind to IPv6 address\n"
"  -v  be verbose\n"
"  -d  don't detach\n"
"  -f  force tunneling (even if remotehost isn't resolvable)\n"
"  -s  connect using specified address\n"
"  -l  bind to specified address\n"
"  -i  act like irc proxy and ask for password\n"
"  -I  send specified password to the irc server\n"
"  -h  print hex dump of packets\n"
"  -m  map specified IPv4 addresses to different IPv6 addresses (see manpage)\n"
"  -L  limit simultanous connections\n"
"\n", arg0);
}

void clear_argv(char *argv)
{
	int x;
  
	for (x = 0; x < strlen(argv); x++)
		argv[x] = 'x';

	return;
}

void read_map(const char *filename)
{
	FILE *map_file;
	char ipv4[128], ipv6[128];
	struct ip_map *a, *n;
	
	debug("reading map file %s...\n", filename);

	if (!(map_file = fopen(filename, "r"))) {
		perror("Unable to read map file");
		exit(1);
	}
	
	maps_count = 0;
	while (!feof(map_file) && fscanf(map_file, "%127s %127s", ipv4, ipv6)) {
		debug("map %s->%s\n", ipv4, ipv6);
		
		n = (struct ip_map*) xmalloc(sizeof(struct ip_map));
		n->ipv4_addr = strdup(ipv4);
		n->ipv6_addr = strdup(ipv6);
		n->next = NULL;
		
		if (!(a = maps)) {
			maps = n;
			continue;
		}
		
		while (1) {
			if (!a->next)
				break;
			
			a = a->next;
		}
		
		a->next = n;
		maps_count++;
	}
	
	debug("read %i items\n", maps_count);
	fclose(map_file);
}

const char *find_ip6(const char *ip4)
{
	struct ip_map *tmp;
	
	for (tmp = maps; tmp; tmp = tmp->next)
		if (!strcmp(ip4, tmp->ipv4_addr))
			return tmp->ipv6_addr;
	
	/* and again - try to find the default if explicit search failed */
	for (tmp = maps; tmp; tmp = tmp->next)
		if (!strcmp("0.0.0.0", tmp->ipv4_addr))
			return tmp->ipv6_addr;

	return source_host;
}

void child_hand()
{
	while (wait4(0, NULL, WNOHANG, NULL) > 0) {
		debug("child dying\n");
		conn_count--;
	}

	signal(SIGCHLD, child_hand);
}

int main(int argc, char **argv)
{
	int force = 0, lsock, csock, one = 0, jeden = 1, local_port;
	int detach = 1, listen6 = 0, sa_len, conn_limit = 0;
	char optc, *username = NULL, *map_filename = NULL, *bind_host = NULL;
	struct sockaddr *sa;
	struct sockaddr_in laddr, caddr;
	struct sockaddr_in6 laddr6;
	int caddrlen = sizeof(caddr);
	struct passwd *pw = NULL;
	
	while ((optc = getopt(argc, argv, "1dv46fs:l:I:i:hu:m:L:A:")) != -1) {
		switch (optc) {
			case '1':
				one = 1;
				break;
			case 'd':
				detach = 0;
				break;
			case 'v':
				verbose = 1;
				break;
			case '4':
				hint = AF_INET; 
				break;
			case '6':
				listen6 = 1;
				break;
			case 's':
				source_host = xstrdup(optarg);
				break;
			case 'l':
				bind_host = xstrdup(optarg);
				break;
			case 'r':
				force = 1;
				break;
			case 'i':
				ircpass = xstrdup(optarg);
				clear_argv(argv[optind - 1]);
				break;
			case 'I':
				ircsendpass = xstrdup(optarg);
				clear_argv(argv[optind - 1]);
				break;
			case 'h':
				hexdump = 1;
				break;
			case 'u':
				username = xstrdup(optarg);
				break;
			case 'm':
				map_filename = xstrdup(optarg);
				break;
			case 'L':
				conn_limit = atoi(optarg);
				break;
			default:
				return 1;
		}
	}

	if (hexdump)
		verbose = 1;

	if (verbose)
		detach = 0;
	
	if (detach)
		verbose = 0;

	if (argc - optind < 2) {
		usage(argv[0]);
		exit(1);
	}

	if (username && !(pw = getpwnam(username))) {
		fprintf(stderr, "%s: unknown user %s\n", argv[0], username);
		exit(1);
	}
  
	if (map_filename)
		read_map(map_filename);
  
	local_port = atoi(argv[optind++]);
	remote_host = argv[optind++];
	remote_port = (argc == optind) ? local_port : atoi(argv[optind]);

	debug("resolving %s\n", remote_host);

	if (!(sa = resolve_host(remote_host, hint)) && !force) {
		fprintf(stderr, "%s: unable to resolve host %s\n", argv[0], remote_host);
		exit(1);
	}

	free(sa);
	sa = NULL;

	if (bind_host) {
		debug("resolving %s\n", bind_host);

		if (!(sa = resolve_host(bind_host, (listen6) ? AF_INET6 : AF_INET))) {
			fprintf(stderr, "%s: unable to resolve host %s\n", argv[0], remote_host);
			exit(1);
		}
	}
 
	debug("local: %s,%d; ", (bind_host) ? bind_host : "default", local_port);
	debug("remote: %s,%d; ", remote_host, remote_port);
	debug((map_filename) ? "source: mapped\n" : "source: %s\n", source_host ? source_host : "default");

	if (!listen6) {
		lsock = socket(PF_INET, SOCK_STREAM, 0);

		memset(&laddr, 0, (sa_len = sizeof(laddr)));
		laddr.sin_family = AF_INET;
		laddr.sin_port = htons(local_port);
		
		if (sa) {
			memcpy(&laddr.sin_addr, &((struct sockaddr_in*) sa)->sin_addr, sizeof(struct in_addr));
			free(sa);
		}
		
		sa = (struct sockaddr*) &laddr;
	} else {
		lsock = socket(PF_INET6, SOCK_STREAM, 0);
		
		memset(&laddr6, 0, (sa_len = sizeof(laddr6)));
		laddr6.sin6_family = AF_INET6;
		laddr6.sin6_port = htons(local_port);
		
		if (sa) {
			memcpy(&laddr6.sin6_addr, &((struct sockaddr_in6*) sa)->sin6_addr, sizeof(struct in6_addr));
			free(sa);
		}

		sa = (struct sockaddr*) &laddr6;
	}

	if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &jeden, sizeof(jeden)) == -1) {
		perror("setsockopt");
		exit(1);
	}
  
	if (bind(lsock, sa, sa_len)) {
		perror("bind");
		exit(1);
	}    
  
	if (listen(lsock, 100)) {
		perror("listen");
		exit(1);
	}

	if (detach) {
		int i, ret;

		signal(SIGHUP, SIG_IGN);
		
		for (i = 0; i < 3; i++)
			close(i);

		ret = fork();
		
		if (ret == -1) {
			perror("fork");
			exit(1);
		}

		if (ret)
			exit(0);
	}

	if (username && ((setgid(pw->pw_gid) == -1) || (setuid(pw->pw_uid) == -1))) {
		perror("setuid/setgid");
		exit(1);
	}

	setsid();
	signal(SIGCHLD, child_hand);
    
	for (;;) {  
		int ret;
		fd_set rds;

		FD_ZERO(&rds);
		FD_SET(lsock, &rds);

		if (select(lsock + 1, &rds, NULL, NULL, NULL) == -1) {
			if (errno == EINTR)
				continue;

			perror("select");
			break;
		}

		if ((csock = accept(lsock, (struct sockaddr*) &caddr, &caddrlen)) == -1) {
			perror("accept");
			break;
		}

		inet_ntop(caddr.sin_family, (caddr.sin_family == AF_INET) ?
			&caddr.sin_addr :
			(void*) &(((struct sockaddr_in6*)&caddr)->sin6_addr),
			remote, sizeof(remote));

		debug("<%d> connection from %s,%d", csock, remote, ntohs(caddr.sin_port));

		if (conn_limit && (conn_count >= conn_limit)) {
			debug(" -- rejected due to limit.\n");
			shutdown(csock, 2);
			close(csock);
			continue;
		}
		
		if (conn_limit) {
			conn_count++;
			debug(" (no. %d)", conn_count);
		}
		
		fflush(stdout);
    
		if ((ret = fork()) == -1) {
			debug(" -- fork() failed.\n");
			shutdown(csock, 2);
			close(csock);
			continue;
		}
    
		if (!ret) {
			close(lsock);
			if (maps_count) {
				find_ip6(remote);
				if (!source_host) {
					debug("<%d> connection attempt from unauthorized IP address: %s\n", csock, remote);
					shutdown(csock, 2);
					close(csock);
					exit(0);
				}
				debug(" mapped to host %s", source_host);
			}
			debug("\n");
			make_tunnel(csock);
			debug("<%d> connection closed\n", csock);
			exit(0);
		} 

		close(csock);
    
		if (one) {
			shutdown(lsock, 2);
			close(lsock);
			exit(0);
		}

	}

	close(lsock);
  
	exit(1);
}



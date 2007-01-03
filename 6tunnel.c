/*
 *  6tunnel v0.11
 *  (C) Copyright 2000-2005 by Wojtek Kaniewski <wojtekka@toxygen.net>
 *  
 *  Contributions by:
 *  - Dariusz Jackowski <ascent@linux.pl>
 *  - Ramunas Lukosevicius <lukoramu@parok.lt>
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License Version 2 as
 *  published by the Free Software Foundation.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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

#define debug(x...) do { \
	if (verbose) \
		printf(x); \
} while(0)

int verbose = 0, conn_count = 0;
int remote_port, verbose, hint = AF_INET6, hexdump = 0;
char *remote_host, *ircpass = NULL;
char *ircsendpass = NULL, remote[128];
char *pid_file = NULL;
const char *source_host;

typedef struct map {
	char *ipv4;
	char *ipv6;
	struct map *next;
} map_t;

map_t *map_list = NULL;
char *map_file = NULL;

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

const char *map_find(const char *ipv4)
{
	map_t *m;

	for (m = map_list; m; m = m->next) {
		if (!strcmp(m->ipv4, ipv4))
			return m->ipv6;
	}

	for (m = map_list; m; m = m->next) {
		if (!strcmp(m->ipv4, "0.0.0.0") || !strcmp(m->ipv4, "default"))
			return m->ipv6;
	}

	return source_host;
}

void make_tunnel(int rsock, const char *remote)
{
	char buf[4096], *outbuf = NULL, *inbuf = NULL;
	int sock = -1, outlen = 0, inlen = 0;
	struct sockaddr *sa = NULL;
	const char *source;

	if (map_list) {
		if (!(source = map_find(remote))) {
			debug("<%d> connection from unmapped address (%s), disconnecting\n", rsock, remote);
			goto cleanup;
		}

		debug("<%d> mapped to %s\n", rsock, source);
	} else
		source = source_host;

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

	if ((sock = socket(sa->sa_family, SOCK_STREAM, 0)) == -1) {
		debug("<%d> unable to create socket (%s)\n", rsock, strerror(errno));
		goto cleanup;
	}

	free(sa);
	sa = NULL;

	if (source) {
		if (!(sa = resolve_host(source, hint))) {
			debug("<%d> unable to resolve source host (%s)\n", rsock, source);
			goto cleanup;
		}

		if (bind(sock, sa, (hint == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) {
			debug("<%d> unable to bind to source host (%s)\n", rsock, source);
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

	close(rsock);

	if (sock != -1)
		close(sock);
}

void usage(const char *arg0)
{
	fprintf(stderr,
			
"usage: %s [-146dvh] [-s sourcehost] [-l localhost] [-i pass]\n"
"           [-I pass] [-L limit] [-A filename] [-p pidfile]\n"
"           [-m mapfile] localport remotehost [remoteport]\n"
"\n"	   
"  -1  allow only one connection and quit\n"
"  -4  preffer IPv4 endpoints\n"
"  -6  bind to IPv6 address\n"
"  -d  don't detach\n"
"  -f  force tunneling (even if remotehost isn't resolvable)\n"
"  -h  print hex dump of packets\n"
"  -i  act like irc proxy and ask for password\n"
"  -I  send specified password to the irc server\n"
"  -l  bind to specified address\n"
"  -L  limit simultanous connections\n"
"  -p  write down pid to specified file\n"
"  -s  connect using specified address\n"
"  -m  read specified IPv4-to-IPv6 map file\n"
"  -v  be verbose\n"
"\n", arg0);
}

void clear_argv(char *argv)
{
	int x;
  
	for (x = 0; x < strlen(argv); x++)
		argv[x] = 'x';

	return;
}

void map_destroy(void)
{
	map_t *m;
	
	debug("map_destroy()\n");
	
	for (m = map_list; m; ) {
		map_t *n;
		
		free(m->ipv4);
		free(m->ipv6);
		n = m;
		m = m->next;
		free(n);
	}

	map_list = NULL;
}

void map_read(void)
{
	char buf[256];
	FILE *f;

	if (!map_file)
		return;

	debug("reading map from %s\n", map_file);

	if (!(f = fopen(map_file, "r"))) {
		debug("unable to read map file, ignoring\n");
		return;
	}
	
	while (fgets(buf, sizeof(buf), f)) {
		char *p, *ipv4, *ipv6;
		map_t *m;

		for (p = buf; *p == ' ' || *p == '\t'; p++);

		if (!*p)
			continue;

		ipv4 = p;

		for (; *p && *p != ' ' && *p != '\t'; p++);

		if (!*p)
			continue;

		*p = 0;
		p++;

		for (; *p == ' ' || *p == '\t'; p++);

		if (!*p)
			continue;

		ipv6 = p;

		for (; *p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n'; p++);

		*p = 0;

		debug("[%s] mapped to [%s]\n", ipv4, ipv6);
		
		m = (map_t*) xmalloc(sizeof(map_t));
		m->ipv4 = xstrdup(ipv4);
		m->ipv6 = xstrdup(ipv6);
		m->next = map_list;
		map_list = m;
	}
	
	fclose(f);
}

void sighup()
{
	map_destroy();
	map_read();

	signal(SIGHUP, sighup);
}

void sigchld()
{
	while (waitpid(-1, NULL, WNOHANG) > 0) {
		debug("child process exited\n");
		conn_count--;
	}

	signal(SIGCHLD, sigchld);
}

void sigterm()
{
	if (pid_file)
		unlink(pid_file);

	exit(0);
}

int main(int argc, char **argv)
{
	int force = 0, lsock, csock, one = 0, jeden = 1, local_port;
	int detach = 1, listen6 = 0, sa_len, conn_limit = 0, optc;
	char *username = NULL, *bind_host = NULL;
	struct sockaddr *sa;
	struct sockaddr_in laddr, caddr;
	struct sockaddr_in6 laddr6;
	unsigned int caddrlen = sizeof(caddr);
	struct passwd *pw = NULL;
	
	while ((optc = getopt(argc, argv, "1dv46fs:l:I:i:hu:m:L:A:p:")) != -1) {
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
				map_file = xstrdup(optarg);
				break;
			case 'L':
				conn_limit = atoi(optarg);
				break;
			case 'p':
				pid_file = xstrdup(optarg);
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
  
	if (map_file)
		map_read();
  
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

	if (map_file)
		debug("source: mapped\n");
	else
		debug("source: %s\n", (source_host) ? source_host : "default");

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

		signal(SIGHUP, sighup);
		
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

	if (pid_file) {
		FILE *f = fopen(pid_file, "w");

		if (!f)
			debug("warning: cannot write to pidfile (%s)\n", strerror(errno));
		else {
			fprintf(f, "%d", getpid());
			fclose(f);
		}
	}

	if (username && ((setgid(pw->pw_gid) == -1) || (setuid(pw->pw_uid) == -1))) {
		perror("setuid/setgid");
		exit(1);
	}

	setsid();
	signal(SIGCHLD, sigchld);
	signal(SIGTERM, sigterm);
	signal(SIGINT, sigterm);
	signal(SIGHUP, sighup);
    
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
			signal(SIGHUP, SIG_IGN);
			close(lsock);
			debug("\n");
			make_tunnel(csock, remote);
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



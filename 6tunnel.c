/*
 * 6tunnel v0.09
 * (c) copyright 2000, 2001 by wojtek kaniewski <wojtekka@irc.pl>
 *
 * modified by tomek lipski <lemur@irc.pl>
 * thx to KeFiR@IRCnet
 *
 * modified by Dariusz Jackowski <ascent@linux.pl>
 *
 * modified by awayzzz <awayzzz@digibel.org>
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

#define debug(x...) { if (verbose) printf(x); }

struct ip_map {
	char *ipv4_addr;
	char *ipv6_addr;
	struct ip_map *next;
};

struct sockaddr *resolve_host(char *, int);
void make_tunnel(int);
void usage(char *);
void print_hexdump(char *, int);
void clear_argv(char *argv);
void read_map(int verb);
void find_ip6(char *ip4);
void child_hand();

struct ip_map *maps;
int maps_count, verbose = 0, conn_count = 0;

int remote_port, verbose, hint = AF_INET6, hexdump = 0, local_port, apache_log_fd = -1;
char *remote_host, *source_host = NULL, *ircpass = NULL, *ircsendpass = NULL, *bind_host = NULL;
char *map_filename = NULL, *apache_log = NULL, remote[128];

int main(int argc, char **argv)
{
  int ret, force = 0, lsock, csock, one = 0, jeden = 1;
  int background = 1, listen6 = 0, sa_len, conn_limit = 0;
  char optc, *username = NULL;
  struct sockaddr *sa;
  struct sockaddr_in laddr, caddr;
  struct sockaddr_in6 laddr6;
  int caddrlen = sizeof(caddr);
  struct passwd *pw = NULL;
  while ((optc = getopt(argc, argv, "1dv46fs:l:I:i:hu:m:L:A:")) != -1)
    switch (optc) {
      case '1': one = 1; break;
      case 'd': background = 0; break;
      case 'v': verbose = 1; break;
      case '4': hint = AF_INET; break;
      case '6': listen6 = 1; break;
      case 's': source_host = strdup(optarg); break;
      case 'l': bind_host = strdup(optarg); break;
      case 'r': force = 1; break;
      case 'i': ircpass = strdup(optarg); clear_argv(argv[optind-1]); break;
      case 'I': ircsendpass = strdup(optarg); clear_argv(argv[optind-1]); break;
      case 'h': hexdump = 1; break;
      case 'u': username = strdup(optarg); break;
      case 'm': map_filename = strdup(optarg); break;
      case 'L': conn_limit = atoi(optarg); break;
      case 'A': apache_log = strdup(optarg); break;
      default: return 1;
    }

  if (hexdump) verbose = 1;
  if (verbose) background = 0;
  if (background) verbose = 0;

  if (argc - optind < 2) {
    usage(argv[0]);
    return 1;
  }

  if (username && !(pw = getpwnam(username))) {
    fprintf(stderr, "%s: unknown user %s\n", argv[0], username);
    exit(1);
  }
  
  if (map_filename)
    read_map(verbose);
  
  local_port = atoi(argv[optind++]);
  remote_host = argv[optind++];
  remote_port = (argc == optind) ? local_port : atoi(argv[optind]);

  debug("resolving %s\n", remote_host);
  if (!(sa = resolve_host(remote_host, hint)) && !force) {
    fprintf(stderr, "%s: unable to resolve host %s\n", argv[0], remote_host);
    return 1;
  }
  free(sa);
  sa = NULL;

  if (bind_host)
    debug("resolving %s\n", bind_host);
  if (bind_host && !(sa = resolve_host(bind_host, (listen6) ? AF_INET6 : AF_INET))) {
    fprintf(stderr, "%s: unable to resolve host %s\n", argv[0], remote_host);
    return 1;
  }
 
  debug("-- \033[1m6tunnel\033[0m --\n");  
  debug("local: %s,%d; ", bind_host ? bind_host : "default", local_port);
  debug("remote: %s,%d; ", remote_host, remote_port);
  debug((map_filename) ? "source: mapped\n" : "source: %s\n", source_host ? source_host : "default");
  free(sa);

  if (!listen6) {
    lsock = socket(PF_INET, SOCK_STREAM, 0);
    memset(&laddr, 0, (sa_len = sizeof(laddr)));
    laddr.sin_family = AF_INET;
    laddr.sin_port = htons(local_port);
    if (bind_host)
      memcpy(&laddr.sin_addr, &((struct sockaddr_in*) sa)->sin_addr, sizeof(struct in_addr));
    sa = (struct sockaddr*) &laddr;
  } else {
    lsock = socket(PF_INET6, SOCK_STREAM, 0);
    memset(&laddr6, 0, (sa_len = sizeof(laddr6)));
    laddr6.sin6_family = AF_INET6;
    laddr6.sin6_port = htons(local_port);
    if (bind_host)
      memcpy(&laddr6.sin6_addr, &((struct sockaddr_in6*) sa)->sin6_addr, sizeof(struct in6_addr));
    sa = (struct sockaddr*) &laddr6;
  }

  if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &jeden, sizeof(jeden)) == -1) {
    perror("setsockopt");
    return 1;
  }
  
  if (bind(lsock, sa, sa_len)) {
    perror("bind");
    return 1;
  }    
  
  if (listen(lsock, 100)) {
    perror("listen");
    return 1;
  }

  if (background) {
    signal(SIGHUP, SIG_IGN);
    for (ret = 0; ret < 3; ret++)
      close(ret);
    ret = fork();
    if (ret == -1) {
      perror("fork");
      return 1;
    }
    if (ret)
      return 0;
  }

  if (username && ((setgid(pw->pw_gid) == -1) || (setuid(pw->pw_uid) == -1))) {
    perror("setuid/setgid");
    exit(1);
  }

  setsid();
  signal(SIGCHLD, child_hand);
    
  for (;;) {  
    if ((csock = accept(lsock, (struct sockaddr*) &caddr, &caddrlen)) == -1) {
      if (errno == EINTR)
        continue;
      else {
        close(lsock);
        break;
      }
    }

    inet_ntop(caddr.sin_family, (caddr.sin_family == AF_INET) ?
      &caddr.sin_addr :
      (void*) &(((struct sockaddr_in6*)&caddr)->sin6_addr),
      remote, 128);
    
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
      return 0;
    }

  }
  
  return 1;
}

void make_tunnel(int rsock)
{
  struct sockaddr *sa = NULL;
  int sock = 0, ret, i;
  fd_set fd_read, fd_exc;
  char buf[4096], *foo;
  
#if 0
  if (apache_log) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char tmp[100];
    int len, j;

    strftime(tmp, 100, "%d/%b/%Y:%H:%M:%S %z", tm);
    snprintf(buf, 4095, "%s - - [%s] \"", remote, tmp);
  
    for (i = strlen(buf), j = i; i < 4094; i++) {
      if ((ret = read(rsock, &buf[i], 1)) < 1) {
        shutdown(rsock, 2);
        close(rsock);
        return;
      }
      if (buf[i] == '\n') break;
    }
    buf[i+1] = 0;
    len = strlen(buf) - 1;
    if (i && buf[i-1] == '\r')
      len--;
    
    if (apache_log_fd == -1) {
      if ((apache_log_fd = open(apache_log, O_APPEND | O_CREAT | O_WRONLY, 0600)) != -1) {
	write(apache_log_fd, buf, len - j);
	write(apache_log_fd, "\" 200 0 - -\n", 12);
      }
    }

    write(rsock, buf + j, strlen(buf) - j);
  }
#endif

#define auth_failed { shutdown(rsock, 2); close(rsock); return; }

  if (ircpass) {
    for (i = 0; i < 4095; i++) {
      if ((ret = read(rsock, &buf[i], 1)) < 1) auth_failed;
      if (buf[i] == '\n') break;
    }
    buf[i] = 0;
    if (i && buf[i-1] == '\r') buf[i-1] = 0;

    if (i == 4095 || strncasecmp(buf, "PASS ", 5)) {
      debug("<%d> irc proxy auth failed - junk\n", rsock);
      foo = "ERROR :Closing link: Make your client send password first\r\n";
      write(rsock, foo, strlen(foo));
      auth_failed;
    }

    if (strcmp(buf + 5, ircpass)) {
      debug("<%d> irc proxy auth failed - password incorrect\n", rsock);
      foo = ":6tunnel 464 * :Password incorrect\r\nERROR :Closing link: Password incorrect\r\n";
      write(rsock, foo, strlen(foo));
      auth_failed;
    }
    debug("<%d> irc proxy auth succeded\n", rsock);
  }
  
#undef auth_failed

  if (!(sa = resolve_host(remote_host, hint))) {
    debug("<%d> unable to resolve %s\n", rsock, remote_host);
    return;
  }
  sock = socket(sa->sa_family, SOCK_STREAM, 0);
  free(sa);
  if (source_host) {
    if (!(sa = resolve_host(source_host, hint))) {
      debug("<%d> unable to resolve source host (%s)\n", rsock, source_host);
      return;
    }
    if (bind(sock, sa, (hint == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) {
      free(sa);
      debug("<%d> unable to bind to source host (%s)\n", rsock, source_host);
      return;
    }
    free(sa);
  }

  sa = resolve_host(remote_host, hint);
  ((struct sockaddr_in*) sa)->sin_port = htons(remote_port);
  if (connect(sock, sa, (sa->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) {
    free(sa);
    debug("<%d> connection refused (%s,%d)\n", rsock, remote_host, remote_port);
    return;
  }
  free(sa);

  debug("<%d> connected to %s,%d\n", rsock, remote_host, remote_port);

  if (ircsendpass) {
    snprintf(buf, 4096, "PASS %s\r\n", ircsendpass);
    write(sock, buf, strlen(buf));
  }

#if 0
  if (apache_log)
    write(sock, buf + j, strlen(buf) - j);
#endif

  for (;;) {
    FD_ZERO(&fd_read);
    FD_SET(sock, &fd_read);
    FD_SET(rsock, &fd_read);
    FD_ZERO(&fd_exc);
    FD_SET(sock, &fd_exc);
    FD_SET(rsock, &fd_exc);
    
    ret = select((sock > rsock) ? (sock + 1) : (rsock + 1), &fd_read, NULL, &fd_exc, NULL);

    if (FD_ISSET(sock, &fd_read) || FD_ISSET(sock, &fd_exc)) {
      if ((ret = read(sock, buf, 4096)) < 1) break;
      if (hexdump) {
        printf("<%d> recvfrom %s,%d\n", rsock, remote_host, remote_port);
	print_hexdump(buf, ret);
      }
      write(rsock, buf, ret);
    }

    if (FD_ISSET(rsock, &fd_read) || FD_ISSET(rsock, &fd_exc)) {
      if ((ret = read(rsock, buf, 4096)) < 1) break;
      if (hexdump) {
        printf("<%d> sendto %s,%d\n", rsock, remote_host, remote_port);
	print_hexdump(buf, ret);
      }
      write(sock, buf, ret);
    }
  }

  shutdown(sock, 2);
  close(sock);
  shutdown(rsock, 2);
  close(rsock);
}

struct sockaddr *resolve_host(char *name, int hint)
{
  struct addrinfo *ai = NULL, hints;
  char *ss;
  int ret;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = hint;
  ret = getaddrinfo(name, NULL, &hints, &ai);
  if (!ret && ai) {
    ss = (char*) malloc(ai->ai_addrlen);
    memcpy(ss, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
    return (struct sockaddr*) ss;
  }
  return NULL;
}

void print_hexdump(char *buf, int len)
{
  int i, j;
  
  for (i = 0; i < ((len / 16) + ((len % 16) ? 1 : 0)); i++) {
    printf("%.4x: ", i * 16);
    for (j = 0; j < 16; j++) {
      if (i*16+j < len)
        printf("%.2x ", buf[i*16+j]);
      else
        printf("   ");
      if (j == 7)
        printf(" ");
    }
    printf(" ");
    for (j = 0; j < 16; j++)
      if (i*16+j < len)
        printf("%c", (isprint(buf[i*16+j])) ? buf[i*16+j] : '.');
    printf("\n");
  }
}

void usage(char *a0)
{
  fprintf(stderr, "\
usage: %s [-146dqvh] [-s sourcehost] [-l localhost] [-i pass]
           [-I pass] [-m mapfile] [-L limit] [-A filename]
	   localport remotehost [remoteport]
	   
  -1  allow only one connection and quit
  -4  preffer IPv4 endpoints
  -6  bind to IPv6 address
  -v  be verbose
  -d  don't detach
  -f  force tunneling (even if remotehost isn't resolvable)
  -s  connect using specified address
  -l  bind to specified address
  -i  act like irc proxy and ask for password
  -I  send specified password to the irc server
  -h  print hex dump of packets
  -m  map specified IPv4 addresses to different IPv6 addresses (see manpage)
  -L  limit simultanous connections
  -A  create apache-like log file

", a0);

}

void clear_argv(char *argv)
{
  int x;
  
  for (x = 0; x < strlen(argv); x++)
    argv[x] = 'x';

  return;
}

void read_map(verb)
{
	FILE *map_file;
	char ipv4[128], ipv6[128];
	struct ip_map *a, *n;
	
	debug("reading map file %s...\n", map_filename);
	if (!(map_file = fopen(map_filename, "r"))) {
		perror("Unable to read map file");
		exit(-1);
	}
	
	maps_count = 0;
	while (!feof(map_file) && fscanf(map_file, "%127s %127s", ipv4, ipv6)) {
		debug("map %s->%s\n", ipv4, ipv6);
		
		n = malloc(sizeof(struct ip_map));
		if (n == NULL) {
			printf("Unable to allocate memory.\n");
			exit(-1);
		}
		
		n->ipv4_addr = strdup(ipv4);
		n->ipv6_addr = strdup(ipv6);
		n->next = NULL;
		
		a = maps;
		if (a == NULL) {
			maps = n;
			continue;
		}
		
		while (1) {
			if (a->next == NULL)
				break;
			
			a = a->next;
		}
		
		a->next = n;
		maps_count++;
	}
	
	debug("read %i items\n", maps_count);
	fclose(map_file);
}

void find_ip6(char *ip4)
{
	struct ip_map *tmp;
	
	source_host = NULL;
	tmp = maps;
	
	while (tmp != NULL) {
		if (!strcmp(ip4, tmp->ipv4_addr)) {
			source_host = tmp->ipv6_addr;
			return;
		}
		tmp = tmp->next;
	}
	
	// and again - try to find the default if explicit search failed
	tmp = maps;
	
	while (tmp != NULL) {
		if (!strcmp("0.0.0.0", tmp->ipv4_addr)) {
			source_host = tmp->ipv6_addr;
			return;
		}
		tmp = tmp->next;
	}
}

void child_hand()
{
  while (wait4(0, NULL, WNOHANG, NULL) > 0) {
    debug("child dying\n");
    conn_count--;
  }
  signal(SIGCHLD, child_hand);
}

/*
 * 6tunnel v0.01
 * (c) copyright 2000 by wojtek kaniewski <wojtekka@irc.pl>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>

struct sockaddr *resolve_host(char *, sa_family_t);
void make_tunnel(int, char *, char *, int, sa_family_t, int);
void usage(char *);

int main(int argc, char **argv)
{
  int ret, local_port, remote_port, force = 0, lsock, csock, one = 0, quiet = 0;
  struct sockaddr *sa;
  char optc, *remote_host, *local_host = NULL, remote[128];
  sa_family_t hint = AF_INET6;
  struct sockaddr_in laddr, caddr;
  int caddrlen = sizeof(caddr);

  if ((optc = getopt(argc, argv, "1q4fs:")) != -1) {
    switch (optc) {
      case '1':
        one = 1;
	break;
      case 'q':
        quiet = 1;
	break;
      case '4':
        hint = AF_INET;
	break;
      case 's':
        local_host = strdup(optarg);
      case 'f':
        force = 1;
	break;
      default:
        usage(argv[0]);
	return 1;
    }
  }

  if (argc - optind < 2) {
    usage(argv[0]);
    return 1;
  }
  
  local_port = atoi(argv[optind++]);
  remote_host = argv[optind++];
  remote_port = (argc == optind) ? local_port : atoi(argv[optind]);
  
  if (!quiet) {
    printf("local: %s, %d\n", local_host ? local_host : "localhost", local_port);
    printf("remote: %s, %d\n", remote_host, remote_port);
  }

  if (!(sa = resolve_host(remote_host, hint)) && !force) {
    fprintf(stderr, "%s: unable to resolve host %s\n", argv[0], remote_host);
    return 1;
  }
  
  lsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  laddr.sin_addr.s_addr = INADDR_ANY;
  laddr.sin_port = htons(local_port);
  
  if (bind(lsock, &laddr, sizeof(laddr))) {
    perror("bind");
    return 1;
  }
    
  if (listen(lsock, 5)) {
    perror("listen");
    return 1;
  }
  
  while ((csock = accept(lsock, &caddr, &caddrlen)) != -1) {
    if (!quiet)
      printf("connection from %s, %d\n", inet_ntop(caddr.sin_family, (caddr.sin_family == AF_INET) ? &caddr.sin_addr : (void*) &(((struct sockaddr_in6*)&caddr)->sin6_addr), remote, 128), ntohs(caddr.sin_port));
    if (!(ret = fork())) {
      close(lsock);
      make_tunnel(csock, local_host, remote_host, remote_port, hint, quiet);
    } else
      close(csock);
    if (one) {
      close(lsock);
      return 0;
    }
  }
  
  return 1;
}

void make_tunnel(int rsock, char *source, char *host, int port, sa_family_t hint, int quiet)
{
  struct sockaddr *sa = NULL;
  int sock, ret;
  fd_set fd_read, fd_exc;
  char buf[4096];
  
  if (!(sa = resolve_host(host, hint)))
    exit(1);

  sock = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
  
  if (source) {
    if (!(sa = resolve_host(source, hint)))
      exit(1);
    if (bind(sock, sa, sizeof(struct sockaddr_in6)))
      exit(1);
  }

  sa = resolve_host(host, hint);
  ((struct sockaddr_in*) sa)->sin_port = htons(port);
  if (connect(sock, sa, sizeof(struct sockaddr_in6))) {
    perror("connect");
    exit(1);
  }
  
  for (;;) {
    FD_ZERO(&fd_read);
    FD_SET(sock, &fd_read);
    FD_SET(rsock, &fd_read);
    FD_ZERO(&fd_exc);
    FD_SET(sock, &fd_exc);
    FD_SET(rsock, &fd_exc);
    
    ret = select(sock > rsock ? sock + 1 : rsock + 1, &fd_read, NULL, &fd_exc, NULL);

    if (FD_ISSET(sock, &fd_read) || FD_ISSET(sock, &fd_exc)) {
      if ((ret = read(sock, buf, 4096)) < 1) break;
      write(rsock, buf, ret);
    }

    if (FD_ISSET(rsock, &fd_read) || FD_ISSET(rsock, &fd_exc)) {
      if ((ret = read(rsock, buf, 4096)) < 1) break;
      write(sock, buf, ret);
    }
  }

  if (!quiet)
    printf("connection closed\n");
  shutdown(sock, 2);
  close(sock);
  shutdown(rsock, 2);
  close(rsock);

  exit(1);
}

struct sockaddr *resolve_host(char *name, sa_family_t hint)
{
  struct addrinfo *ai = NULL, hints;
  char *ss;
  int ret;

  hints.ai_family = hint;
  ret = getaddrinfo(name, NULL, NULL, &ai);
  if (!ret && ai) {
    ss = (char*) malloc(ai->ai_addrlen);
    memcpy(ss, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
    return (struct sockaddr*) ss;
  } else 
    return NULL;
}

void usage(char *a0)
{
  fprintf(stderr, "\
usage: %s [-14qf] [-s localhost] localport remotehost remoteport\n\
\n\
  -1  allow only one connection and quit\n\
  -4  preffer IPv4\n\
  -q  be quiet\n\
  -f  force tunneling (even if remotehost isn't resolvable)\n\
  -s  connect using speciffied address\n\
\n", a0);

}

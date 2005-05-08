/*
 * 6tunnel v0.03
 * (c) copyright 2000 by wojtek kaniewski <wojtekka@irc.pl>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

struct sockaddr *resolve_host(char *, int);
void make_tunnel(int, char *, char *, int, int, int);
void usage(char *);

int main(int argc, char **argv)
{
  int ret, local_port, remote_port, force = 0, lsock, csock, one = 0;
  int verbose = 0, background = 1, listen6 = 0, sa_len;
  char optc, *remote_host, *source_host = NULL, *bind_host = NULL, remote[128];
  int hint = AF_INET6;
  struct sockaddr *sa;
  struct sockaddr_in laddr, caddr;
  struct sockaddr_in6 laddr6;
  int caddrlen = sizeof(caddr);

  while ((optc = getopt(argc, argv, "1dv46fs:l:")) != -1)
    switch (optc) {
      case '1': one = 1; break;
      case 'd': background = 0; break;
      case 'v': verbose = 1; background = 0; break;
      case '4': hint = AF_INET; break;
      case '6': listen6 = 1; break;
      case 's': source_host = strdup(optarg); break;
      case 'l': bind_host = strdup(optarg); break;
      case 'r': force = 1; break;
      default: usage(argv[0]); return 1;
    }

  if (background)
    verbose = 0;

  if (argc - optind < 2) {
    usage(argv[0]);
    return 1;
  }
  
  local_port = atoi(argv[optind++]);
  remote_host = argv[optind++];
  remote_port = (argc == optind) ? local_port : atoi(argv[optind]);
  
  if (verbose) {
    printf(" local: %s, %d\n", bind_host ? bind_host : "localhost", local_port);
    printf("remote: %s, %d\n", remote_host, remote_port);
  }

  if (!(sa = resolve_host(remote_host, hint)) && !force) {
    fprintf(stderr, "%s: unable to resolve host %s\n", argv[0], remote_host);
    return 1;
  }

  if (bind_host && !(sa = resolve_host(bind_host, (listen6) ? AF_INET6 : AF_INET))) {
    fprintf(stderr, "%s: unable to resolve host %s\n", argv[0], remote_host);
    return 1;
  }
 
  if (!listen6) {
    lsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&laddr, 0, (sa_len = sizeof(laddr)));
    laddr.sin_family = AF_INET;
    laddr.sin_port = htons(local_port);
    if (bind_host)
      memcpy(&laddr.sin_addr, &((struct sockaddr_in*) sa)->sin_addr, sizeof(struct in_addr));
    sa = (struct sockaddr*) &laddr;
  } else {
    lsock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
    memset(&laddr6, 0, (sa_len = sizeof(laddr6)));
    laddr6.sin6_family = AF_INET6;
    laddr6.sin6_port = htons(local_port);
    if (bind_host)
      memcpy(&laddr6.sin6_addr, &((struct sockaddr_in6*) sa)->sin6_addr, sizeof(struct in6_addr));
    sa = (struct sockaddr*) &laddr6;
  }
  
  if (bind(lsock, sa, sa_len)) {
    perror("bind");
    return 1;
  }
    
  if (listen(lsock, 5)) {
    perror("listen");
    return 1;
  }

  if (background) {
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

  signal(SIGHUP, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
    
  for (;;) {
  
    if ((csock = accept(lsock, (struct sockaddr*) &caddr, &caddrlen)) == -1) {
      if (errno == EINTR)
        continue;
      else
        break;
    }

    if (verbose)
      printf("<%d> connection from %s, %d\n", csock, inet_ntop(caddr.sin_family, (caddr.sin_family == AF_INET) ? &caddr.sin_addr : (void*) &(((struct sockaddr_in6*)&caddr)->sin6_addr), remote, 128), ntohs(caddr.sin_port));

    if ((ret = fork()) == -1) {
      shutdown(csock, 2);
      close(csock);
      continue;
    }
    
    if (!ret) {
      shutdown(lsock, 2);
      close(lsock);
      make_tunnel(csock, source_host, remote_host, remote_port, hint, verbose);
      if (verbose)
        printf("<%d> connection closed\n", csock);
//    } else {
//      shutdown(csock, 2);
//      close(csock);
    }
    
    if (one) {
      shutdown(lsock, 2);
      close(lsock);
      return 0;
    }
  }
  
  return 1;
}

void make_tunnel(int rsock, char *source, char *host, int port, int hint, int verbose)
{
  struct sockaddr *sa = NULL;
  int sock, ret;
  fd_set fd_read, fd_exc;
  char buf[4096];
  
  if (!(sa = resolve_host(host, hint))) {
    if (verbose) printf("<%d> unable to resolve %s\n", rsock, host);
    return;
  }
  sock = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
  
  if (source) {
    if (!(sa = resolve_host(source, hint))) {
      if (verbose) printf("<%d> unable to resolve source host (%s)\n", rsock, source);
      return;
    }
    if (bind(sock, sa, (hint == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) {
      if (verbose) printf("<%d> unable to bind to source host (%s)\n", rsock, source);
      return;
    }
  }

  sa = resolve_host(host, hint);
  ((struct sockaddr_in*) sa)->sin_port = htons(port);
  printf("sa_family = %d\n", sa->sa_family);
  if (connect(sock, sa, (sa->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) {
    if (verbose) {
      printf("<%d> connection refused (%s, %d)\n", rsock, host, port);
      perror("connect");
    }
    return;
  }

  printf("<%d> connected to %s, %d\n", rsock, host, port);
  
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
      write(rsock, buf, ret);
    }

    if (FD_ISSET(rsock, &fd_read) || FD_ISSET(rsock, &fd_exc)) {
      if ((ret = read(rsock, buf, 4096)) < 1) break;
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

void usage(char *a0)
{
  fprintf(stderr, "\
usage: %s [-146dqv] [-s sourcehost] [-l localhost] \n\
                localport remotehost remoteport\n\
\n\
  -1  allow only one connection and quit\n\
  -4  preffer IPv4 endpoints\n\
  -6  bind to IPv6 address\n\
  -v  be verbose\n\
  -d  don't fork\n\
  -f  force tunneling (even if remotehost isn't resolvable)\n\
  -s  connect using specified address\n\
  -l  bind to specified address\n\
\n", a0);

}

# 6tunnel

6tunnel allows you to use services provided by IPv6 hosts with IPv4-only applications and vice-versa. It can bind to any of your IPv4 (default) or IPv6 addresses and forward all data to IPv4 or IPv6 (default) host.

The following example binds to local IPv4 port 10000 and redirects all connections to krakow6.irc.pl port 6667 via IPv6:

```
$ 6tunnel 10000 krakow6.irc.pl 6667
$
```

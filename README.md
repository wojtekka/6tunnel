6tunnel
=======

6tunnel allows you to use services provided by IPv6 hosts with
IPv4-only applications and vice-versa. It can bind to any of your IPv4
(default) or IPv6 addresses and forward all data to IPv4 or IPv6
(default) host. For example

```
6tunnel -1 6668 irc6.net 6667
```

will be enough to connect to IPv6 irc server with

```
irc foobar localhost:6668
```

If you don't wish to run 6tunnel every time you want to show your
`:c001:` or `:dead:` IPv6 address on IRC, you can use `-i` parameter, which
makes 6tunnel ask your client for specified password. Just run

```
6tunnel -i dupa.8 31337 irc6.net 6667
```

and then type

```
irc foobar localhost:31337:dupa.8
```

If your IRC server requires you to send password, specify it with `-I`
parameter -- after successful proxy authentication 6tunnel will send it
to the server.

6tunnel can also be used as a tunnel for all other combinations of IPv4
and IPv6 endpoints. If remote host doesn't have any IPv6 addresses,
6tunnel will use the IPv4 one. In other cases, use -4 parameter which
makes IPv4 address the preffered one. For IPv6-to-any tunnels use -6
which makes 6tunnel bind to IPv6 address.

License
-------

Since version 0.11 released under the terms of
[GPL version 2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html) --
see [release notes](https://github.com/wojtekka/6tunnel/releases/tag/0.11)
for details.


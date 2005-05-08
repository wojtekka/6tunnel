Name: 6tunnel
Version: 0.03
Release: 1
Group: Networking/Utilities
Copyright: GPL
BuildRoot: /var/tmp/%{name}-root
Source: ftp://amba.bydg.pdi.net/pub/wojtekka/6tunnel-%{version}.tar.gz
Summary: Simple tunneling for applications that don't speak IPv6.

%description
If you want to access some services that are avaiable only for IPv6 hosts
and the application doesn't support it or you have no time to play with
patches, use this tool. Simple `6tunnel 6668 irc6.net 6667' will do :)

%prep
%setup -n 6tunnel
%build
make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin %{buildroot}/usr/man/man1
install 6tunnel %{buildroot}/usr/bin
install 6tunnel.1 %{buildroot}/usr/man/man1

%clean
rm -rf %{buildroot}

%files
/usr/bin/6tunnel
/usr/man/man1/6tunnel.1

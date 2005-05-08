#!/bin/sh
autoconf
test x$NOCONFIGURE = x && ./configure

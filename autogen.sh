#!/bin/sh
autoreconf --install
test x$NOCONFIGURE = x && ./configure

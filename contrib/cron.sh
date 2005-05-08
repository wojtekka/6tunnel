#!/bin/sh
#
# This is a script for use in crontab.
#
# To check for your 6tunnel every 10 minutes,
# put this line in your crontab:
# 0,10,20,30,40,50 * * * * /home/yourdir/6tunnel/cron.sh >/dev/null 2>&1
#

### CONFIG ###

# Path to 6tunnel
T6PATH="/home/misio/6tunnel"

# Real 6tunnel file name
T6BIN="6tunnel"

# Start options
T6OPTIONS="-4 -s very.nice.host.pl -i secretpass 19999 poznan.irc.pl 6666"

# Name of pidfile
T6PIDFILE="6tunnel.pid"

### CODE ###

cd $T6PATH
if test -r $T6PATH/$T6PIDFILE; then
     MYPID=$(cat $T6PATH/$T6PIDFILE)
     if $(kill -CHLD $MYPID >/dev/null 2>&1)
     then
        exit 0
     fi
     echo ""
     echo "erasing old PID file"
     rm -f $T6PATH/$T6PIDFILE
fi

echo ""
echo "6tunnel not running, restarting..."
echo ""

if test -x $T6BIN ;then
   $T6PATH/$T6BIN -p $T6PIDFILE $T6OPTIONS
   exit 0
fi

echo "error restarting 6tunnel"


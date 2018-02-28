#!/bin/sh

iptables -L -n -v | grep -q $1
RETVAL=$?

if [ $RETVAL -eq 0 ]; then

        echo "IP address already in blocklist: $1"
        exit 0

fi
echo "Adding enemy $1"
iptables -A Enemies -s $1 -j DROP

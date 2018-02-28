#!/bin/sh

echo "Deleting enemy $1"
iptables -D Enemies -s $1 -j DROP

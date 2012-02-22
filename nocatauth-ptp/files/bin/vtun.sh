#!/bin/sh

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin

ROUTER="10.10.2.1"
TUNNEL="192.168.0.1"
TSERV="1.2.3.4"
SSHUSER="nocat"
VCONF="/usr/local/etc/vtund.conf"

echo "Loading module..."
modprobe tun

echo "Dropping default route..."
route del default
route add $TSERV gw $ROUTER

echo "Starting ssh to $TSERV..."
ssh -N -C -f -c blowfish -L 5000:localhost:5000 $SSHUSER@$TSERV

echo "Firing up vtund..."
vtund -f $VCONF home localhost

echo "Adding new default route..."
sleep 2
route add default gw $TUNNEL

echo "Have fun!"

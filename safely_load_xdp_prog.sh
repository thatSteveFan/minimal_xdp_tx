#!/bin/bash
echo "Loading $2 onto $1, removing after 30s sleep"

ip link set dev $1 xdp obj $2 sec xdp

sleep 5

ip link set dev $1 xdp off


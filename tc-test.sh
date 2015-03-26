#! /bin/bash
###############################################################################
# limittraf - per-client outgoing traffic limiter.
# Copyright (C) 2013-2015 Edward Chernenko.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
###############################################################################

# NOTE: on Fedora >=17 additional kernel modules should be installed:
#	yum install kernel-PAE-modules-extra

# WAS: qdisc pfifo_fast 0: dev em1 root refcnt 2 bands 3 priomap  1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1

export DEV="em1"

modprobe sch_netem || exit
tc qdisc del dev $DEV root 2>/dev/null

#tc qdisc add dev $DEV root handle 1: cbq avpkt 1000 bandwidth 16mbit
#tc class add dev $DEV parent 1: classid 1:1 cbq rate 128kbit allot 1500 prio 5 bounded isolated 
#tc filter add dev $DEV parent 1: protocol ip prio 16 u32 match ip dst 184.72.216.34 flowid 1:1

tc qdisc add dev $DEV root handle 1: htb
tc class add dev $DEV parent 1: classid 1:1 htb rate 128kbit burst 10k mpu 64
tc filter add dev $DEV parent 1: protocol ip prio 123456 u32 match ip dst 184.72.216.34 flowid 1:1

# tc filter del dev $DEV prio 123456


echo "tc qdisc show"
tc qdisc show 
echo "tc class show"
tc class show dev $DEV
echo "tc filter show"
tc filter show dev $DEV

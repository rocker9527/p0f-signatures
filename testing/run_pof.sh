#!/bin/bash

MAC_EXPR=$(ifconfig -a | grep "HWaddr " | grep -v "HWaddr 00:00:00:00:00:00" | grep "Link encap:Ethernet" | awk '{tmp=match($0,/HWaddr ([0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2})/,m);print "ether dst "m[1]}' | sort | uniq | awk -vORS=" || " '{print $0}' | sed 's/ || $/\n/')
./p0f -s /var/run/p0f.sock -f ../p0f.fp -i lo -d "tcp port 80 && ($MAC_EXPR)" 
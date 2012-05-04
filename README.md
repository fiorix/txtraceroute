# txtraceroute

Pure python traceroute implementation

This traceroute is based on the implementation by fiorix and is extended to
support TCP and UDP traceroute.

## For TCP SYN traceroute:

`sudo python txtraceroute.py -n -g -p tcp -d <dst_port> -s <src_port> ooni.nu`

## For UDP traceroute:

`sudo python txtraceroute.py -n -g -p udp -d <dst_port> -s <src_port> ooni.nu`

## For ICMP Ping traceroute:

`sudo python txtraceroute.py -n -g -p icmp ooni.nu`


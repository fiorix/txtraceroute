#!/usr/bin/env python
# coding: utf-8
#
# Copyright 2010 Alexandre Fiori
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import json
import operator
import os
import socket
import struct
import sys
import time

from twisted.internet import defer, reactor, task
from twisted.web.client import getPage

class iphdr(object):
    def __init__(self, proto=socket.IPPROTO_ICMP, src="0.0.0.0", dst=None):
        self.version = 4
        self.hlen = 5
        self.tos = 0
        self.length = 20
        self.id = os.getpid()
        self.frag = 0
        self.ttl = 255
        self.proto = proto
        self.cksum = 0
        self.src = src
        self.saddr = socket.inet_aton(src)
        self.dst = dst or "0.0.0.0"
        self.daddr = socket.inet_aton(self.dst)
        self.data = ""

    def assemble(self):
        header = struct.pack('BBHHHBB',
                             (self.version & 0x0f) << 4 | (self.hlen & 0x0f),
                             self.tos, self.length + len(self.data),
                             socket.htons(self.id), self.frag,
                             self.ttl, self.proto)
        return header + "\000\000" + self.saddr + self.daddr + self.data

    @classmethod
    def disassemble(self, data):
        ip = iphdr()
        pkt = struct.unpack('!BBHHHBBH', data[:12])
        ip.version = (pkt[0] >> 4 & 0x0f)
        ip.hlen = (pkt[0] & 0x0f)
        ip.tos, ip.length, ip.id, ip.frag, ip.ttl, ip.proto, ip.cksum = pkt[1:]
        ip.saddr = data[12:16]
        ip.daddr = data[16:20]
        ip.src = socket.inet_ntoa(ip.saddr)
        ip.dst = socket.inet_ntoa(ip.daddr)
        return ip

    def __repr__(self):
        return "IP (tos %s, ttl %s, id %s, frag %s, proto %s, length %s) " \
               "%s -> %s" % \
               (self.tos, self.ttl, self.id, self.frag, self.proto, self.length,
                self.src, self.dst)


class icmphdr(object):
    def __init__(self, data=""):
        self.type = 8
        self.code = 0
        self.cksum = 0
        self.id = os.getpid()
        self.sequence = 0
        self.data = data

    def assemble(self):
        part1 = struct.pack("BB", self.type, self.code)
        part2 = struct.pack("!HH", self.id, self.sequence)
        cksum = self.checksum(part1 + "\000\000" + part2 + self.data)
        cksum = struct.pack("!H", cksum)
        return part1 + cksum + part2 + self.data

    @classmethod
    def checksum(self, data):
        if len(data) & 1:
            data += "\0"
        cksum = reduce(operator.add,
                       struct.unpack('!%dH' % (len(data)>>1), data))
        cksum = (cksum >> 16) + (cksum & 0xffff)
        cksum += (cksum >> 16)
        cksum = (cksum & 0xffff) ^ 0xffff
        return cksum

    @classmethod
    def disassemble(self, data):
        icmp = icmphdr()
        pkt = struct.unpack("!BBHHH", data)
        icmp.type, icmp.code, icmp.cksum, icmp.id, icmp.sequence = pkt
        return icmp

    def __repr__(self):
        return "ICMP (type %s, code %s, id %s, sequence %s)" % \
               (self.type, self.code, self.id, self.sequence)


@defer.inlineCallbacks
def geolocate(ip):
    try:
        r = yield getPage("http://freegeoip.net/json/%s" % ip)
        d = json.loads(r)
        items = [d["country_name"], d["region_name"], d["city"]]
        text = ", ".join([s for s in items if s])
        defer.returnValue(text.encode("utf-8"))
    except Exception, e:
        defer.returnValue("Unknown location")


class Hop(object):
    def __init__(self, ttl):
        self.ttl = ttl
        self.found = False
        self.tries = 0
        self.last_try = 0
        self.ip = None
        self.location = None

    @property
    def number(self):
        return self.ttl

    @property
    def seconds(self):
        if self.found is False:
            return -1
        else:
            return self.found - self.last_try

    def __repr__(self):
        if self.ip == "??" or self.location is None:
            location = ""
        else:
            location = " (%s)" % (self.location)
        if self.seconds == -1:
            ping = ""
        else:
            ping = " %0.3fs" % self.seconds
        return "%02d. % 15s%s%s" % (self.ttl, self.ip, ping, location)


class Traceroute(object):
    def __init__(self, target, hopfound_callback=None,
                 max_hops=30, retries=3, timeout=2):
        fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        fd.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        self.fd = fd
        self.target = target
        self.max_hops = max_hops
        self.retries = retries
        self.timeout = timeout
        self.hopfound_callback = hopfound_callback
        reactor.addReader(self)
        reactor.addWriter(self)

        # response, and outgoing queue
        self.hops = {}
        self.out_queue = []
        self.target_id = None

        # will call the deferred when waiting is False
        self.waiting = True
        self.deferred = defer.Deferred()

        # send 1st probe packet
        for ttl in xrange(1, max_hops):
            self.send(Hop(ttl))

        # start looping call to double check hops
        t = task.LoopingCall(self.checkPending)
        t.start(0.5)

    def getRoute(self):
        return self.deferred

    def fileno(self):
        return self.fd.fileno()

    def done(self):
        result = []
        self.waiting = False
        items = sorted(self.hops.iteritems(), key=operator.itemgetter(0))
        for (hid, hop) in items:
            result.append(hop)
            if hop.ip == self.target:
                break

        self.deferred.callback(result)

    @defer.inlineCallbacks
    def checkPending(self):
        pending = False
        items = sorted(self.hops.iteritems(), key=operator.itemgetter(0))
        for hid, hop in items:
            if self.target_id is not None:
                if hid > self.target_id:
                    break

            if hop.found is False:
                if hop.tries <= self.retries:
                    pending = True
                    if hop.last_try+self.timeout < time.time():
                        self.send(hop)
                        continue
                else:
                    hop.found = time.time()
                    hop.ip = "??"
            else:
                if hop.ip != "??" and hop.location is None:
                    hop.location = yield geolocate(hop.ip)

        if pending is False:
            self.done()
            defer.returnValue(False)

    def send(self, hop):
        hop.tries += 1
        hop.last_try = time.time()

        ip = iphdr(dst=self.target)
        icmp = icmphdr("traceroute")

        ip.ttl = hop.ttl
        ip.id += hop.ttl
        icmp.id = ip.id
        ip.data = icmp.assemble()

        self.hops[ip.id] = hop
        self.out_queue.append((ip.assemble(), (ip.dst, 0)))

    def doWrite(self):
        if self.out_queue and self.waiting is True:
            pkt = self.out_queue.pop(0)
            self.fd.sendto(*pkt)

    def doRead(self):
        if self.waiting is False:
            return

        hop_id = None
        pkt, src = self.fd.recvfrom(4096)

        # disassemble ip header
        ip = iphdr.disassemble(pkt[:20])
        if ip.proto != socket.IPPROTO_ICMP:
            return

        # disassemble icmp header
        icmp = icmphdr.disassemble(pkt[20:28])
        if icmp.type != 11:
            if icmp.type != 0 or icmp.id not in self.hops:
                return
            else:
                hop_id = icmp.id
        else:
            # disassemble referenced ip header
            ref = iphdr.disassemble(pkt[28:48])
            if not self.hops.get(ref.id):
                defer.returnValue(None)
            hop_id = ref.id

        if hop_id is not None:
            self.hops[hop_id].found = time.time()
            self.hops[hop_id].ip = ip.src

        if ip.src == self.target:
            self.target_id = hop_id

        if self.target_id is None or hop_id < self.target_id:
            if callable(self.hopfound_callback):
                self.hopfound_callback(self.hops[hop_id])

    def connectionLost(self, why):
        pass

    def logPrefix(self):
        return "Traceroute(%s)" % self.target


def hopfound_callback(hop):
    #print "found", hop
    sys.stdout.write(".")
    sys.stdout.flush()


@defer.inlineCallbacks
def trace(target):
    print("Tracing %s" % target)
    d = Traceroute(target, hopfound_callback)
    result = yield d.getRoute()
    print "!"
    for hop in result:
        print hop

    reactor.stop()


def main():
    try:
        target = sys.argv[1]
    except:
        print("use: %s target" % sys.argv[0])
        sys.exit(1)

    try:
        target = socket.gethostbyname(target)
    except Exception, e:
        print("Could not resolve: %s\n%s" % (target, str(e)))
        sys.exit(1)

    if os.getuid() != 0:
        print("Traceroute needs root privileges for the raw socket")
        sys.exit(1)

    reactor.callWhenRunning(trace, target)
    reactor.run()

if __name__ == "__main__":
    main()

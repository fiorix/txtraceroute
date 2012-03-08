#!/usr/bin/env python
# coding: utf-8

import json
import operator
import os
import socket
import struct
import sys
import time

from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet import threads
from twisted.python import usage
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
               (self.tos, self.ttl, self.id, self.frag, self.proto,
                self.length, self.src, self.dst)


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
                       struct.unpack('!%dH' % (len(data) >> 1), data))
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
def geoip_lookup(ip):
    try:
        r = yield getPage("http://freegeoip.net/json/%s" % ip)
        d = json.loads(r)
        items = [d["country_name"], d["region_name"], d["city"]]
        text = ", ".join([s for s in items if s])
        defer.returnValue(text.encode("utf-8"))
    except Exception:
        defer.returnValue("Unknown location")


@defer.inlineCallbacks
def reverse_lookup(ip):
    try:
        r = yield threads.deferToThread(socket.gethostbyaddr, ip)
        defer.returnValue(r[0])
    except Exception:
        defer.returnValue(None)


class Hop(object):
    def __init__(self, target, ttl):
        self.found = False
        self.tries = 0
        self.last_try = 0
        self.remote_ip = None
        self.remote_icmp = None
        self.remote_host = None
        self.location = ""

        self.ttl = ttl
        self.ip = iphdr(dst=target)
        self.ip.ttl = ttl
        self.ip.id += ttl

        self.icmp = icmphdr("traceroute")
        self.icmp.id = self.ip.id
        self.ip.data = self.icmp.assemble()

        self._pkt = self.ip.assemble()

    @property
    def pkt(self):
        self.tries += 1
        self.last_try = time.time()
        return self._pkt

    def __repr__(self):
        if self.found:
            if self.remote_host:
                ip = ":: %s" % self.remote_host
            else:
                ip = ":: %s" % self.remote_ip.src
            ping = "%0.3fs" % (self.found - self.last_try)
        else:
            ip = "??"
            ping = "-"

        location = ":: %s" % self.location if self.location else ""
        return "%02d. %s %s %s" % (self.ttl, ping, ip, location)


class TracerouteProtocol(object):
    def __init__(self, target, **settings):
        self.target = target
        self.settings = settings
        self.fd = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                socket.IPPROTO_ICMP)
        self.fd.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        self.hops = []
        self.out_queue = []
        self.waiting = True
        self.deferred = defer.Deferred()

        reactor.addReader(self)
        reactor.addWriter(self)

        # send 1st probe packet
        self.out_queue.append(Hop(self.target, 1))

    def logPrefix(self):
        return "TracerouteProtocol(%s)" % self.target

    def fileno(self):
        return self.fd.fileno()

    @defer.inlineCallbacks
    def hopFound(self, hop, ip, icmp):
        hop.remote_ip = ip
        hop.remote_icmp = icmp

        if (ip and icmp):
            hop.found = time.time()
            if self.settings.get("geoip_lookup") is True:
                hop.location = yield geoip_lookup(ip.src)

            if self.settings.get("reverse_lookup") is True:
                hop.remote_host = yield reverse_lookup(ip.src)

        ttl = hop.ttl + 1
        last = self.hops[-2:]
        if len(last) == 2 and last[0].remote_ip == ip or \
           (ttl > (self.settings.get("max_hops", 30) + 1)):
            done = True
        else:
            done = False

        if not done:
            cb = self.settings.get("hop_callback")
            if callable(cb):
                yield defer.maybeDeferred(cb, hop)

        if not self.waiting:
            if self.deferred:
                self.deferred.callback(self.hops)
                self.deferred = None
        else:
            self.out_queue.append(Hop(self.target, ttl))

    def doRead(self):
        if not self.waiting or not self.hops:
            return

        pkt = self.fd.recv(4096)

        # disassemble ip header
        ip = iphdr.disassemble(pkt[:20])
        if ip.proto != socket.IPPROTO_ICMP:
            return

        found = False

        # disassemble icmp header
        icmp = icmphdr.disassemble(pkt[20:28])
        if icmp.type == 0 and icmp.id == self.hops[-1].icmp.id:
            found = True
        elif icmp.type == 11:
            # disassemble referenced ip header
            ref = iphdr.disassemble(pkt[28:48])
            if ref.dst == self.target:
                found = True

        if ip.src == self.target:
            self.waiting = False

        if found:
            self.hopFound(self.hops[-1], ip, icmp)

    def hopTimeout(self, *ign):
        hop = self.hops[-1]
        if not hop.found:
            if hop.tries < self.settings.get("max_tries", 3):
                self.out_queue.append(hop)
            else:
                self.hopFound(hop, None, None)

    def doWrite(self):
        if self.waiting and self.out_queue:
            hop = self.out_queue.pop(0)
            pkt = hop.pkt
            if not self.hops or (self.hops and hop.ttl != self.hops[-1].ttl):
                self.hops.append(hop)
            self.fd.sendto(pkt, (hop.ip.dst, 0))

            timeout = self.settings.get("timeout", 1)
            reactor.callLater(timeout, self.hopTimeout)

    def connectionLost(self, why):
        pass


def traceroute(target, **settings):
    tr = TracerouteProtocol(target, **settings)
    return tr.deferred


@defer.inlineCallbacks
def start_trace(target, **settings):
    hops = yield traceroute(target, **settings)
    if settings["hop_callback"] is None:
        for hop in hops:
            print hop

    reactor.stop()


class Options(usage.Options):
    optFlags = [
        ["silent", "s", "Only print results at the end."],
        ["no-dns", "n", "Show numeric IPs only, not their host names."],
        ["no-geoip", "g", "Do not collect and show GeoIP information"],
        ["help", "h", "Show this help"],
    ]
    optParameters = [
        ["timeout", "t", 2, "Timeout for probe packets"],
        ["tries", "r", 3, "How many tries before give up probing a hop"],
        ["max_hops", "m", 30, "Max number of hops to probe"],
    ]


def main():
    if os.getuid() != 0:
        print("traceroute needs root privileges for the raw socket")
        sys.exit(1)

    def show(hop):
        print hop

    defaults = dict(hop_callback=show,
                    reverse_lookup=True,
                    geoip_lookup=True,
                    timeout=2,
                    max_tries=3,
                    max_hops=30)

    if len(sys.argv) < 2:
        print("Usage: %s [options] host" % (sys.argv[0]))
        print("%s: Try --help for usage details." % (sys.argv[0]))
        sys.exit(1)

    target = sys.argv.pop(-1) if sys.argv[-1][0] != "-" else ""
    config = Options()
    try:
        config.parseOptions()
        if not target:
            raise
    except usage.UsageError, e:
        print("%s: %s" % (sys.argv[0], e))
        print("%s: Try --help for usage details." % (sys.argv[0]))
        sys.exit(1)

    settings = defaults.copy()
    if config.get("silent"):
        settings["hop_callback"] = None
    if config.get("no-dns"):
        settings["reverse_lookup"] = False
    if config.get("no-geoip"):
        settings["geoip_lookup"] = False
    if "timeout" in config:
        settings["timeout"] = config["timeout"]
    if "tries" in config:
        settings["max_tries"] = config["tries"]
    if "max_hops" in config:
        settings["max_hops"] = config["max_hops"]

    try:
        target = socket.gethostbyname(target)
    except Exception, e:
        print("could not resolve '%s': %s" % (target, str(e)))
        sys.exit(1)

    reactor.callWhenRunning(start_trace, target, **settings)
    reactor.run()

if __name__ == "__main__":
    main()

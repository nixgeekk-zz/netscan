#!/usr/bin/env python2

import sys, socket, time, os, netifaces, netaddr, nmap
from netaddr import *
from scapy.all import *

global addr, netmask, cidr, allhosts

def GetIPAndHostName():
    fqdn = socket.getfqdn()
    global curip
    curip = socket.gethostbyname(fqdn)
    print fqdn, curip

def GetSubNet():
    global ip
    ip = IPNetwork(curip)


def CurDateAndTime():
    os.environ['TZ'] = 'US/Pacific'
    time.tzset()
    ztime = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.localtime())
    print("%s" % ztime)


def get_address_in_network():

    global addr, netmask, cidr, allhosts
    network = netaddr.IPNetwork(ip)
    for iface in netifaces.interfaces():
        if iface == 'lo':
            continue

        addresses = netifaces.ifaddresses(iface)

        if network.version == 4 and netifaces.AF_INET in addresses:
            addr = addresses[netifaces.AF_INET][0]['addr']
            netmask = addresses[netifaces.AF_INET][0]['netmask']
            cidr = netaddr.IPNetwork("%s/%s" % (addr, netmask))

            print ("using Current interface: %s" % iface)

            allhosts = IPNetwork(cidr)

            print ("IPADDR: %s" % addr)
            print ("NETMASK: %s" % netmask)
            print "CIDR: %s " % cidr
            print "Nodes in Subnet: %s" % len(allhosts)

            starttime = time.time()
            nm = nmap.PortScanner()
            a=nm.scan(hosts=str(cidr), arguments='-T4 -sP  --min-rate 1000 --max-retries 1')
            endtime = time.time()
            totaltime = endtime - starttime
            n = 0
            for k,v in a['scan'].iteritems():
                if str(v['status']['state']) == 'up':
                    n += 1
                    try:    print str(v['addresses']['ipv4']) + ' => ' + str(v['addresses']['mac']) + ' => ' + str(v['hostnames'])[25:-2]
                    except: print str(v['addresses']['ipv4'])

            print ("Nodes in Subnet: %d" % n)
            print ("Arp scan in %f seconds...." % (totaltime))


def main():
    CurDateAndTime()
    GetIPAndHostName()
    GetSubNet()
    get_address_in_network()


main()
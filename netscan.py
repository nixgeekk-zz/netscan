#!/usr/bin/env python3

import socket, time, os, netifaces, netaddr, nmap, pprint, re, subprocess, logging, argparse
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from netaddr import *
from portscan import TCP_connect, scan_ports

global addr, netmask, cidr, allhosts

def OpenFile():
    global f
    f = open('portscan_output.txt', 'at+')

def WriteFile(string):
    f.write(str(string))

def CloseFile():
    f.close()


def OpenFileLimit():
    
    ulimitmax = subprocess.getoutput('ulimit -Sn')
    nulimitmax = int(ulimitmax)


    if os.name.split()[0] == 'posix':
        if nulimitmax < 10000:
            print()
            print('Please set open files too 10000.. ulimit -Sn 10000')
            #os.popen("bash -c ulimit -Sn 10000")
            print()
            raise SystemExit()
            

def GetIPAndHostName():
    fqdn = socket.getfqdn()
    global curip
    curip = socket.gethostbyname(fqdn)
    print ("%s, %s" % (fqdn, curip))

def GetSubNet():
    global ip
    ip = IPNetwork(curip)


def CurDateAndTime():
    os.environ['TZ'] = 'US/Pacific'
    time.tzset()
    ztime = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.localtime())
    print ("%s" % ztime)

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
            print ("CIDR: %s " % cidr)
            print ("Nodes in Subnet: %s" % len(allhosts))
            print()

            nm = nmap.PortScanner()

            starttime = time.time()

            a=nm.scan(hosts=str(cidr), arguments='-T4 -sP -PE --min-rate 1000 --max-retries 1')

            endtime = time.time()
            totaltime = endtime - starttime
            n = 0
            print('-------------------------------------------------------------------------------')
            print('Hostname   ::  IP Address  ::    Mac    ::     Vendor')
            print('-------------------------------------------------------------------------------')
            print()
            for k,v in a['scan'].items():
                if str(v['status']['state']) == 'up':
                    n += 1
                    pp = pprint.PrettyPrinter(indent=0)
                    splithost = str(v['hostnames'])
                    splitip = str(v['addresses']['ipv4'])
                    splitvendor = str(v['vendor'])
                    zhost = str(splithost.split("'")[7:8])
                    newzhost = re.sub('[\[\]\']', '', zhost)

                    #print(len(newzhost))
                    #print(newzhost)

                    if len(newzhost) <= 4:
                        Znewzhost = 'NULL'
                    else:
                        Znewzhost = newzhost

                    ZipAddr = splitip
                    zvendor1 = str(splitvendor.split("'")[1:2])
                    zvendor2 = str(splitvendor.split("'")[3:4])
                    newzvendor1 = re.sub('[\[\]\'\{\}]', '', zvendor1)
                    newzvendor2 = re.sub('[\[\]\'\{\}]', '', zvendor2)


                    if len(newzvendor1) != 0:
                        Znewzvendor1 = newzvendor1
                    else:
                        Znewzvendor1 = 'NULL'

                    if len(newzvendor2) != 0:
                        Znewzvendor2 = newzvendor2
                    else:
                        Znewzvendor2 = 'NULL'

                    print("%s :: %s :: %s :: %s" % (Znewzhost, ZipAddr, Znewzvendor1, Znewzvendor2))
                    parser = argparse.ArgumentParser()
                    parser.add_argument('-p', action='store_true', help='scan ports')
                    parser.add_argument('-f', action='store_true', help='write output to a file')
                    results = parser.parse_args()


                    if results.p:
                        scan_ports(ZipAddr, 1)

                    if results.f:
                        strscan = str(scan_ports(ZipAddr, 1))
                        #print(strscan)
                        WriteFile(strscan)


            print ("Nodes in Subnet: %d" % n)
            print ("Arp scan in %f seconds...." % (totaltime))


def main():

    astarttime = time.time()


    OpenFile()
    OpenFileLimit()
    CurDateAndTime()
    GetIPAndHostName()
    GetSubNet()
    get_address_in_network()
    CloseFile()

    aendtime = time.time()

    atotaltime = aendtime - astarttime
    print(0)
    print("Total time: %f" % atotaltime)
    print(0)

main()

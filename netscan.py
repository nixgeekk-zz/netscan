#!/usr/bin/env python3

import socket, struct, time, os, netifaces, netaddr, nmap, pprint, re, subprocess, logging, argparse, resource
from netaddr import *
from portscan import scan_ports
from pwd import getpwnam
import getpass
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

global addr, netmask, cidr, allhosts, scannedhosts, strscan, xx, results


def OpenFile():
    global f
    f = open('portscan_output.txt', 'w+')


def WriteFile(strscan):
    #print(strscan)
    f.write(str(strscan))


def CloseFile():
    f.close()


def OpenFileLimit():
    global soft, hard, softlimit, hardlimit
    ulimitmax = subprocess.getoutput('ulimit -Sn')
    softlimit = subprocess.getoutput('ulimit -Sn')
    hardlimit = subprocess.getoutput('ulimit -Hn')
    nulimitmax = int(ulimitmax)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)

    if os.name.split()[0] == 'posix':
        if nulimitmax < 10000:
            print()
            if int(hardlimit) < 10000:
                newhardlimit = 10000
            else:
                newhardlimit = hardlimit

            print("Open File limit too small, setting Open Files limit to 10000")
            resource.setrlimit(resource.RLIMIT_NOFILE, (int(newhardlimit), int(newhardlimit)))
            s, h = resource.getrlimit(resource.RLIMIT_NOFILE)
            print("Soft: %s, Hard: %s\n" % (s, h))
            print()


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

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', action='store_true', help='scan ports')
    parser.add_argument('-f', action='store_true', help='write output to a file')
    results = parser.parse_args()

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
            # print("All hosts: %d" % (allhosts.size - 2))

            print ("IPADDR: %s" % addr)
            print ("NETMASK: %s" % netmask)
            print ("CIDR: %s " % cidr)
            print ("Nodes in Subnet: %d" % (allhosts.size - 2))
            print()

            starttime = time.time()
            nm = nmap.PortScanner()
            a = nm.scan(hosts=str(cidr), arguments=' --system-dns -F -T4 -R -sS -PE --min-rate 1000 --max-retries 1')
            endtime = time.time()
            totaltime = endtime - starttime
            n = 0
            print('-------------------------------------------------------------------------------')
            print('Hostname/FQDN   ::  IP Address  ::    Mac    ::     Vendor')
            print('-------------------------------------------------------------------------------')
            print()
            if results.f:
                WriteFile("-------------------------------------------------------------------------------" + "\n" +
                "Hostname/FQDN   ::  IP Address  ::    Mac    ::     Vendor" + "\n" +
                "-------------------------------------------------------------------------------" + "\n")
                print("\nwriting to file portscan_output.txt in current directory.\n")
                WriteFile("\n")

            for k,v in a['scan'].items():
                if str(v['status']['state']) == 'up':
                    n += 1
                    pp = pprint.PrettyPrinter(indent=0)
                    splithost = str(v['hostnames'])
                    splitip = str(v['addresses']['ipv4'])
                    splitvendor = str(v['vendor'])
                    zhost = str(splithost.split("'")[7:8])
                    newzhost = re.sub('[\[\]\']', '', zhost)

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


                    if results.p:
                        scan_ports(ZipAddr, 1)

                    if results.f:
                        WriteFile(Znewzhost + " :: ")
                        WriteFile(ZipAddr + " :: ")
                        WriteFile(Znewzvendor1 + " :: ")
                        WriteFile(Znewzvendor2 + " :: ")
                        WriteFile("\n")

            print ("Number of hosts found in Subnet: %d" % n)
            if results.f:
                WriteFile("Nodes in Subnet: %d\n" % n)
            print ("Arp scan in %f seconds...." % totaltime)
            if results.f:
                WriteFile("Arp scan in %f seconds....\n\n" % totaltime)


def main():

    astarttime = time.time()
    currentuser = getpass.getuser()
    userUID = getpwnam(currentuser).pw_uid
    #print(currentuser)
    #print(userUID)

    if userUID > 0:
        print("Must be root user to run this!\n\n")
        exit()

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', action='store_true', help='scan ports')
    parser.add_argument('-f', action='store_true', help='write output to a file')
    results = parser.parse_args()

    if results.f:
        OpenFile()
    OpenFileLimit()
    CurDateAndTime()
    GetIPAndHostName()
    GetSubNet()
    get_address_in_network()

    aendtime = time.time()

    atotaltime = aendtime - astarttime
    print()
    print("Total time: %f seconds" % atotaltime)
    if results.f:
        WriteFile("Total time: %f seconds\n\n" % atotaltime)
    print()
    if int(softlimit) < 10000:
        print("reverting Open files to original setting Soft: %s Hard: %s" % (softlimit, hardlimit))
        resource.setrlimit(resource.RLIMIT_OFILE, (soft, hard))
        ss, hh = resource.getrlimit(resource.RLIMIT_NOFILE)
        print("Soft: %s, Hard: %s\n" % (ss, hh))
    if results.f:
        CloseFile()

main()

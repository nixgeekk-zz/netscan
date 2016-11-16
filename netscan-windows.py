
import sys, socket, time, os, netifaces, netaddr, nmap, pytz, ipaddress, iptools
import winreg
from netaddr import *
from scapy.all import *

global addr, netmask, cidr, allhosts, xrange

def GetNetMask(ip):
    proc = subprocess.Popen('ipconfig', stdout=subprocess.PIPE)
    while True:
        line = proc.stdout.readline()
        if ip.encode() in line:
            break
    subnet_mask = proc.stdout.readline().rstrip().split(b':')[-1].replace(b' ', b'').decode()

    return (subnet_mask)


def GetIPAndHostName():
    global fqdn
    fqdn = socket.getfqdn()
    global curip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 0))
    curip = s.getsockname()[0]
    #curip = socket.gethostbyname(fqdn)
    print ("%s,%s" % (fqdn, curip))

def GetSubNet():
    global ip
    ip = IPNetwork(curip)

def CurDateAndTime():
    os.environ['TZ'] = 'US/Pacific'
    pytz.timezone('US/Pacific')
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
            if addr[0:3] == '169' or addr == '127.0.0.1':
                continue

            print (addr)
            #netmask = addresses[netifaces.AF_INET][0]['netmask']
            #netmask = '255.255.255.0'
            netmask = GetNetMask(addr)

            cidr = netaddr.IPNetwork("%s/%s" % (addr, netmask))
            #nn = ipaddress.ip_network(cidr)
            #netmask = nn.netmask
            print (netmask)

            print ("using Current interface: %s" % iface)

            allhosts = IPNetwork(cidr)

            print ("IPADDR: %s" % addr)
            print ("NETMASK: %s" % netmask)
            print ("CIDR: %s " % cidr)
            print ("Nodes in Subnet: %s" % len(allhosts))

            starttime = time.time()
            nm = nmap.PortScanner()
            a=nm.scan(hosts=str(cidr), arguments='-T4 -sP  --min-rate 1000 --max-retries 1')
            endtime = time.time()
            totaltime = endtime - starttime
            n = 0

            print('-------------------------------------------------------------------------------')
            print('Hostname   ::  IP Address  ::    Mac    ::     Vendor')
            print('-------------------------------------------------------------------------------')
            print()
            for k, v in a['scan'].items():
                if str(v['status']['state']) == 'up':
                    n += 1
                    #pp = pprint.PrettyPrinter(indent=0)

                splithost = str(v['hostnames'])
                splitip = str(v['addresses']['ipv4'])
                splitvendor = str(v['vendor'])

            # splithost = re.sub('[\']', '', splithost)

            # print (splitip)

                zhost = str(splithost.split("'")[7:8])
                newzhost = re.sub('[\[\]\']', '', zhost)

            # print(len(newzhost))
                if len(newzhost) <= 4:
                    Znewzhost = 'NULL'
                else:
                    Znewzhost = newzhost

                zip = splitip

                zvendor1 = str(splitvendor.split("'")[1:2])
                zvendor2 = str(splitvendor.split("'")[3:4])
                newzvendor1 = re.sub('[\[\]\'\{\}]', '', zvendor1)
                newzvendor2 = re.sub('[\[\]\'\{\}]', '', zvendor2)

                # print(len(newzvendor1))
                # print(len(newzvendor2))

                if len(newzvendor1) != 0:
                    Znewzvendor1 = newzvendor1
                else:
                    Znewzvendor1 = 'NULL'

                if len(newzvendor2) != 0:
                    Znewzvendor2 = newzvendor2
                else:
                    Znewzvendor2 = 'NULL'

                print("%s :: %s :: %s :: %s" % (Znewzhost, zip, Znewzvendor1, Znewzvendor2))
                
    print ("Nodes in Subnet: %d" % n)
    print ("Arp scan in %f seconds...." % (totaltime))


def main():
    CurDateAndTime()
    GetIPAndHostName()
    GetSubNet()
    get_address_in_network()


main()
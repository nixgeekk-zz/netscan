#!/usr/bin/env python3
# This script runs on Python 3
import socket, threading
from datetime import datetime
from queue import Queue

def TCP_connect(ip, port_number, delay, output):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(delay)
    try:
        TCPsock.connect((ip, port_number))
        output[port_number] = 'Listening'
    except:
        output[port_number] = ''

    TCPsock.close()

def scan_ports(host_ip, delay):

    print()
    threads = []        # To run TCP_connect concurrently
    output = {}         # For printing purposes
    count = 0
    # Check what time the scan started
    t1 = datetime.now()

    # Spawning threads to scan ports
    for i in range(10000):
        t = threading.Thread(target=TCP_connect, args=(host_ip, i, delay, output))
        t.daemon = True
        threads.append(t)

    # Starting threads
    for i in range(10000):
        threads[i].start()

    # Locking the script until all threads complete
    for i in range(10000):
        threads[i].join()

    # Printing listening ports from small to large
    for i in range(10000):
        if output[i] == 'Listening':
            print(str(i) + ': ' + str(output[i]))
            count += 1
#            return(str(i) + ': ' + str(output[i]) + '\n')


    print()            
    print('Count of ports open: %s - %s' % (count, str(host_ip)))

    # Checking the time again
    t2 = datetime.now()

    # Calculates the difference of time, to see how long it took to run the script
    total = t2 - t1

    # Printing the information to screen
    print('Port Scanning Completed in: ' , (total))
    print()

def main():
    host_ip = input("Enter host IP: ")
    delay = int(input("How many seconds the socket is going to wait until timeout: "))
    scan_ports(host_ip, delay)

if __name__ == "__main__":
    main()

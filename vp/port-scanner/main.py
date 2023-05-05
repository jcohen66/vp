import optparse
import socket
from socket import *
from threading import *

screenLock = Semaphore(value=1)

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('ViolentPython\r\n')
        results = connSkt.recv(100)
        screenLock.acquire()
        print(f'[+]{tgtPort}/tcp open')
        connSkt.close()
    except Exception as e:
        screenLock.acquire()
        print(f"[-]{tgtPort}/tcp closed")
    finally:
        screenLock.release()
        connSkt.close()


def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except Exception as e:
        print(f'[-] Cannot resolve {tgtHost}: Unknown host')
        return
    
    try:
        tgtName = gethostbyaddr(tgtIP)
        print(f'\n[+] Scan results for: {tgtName[0]}')
    except Exception as e:
        print(f'\n[-] Scan results for: {tgtIP}')
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
        t.start()
        print(f'Scanning port {tgtPort}')

def main():

    parser = optparse.OptionParser(f'usage %prog -H <target host> -p <target port>')

    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s] separated by commas')
    (options, arg) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')
    if (tgtHost == None) | (tgtPorts == None):
        print(parser.usage)
        exit(0)
    portScan(tgtHost, tgtPorts)

if __name__ == '__main__':
    main()

# input a hostname and comma separated list of ports to scan

# translate the hostname into an IP4 address

# for each port in the list connect to the host and port

# send garbage data to determine if service is running on the port
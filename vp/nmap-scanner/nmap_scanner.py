import nmap
import optparse
from threading import *

def nmapScan(tgtHost, tgtPort):
    nmScan = nmap.PortScanner()
    nmScan.scan(tgtHost, tgtPort)
    #print(nmScan.scan(tgtHost, tgtPort))

    try:
        # state = nmScan[tgtHost]['tcp'][int(tgtPort)]['state']
        state = nmScan['scan'][tgtHost]['tcp'][tgtPort]['state']
        print(f'[*] {tgtHost} tcp/{tgtPort} {state}')
    except KeyError as e:
        pass
        # print(tgtHost, tgtPort, e)
    

def main():
    parser = optparse.OptionParser('usage%prog -H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help="specify target port[s] separated by commas")
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    if tgtHost is None:
        exit(0)
    if options.tgtPort is not None:
        for tgtPort in tgtPorts:
            nmapScan(tgtHost, tgtPort)
    else:
        for tgtPort in range(2000):
            t = Thread(target=nmapScan, args=(tgtHost,str(tgtPort)))    
            t.start()


if __name__ == "__main__":
    main()
# end main            print(tgtHost, tgtPort)

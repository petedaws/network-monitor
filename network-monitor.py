import nmap
import pprint
nm = nmap.PortScanner()
nm.scan('192.168.1.1/24 -sn')
hosts = nm.all_hosts()
pprint.pprint(hosts)

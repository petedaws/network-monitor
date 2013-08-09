import nmap
import pprint
import time
nm = nmap.PortScanner()

while 1:
  r = nm.scan('192.168.1.1/24 -sn')
  macs = [i['addresses'].get('mac') for i in r['scan'].values()]
  pprint.pprint(macs)
  time.sleep(10)

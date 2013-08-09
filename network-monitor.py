import nmap
import pprint
import time
import sys
import pprint
nm = nmap.PortScanner()

last_scan = {}
cumulative_scan = {}

def get_mac_list(scan):
  if 'scan' in scan:
    return [i['addresses'].get('mac') for i in scan['scan'].values()]
  else:
    return []

while 1:
  print 'running scan..',
  current_scan = nm.scan('192.168.1.1/24 -sn')
  print 'complete'
  new_macs = set(get_mac_list(current_scan)) - set(get_mac_list(last_scan))
  lost_macs = set(get_mac_list(last_scan)) - set(get_mac_list(current_scan))
  last_scan = current_scan
  cumulative_scan.update(current_scan)
  open('cumulative_scan.txt','wb').write(pprint.pprint(cumulative_scan))
  if len(new_macs):
      print 'New hosts found %s' % new_macs
  if len(lost_macs):
      print 'Hosts lost %s' % lost_macs
  time.sleep(10)

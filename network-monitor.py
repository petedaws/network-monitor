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
  host_join = set(get_mac_list(current_scan)) - set(get_mac_list(last_scan))
  host_left = set(get_mac_list(last_scan)) - set(get_mac_list(current_scan))
  host_new = set(get_mac_list(cumulative_scan)) - set(get_mac_list(current_scan))
  last_scan = current_scan
  cumulative_scan.update(current_scan)
  open('cumulative_scan.txt','wb').write(pprint.pformat(cumulative_scan))
  if len(host_join):
      #print 'Host Joined %s' % host_join
      pass
  if len(host_left):
      #print 'Host Left %s' % host_left
      pass    
  if len(host_new):
      print 'New Host detected %s' % host_new
  time.sleep(10)

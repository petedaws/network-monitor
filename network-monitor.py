import nmap
import pprint
import time
import sys
import pprint
nm = nmap.PortScanner()

last_scan = {}
cumulative_scan = {}

def scan_reformat(scan):
  sr = {}
  if 'scan' in scan:
    for host in scan['scan']:
      sr[host['addresses']['mac']] = host
      return sr
  else:
    return {}

while 1:
  print 'running scan..',
  s = nm.scan('192.168.1.1/24 -sn')
  print 'complete'
  current_scan = scan_reformat(s)
  host_join = set(current_scan.keys()) - set(last_scan.keys())
  host_left = set(last_scan.keys()) - set(current_scan.keys())
  host_new = set(cumulative_scan.keys()) - set(current_scan.keys())
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

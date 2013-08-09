import nmap
import pprint
import time
import sys
import pprint
nm = nmap.PortScanner()

last_scan = {}
try:
  cumulative_scan = eval(open('cumulative_scan.txt','rb').read())
except Exception,e:
  cumulative_scan = {}

def scan_reformat(scan):
  sr = {}
  if 'scan' in scan:
    for host in scan['scan'].values():
      if 'addresses' in host:
        if 'mac' in host['addresses']:
          sr[host['addresses']['mac']] = host
        else:
          sr[host['addresses']['ipv4']] = host
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
  host_new = set(current_scan.keys()) - set(cumulative_scan.keys())
  print 'current_scan'
  pprint.pprint(current_scan.keys())
  print 'last_scan' 
  pprint.pprint(last_scan.keys())
  print 'cumulative_scan'
  pprint.pprint(cumulative_scan.keys())
  last_scan = current_scan
  cumulative_scan.update(current_scan)
  open('cumulative_scan.txt','wb').write(pprint.pformat(cumulative_scan))
  if len(host_join):
      print 'Host Joined %s' % host_join
      pass
  if len(host_left):
      print 'Host Left %s' % host_left
      pass    
  if len(host_new):
      print 'New Host detected %s' % host_new
      pass
  time.sleep(10)

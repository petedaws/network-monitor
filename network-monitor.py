import nmap
import pprint
import time
import sys
nm = nmap.PortScanner()

mac_list = []

while 1:
  sys.stdout.write('running scan..')
  r = nm.scan('192.168.1.1/24 -sn')
  print 'complete'
  current_mac_list = [i['addresses'].get('mac') for i in r['scan'].values()]
  new_macs = set(current_mac_list) - set(mac_list)
  lost_macs = set(mac_list) - set(current_mac_list)
  mac_list = current_mac_list
  if len(new_macs):
      print 'New hosts found %s' % new_macs
  if len(lost_macs):
      print 'Hosts lost %s' % lost_macs
  time.sleep(10)

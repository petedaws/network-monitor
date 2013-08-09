import nmap
import pprint
import time
nm = nmap.PortScanner()

mac_list = []

while 1:
  r = nm.scan('192.168.1.1/24 -sn')
  current_mac_list = [i['addresses'].get('mac') for i in r['scan'].values()]
  new_macs = set(current_mac_list) - set(mac_list)
  lost_macs = set(mac_list) - set(current_mac_list)
  if len(new_macs):
      print 'New hosts found %s' % new_macs
  if len(lost_macs):
      print 'Hosts lost %s' % lost_macs
  time.sleep(10)

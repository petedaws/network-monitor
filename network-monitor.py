import nmap
import pprint
import time
import sys
import pprint
import urllib2
import smtplib
from email.mime.text import MIMEText

nm = nmap.PortScanner()

last_scan = {}
vendor_mapping = {}
try:
  cumulative_scan = eval(open('cumulative_scan.txt','rb').read())
except Exception,e:
  cumulative_scan = {}
conf = eval(open('conf.cfg','rb').read())

if not conf['password']:
	conf['password'] = open('%s.password' % conf['email'],'rb').read()

def scan_reformat(scan):
  sr = {}
  if 'scan' in scan:
    for host in scan['scan'].values():
      if 'addresses' in host:
        if 'mac' in host['addresses']:
          host['vendor_details'] = vendor_mapping.get(host['addresses']['mac']) 
          sr[host['addresses']['mac']] = host
        else:
          sr[host['addresses']['ipv4']] = host
    return sr
  else:
    return {}

def vendor_lookup(scan,vendors):
  for mac in scan.keys():
    if not vendor_mapping.get(mac):
      vendors[mac] = urllib2.urlopen(conf['lookup_url']+conf['lookup_id']+'/'+mac[:8].replace(':','')).read().split(',')
      scan[mac]['vendor_details'] = vendors[mac]

while 1:
  s = nm.scan(conf['subnet']+ ' -sn')
  current_scan = scan_reformat(s)
  vendor_lookup(current_scan,vendor_mapping)
  host_join = set(current_scan.keys()) - set(last_scan.keys())
  host_left = set(last_scan.keys()) - set(current_scan.keys())
  host_new = set(current_scan.keys()) - set(cumulative_scan.keys())
  last_scan = current_scan
  cumulative_scan.update(current_scan)
  open('cumulative_scan.txt','wb').write(pprint.pformat(cumulative_scan))
  if len(host_new):
      output = 'The following new hosts joined the network:\n'
      for mac in host_new:
        output += pprint.pformat(cumulative_scan[mac])
        output += '\n\n'
      msg = MIMEText(output)
      msg['Subject'] = 'ALERT: New host(s) detected on %s' % (conf['subnet'])
      msg['From'] = conf['email_source']
      s = smtplib.SMTP(conf['email_server'])
      s.starttls()
      s.login(conf['email'],conf['password'])
      s.sendmail(conf['email_source'],[conf['email_out']],msg.as_string())
      s.quit() 
  time.sleep(10)

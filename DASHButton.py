from scapy.all import *
import time
import requests

MAGIC_FORM_URL = 'CLOUDSTITCH API URL'

def record():
	data = {
		"Timestamp": time.strftime("%Y-%m-%d %H:%M"), 
		"Action": 'LOG'
	}
	print str(data['Timestamp']) + " " + str(data['Action'])
	requests.post(MAGIC_FORM_URL, data)
	
def arp_display(pkt):
  timestamp = time.strftime("%Y-%m-%d %H:%M")
  if pkt[ARP].op == 1: #who-has (request)
  	if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
		if pkt[ARP].hwsrc == '74:75:48:bb:c7:e5':
			record()
		else:
			print "ARP Probe from: " + pkt[ARP].hwsrc
			
print sniff(prn=arp_display, filter="arp", store=0, count=10)

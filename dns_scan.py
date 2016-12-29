
from scapy.all import *

a = rdpcap('/tmp/DNS.pcap')
def dns_scan(packets):
	dnsamplification_log = open("logs.txt", "a")
	found = False #flag
	dnslist = take_sample("DNS")
	rslist = []
	qrlist = []
	

	for packet in dnslist:
		if packet[DNS].qr == 0:
			qrlist.append(packet)
		else:
			rslist.append(packet)

	del dnslist[:]

	for rsP in rslist:
		for qrP in qrlist:
			if rsP[IP].src == qrP[IP].src and rsP[IP].id == qrP[IP].id:
				found = True
				qrlist.remove(qrP)
				break
		if found == True:
			found = False
			continue
		else:
`			for element in dnslist:
				if element[0] - datetime.datetime(rsP.time).min
			
				




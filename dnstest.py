
from scapy.all import *
import datetime


a = rdpcap('/tmp/DNS.pcap')

class PInfo():
	
    def __init__(self, destport, starttime, lasttime, counter, IPs, size):
        self.destport = destport
        self.starttime = starttime
        self.lasttime = lasttime
        self.counter = counter
        self.IPs = IPs
	self.size = size
    
    def compareTime(self, packettime):
    # returns True if less than two minutes have passed False othrewise
        if packettime.timetuple()[5] - self.lasttime.timetuple()[5] <= 1 and \
                    packettime.timetuple()[1] == self.lasttime.timetuple()[1] and \
                        packettime.timetuple()[2] == self.lasttime.timetuple()[2] and \
                            packettime.timetuple()[3] == self.lasttime.timetuple()[3] and \
                                packettime.timetuple()[4] == self.lasttime.timetuple()[4]:
            return True


        if (packettime.timetuple()[5] - self.lasttime.tuple()[5] > 1 or \
        packettime.timetuple()[1] != self.lasttime.tuple()[1] or \
        packettime.timetuple()[2] != self.lasttime.tuple()[2] or \
        packettime.timetuple()[3] != self.lasttime.tuple()[3] or \
        packettime.timetuple()[4] != self.lasttime.tuple()[4]):
            return False

	return False

def take_sample(packets, protocol, *args):
	genericlist = []
	hasAll = True
	for packet in packets:
		if protocol in packet:
        		for flags in args:
                		if flags[0] is '!' and not(packet[protocol].flags & int(flags[1:], 16)):
                   			hasAll = True
                		elif flags[0] is not '!' and (packet[protocol].flags & int(flags, 16)):
                    			hasAll = True
                		else:
               	     			hasAll = False
                 		  	break
			if hasAll is True:
				genericlist.append(packet)
	return genericlist



def dns_scan(packets):

	dnsamplification_log = open("logs.txt", "a")
	
	successful_amps = []
	rslist = []
	qrlist = []
	amp_info = None

	for packet in packets:
		if packet[DNS].qr == 0:
			qrlist.append(packet)
		else:
			rslist.append(packet)

	
	for rsP in rslist:
		for qrP in qrlist:
			if rsP[IP].src == qrP[IP].dst and rsP[DNS].id == qrP[DNS].id:
				qrlist.remove(qrP)
				break
		else:
			rsPtime = datetime.datetime.fromtimestamp(int(rsP.time))
			if amp_info != None:
				if amp_info.compare(rsPtime):
					amp_info.counter += 1
					amp_info.size += len(rsP)
					if rsP[IP].src not in amp_info.IPs:
						amp_info.IPs.append(rsP[IP].src)

				elif amp_info.compare(rsPtime) is False and amp_info.counter >= 10:  
                        	# if more than two minutes have passed since the last attack and there were more than 10 attempts recently, classify as an attack that has happend
                        		successful_amps.append[amp_info]
					amp_info = None	 

				else:                     
 				# if more than two minutes have passed since the last attack and there were less than 10 attempts recently, delete from the list of possible attacks            
                        		amp_info = None
			else:
				amp_info = PInfo(53 ,rsPtime, rsPtime, 1, [rsP[IP].src], len(rsP))

	
	if amp_info != None and amp_info.counter >= 10:
		successful_amps.append[amp_info]
        
	for element in successful_amps:    
		dnsamplification_log.write("<!> There has been a DNS AMPLIFICATION attack (on DNS port 53) from the time: %s to the time %s, a total of %d DNS response packets were sent with no queries, a total of %d bytes were sent, The responding IPs are:\n" % (element.firsttime.strftime('%Y-%m-%d %H:%M:%S'), element.lasttime.strftime('%Y-%m-%d %H:%M:%S'), element.counter, element.size))
		for aIP in element.IPs:
            		dnsamplification_log.write("    %s\n" % (aIP))


dns_scan(a)



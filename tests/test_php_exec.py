from scapy.all import *
import datetime

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
    hasAll = False
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
                hasAll = False
    return genericlist

def scan_syn(packets):
    s = ""

    synlist = take_sample(packets, 'TCP', "0x02", "!0x10")
    acklist = take_sample(packets, 'TCP', "0x10", "!0x02")
    floodList = [] 
    successfulFloods = [] 

    for synP in synlist:
        for ackP in acklist:
            if ackP[IP].src == synP[IP].src and ackP[TCP].dport == synP[TCP].dport and ackP[IP].id == synP[IP].id + 1:
                acklist.remove(ackP)
                break
        else:        
		for element in floodList:		     
		        if element.destport == synP[TCP].dport:
				synPtime = datetime.datetime.fromtimestamp(int(synP.time))

				if element.compareTime(synPtime) == True:
					element.counter += 1
					if synP[IP].src not in element.IPs:
					    element.IPs.append(synP[IP].src)
					    break
		                    
				elif element.compareTime(synPtime) == False and element.counter >= 10:
		       			successfulFloods.append[element]
					floodList.remove(element)	 
		        		break

				else:                    
		       			floodList.remove(element)
					break
		else:
                	floodList.append(PInfo(synP[TCP].dport, datetime.datetime.fromtimestamp(int(synP.time)), datetime.datetime.fromtimestamp(int(synP.time)), 1, [synP[IP].src], None))

    for element in floodList:
        if element.counter >= 10:
            successfulFloods.append(element)
        
    for element in successfulFloods:    
        s+=("<!> There has been a SYNFLOOD attack on port: %d from the time: %s to the time %s, a total of %d SYN packets were sent with no ACK answers, The attacking IPs are:\n" % (element.destport, element.starttime.strftime('%Y-%m-%d %H:%M:%S'), element.lasttime.strftime('%Y-%m-%d %H:%M:%S'), element.counter))
        for aIP in element.IPs:
            s+=("    %s\n" % (aIP))
    print s


a = rdpcap('/tmp/SynFlood')
scan_syn(a)

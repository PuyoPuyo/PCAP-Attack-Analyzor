def scan_syn(packets):
    synflood_log = open("logs.txt", "a")
    synlist = take_sample(packets, 'TCP', "0x02", "!0x10") # 0x02 is a SYN flag, 0x10 is an ACK flag 
    acklist = take_sample(packets, 'TCP', "0x10", "!0x02")
    floodList = [] 
    successfulFloods = [] # list of all the successful syn flood attacks that have happened with all the information from a floodList value

    for synP in synlist:
        for ackP in acklist:
            if ackP[IP].src == synP[IP].src and ackP[TCP].dport == synP[TCP].dport and ackP[IP].id == synP[IP].id + 1:
                acklist.remove(ackP)
                break
        else:        
		for element in floodList:		     
		        if element.destport == synP[TCP].dport:
				synPtime = datetime.datetime.fromtimestamp(int(synP.time))

				if element.compareTime(synPtime):
					element.counter += 1
					if synP[IP].src not in element.IPs:
					    element.IPs.append(synP[IP].src)
					    break
		                    
				elif element.compareTime(synPtime) is False and element.counter >= 10:
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
        synflood_log.write("<!> There has been a SYNFLOOD attack on port: %d from the time: %s to the time %s, a total of %d SYN packets were sent with no ACK answers, The attacking IPs are:\n" % (element.destport, element.starttime.strftime('%Y-%m-%d %H:%M:%S'), element.lasttime.strftime('%Y-%m-%d %H:%M:%S'), element.counter))
        for aIP in element.IPs:
            synflood_log.write("    %s\n" % (aIP))



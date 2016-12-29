def scan_syn(packets):
    synflood_log = open("logs.txt", "a")
    synlist = take_sample(packets, 'TCP', "0x02", "!0x10") # 0x02 is a SYN flag, 0x10 is an ACK flag 
    acklist = take_sample(packets, 'TCP', "0x10", "!0x02")
    floodList = [] # [0] - dest port [1] - starting date + time of attack [2] - last attack attempt date + time [3] - counter for the amount of syn flood attempts [4] - IPs of all the attackers
    successfulFloods = [] # list of all the successful syn flood attacks that have happened with all the information from a floodList value

    for synP in synlist:
        for ackP in acklist:
            if ackP[IP].src == synP[IP].src and ackP[TCP].dport == synP[TCP].dport and ackP[IP].id == synP[IP].id + 1:
                acklist.remove(ackP)
                break
        else:        
            for x in xrange(len(floodList)):
		element = floodList[x]
                if element[0] == synP[TCP].dport:
			synPtime = datetime.datetime.fromtimestamp(int(synP.time))

			if synPtime.timetuple()[5] - element[2].timetuple()[5] <= 1 and \
				synPtime.timetuple()[1] == element[2].timetuple()[1] and \
					synPtime.timetuple()[2] == element[2].timetuple()[2] and \
						synPtime.timetuple()[3] == element[2].timetuple()[3] and \
							synPtime.timetuple()[4] == element[2].timetuple()[4]:
                       		# if less than two minutes have passed since the last attempted attack
				element = (element[0], element[1], synPtime, element[3] + 1, element[4])
				floodList[x] = element
                        	if synP[IP].src not in element[4]:
                            		element[4].append(synP[IP].src)
                        	break
                            
			if (synPtime.timetuple()[5] - element[2].tuple()[5] >= 1 or \
			synPtime.timetuple()[1] != element[2].tuple()[1] or \
			synPtime.timetuple()[2] != element[2].tuple()[2] or \
			synPtime.timetuple()[3] != element[2].tuple()[3] or \
			synPtime.timetuple()[4] != element[2].tuple()[4]) and \
				element[3] >= 10:  
                        # if more than two minutes have passed since the last attack and there were more than 10 attempts recently, classify as an attack that has happend
                        	successfulFloods.append[element]
				floodList.remove(element)	 
                        	break

			if (synPtime.timetuple()[5] - element[2].tuple()[5] >= 1 or \
			synPtime.timetuple()[1] != element[2].tuple()[1] or \
			synPtime.timetuple()[2] != element[2].tuple()[2] or \
			synPtime.timetuple()[3] != element[2].tuple()[3] or \
			synPtime.timetuple()[4] != element[2].tuple()[4]) and \
				element[3] < 10:                      
                        # if more than two minutes have passed since the last attack and there were less than 10 attempts recently, delete from the list of possible attacks            
                        	floodList.remove(element)
                        	break
            else:
                floodList.append((synP[TCP].dport, datetime.datetime.fromtimestamp(int(synP.time)), datetime.datetime.fromtimestamp(int(synP.time)), 1, [synP[IP].src]))

    for element in floodList:
        if element[3] >= 10:
            successfulFloods.append(element)
        
    for element in successfulFloods:    
        synflood_log.write("<!> There has been a SYNFLOOD attack on port: %d from the time: %s to the time %s, a total of %d SYN packets were sent with no ACK answers, The attacking IPs are:\n" % (element[0], element[1].strftime('%Y-%m-%d %H:%M:%S'), element[2].strftime('%Y-%m-%d %H:%M:%S'), element[3]))
        for aIP in element[4]:
            synflood_log.write("    %s\n" % (aIP))


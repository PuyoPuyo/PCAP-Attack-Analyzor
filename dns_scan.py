def dns_scan(packets):

	dnsamplification_log = open("logs.txt", "a")
	
	dnslist = take_sample(packets, "DNS")
	successful_amps = []
	rslist = []
	qrlist = []
	amp_info = None

	for packet in dnslist:
		if packet[DNS].qr == 0:
			qrlist.append(packet)
		else:
			rslist.append(packet)

	del dnslist[:]
	del dnslist
	
	for rsP in rslist:
		for qrP in qrlist:
			if rsP[IP].src == qrP[IP].dst and rsP[DNS].id == qrP[DNS].id:
				qrlist.remove(qrP)
				break
		else:
			rsPtime = datetime.datetime.fromtimestamp(int(rsP.time))
			if amp_info != None:
				if rsPtime.timetuple()[5] - amp_info[1].timetuple()[5] <= 1 and \
					rsPtime.timetuple()[1] == amp_info[1].timetuple()[1] and \
						rsPtime.timetuple()[2] == amp_info[1].timetuple()[2] and \
							rsPtime.timetuple()[3] == amp_info[1].timetuple()[3] and \
								rsPtime.timetuple()[4] == amp_info[1].timetuple()[4]:
					temp = (amp_info[0], rsPtime, amp_info[2]+1, amp_info[3], amp_info[4] + len(rsP)) 			
					amp_info = temp
					if rsP[IP].src not in amp_info[3]:
						amp_info[3].append(rsP[IP].src)

				if (rsPtime.timetuple()[5] - amp_info[1].tuple()[5] >= 1 or \
					rsPtime.timetuple()[1] != amp_info[1].tuple()[1] or \
					rsPtime.timetuple()[2] != amp_info[1].tuple()[2] or \
					rsPtime.timetuple()[3] != amp_info[1].tuple()[3] or \
					rsPtime.timetuple()[4] != amp_info[1].tuple()[4]) and \
						amp_info[2] >= 10:  
                        		# if more than two minutes have passed since the last attack and there were more than 10 attempts recently, classify as an attack that has happend
                        		successful_amps.append[amp_info]
					amp_info = None	 

				if (rsPtime.timetuple()[5] - amp_info[1].tuple()[5] >= 1 or \
				rsPtime.timetuple()[1] != amp_info[1].tuple()[1] or \
				rsPtime.timetuple()[2] != amp_info[1].tuple()[2] or \
				rsPtime.timetuple()[3] != amp_info[1].tuple()[3] or \
				rsPtime.timetuple()[4] != amp_info[1].tuple()[4]) and \
					amp_info[2] < 10:                      
 				# if more than two minutes have passed since the last attack and there were less than 10 attempts recently, delete from the list of possible attacks            
                        		amp_info = None
			else:
				amp_info = (rsPtime, rsPtime, 1, [rsP[IP].src], len(rsP))

	
	if amp_info[2] >= 10:
		successful_amps.append[amp_info]
        
	for element in successful_amps:    
		dnsamplification_log.write("<!> There has been a DNS AMPLIFICATION attack (on DNS port 53) from the time: %s to the time %s, a total of %d DNS response packets were sent with no queries, a total of %d bytes were sent, The responding IPs are:\n" % (element[0].strftime('%Y-%m-%d %H:%M:%S'), element[1].strftime('%Y-%m-%d %H:%M:%S'), element[2], element[4]))
		for aIP in element[3]:
            		dnsamplification_log.write("    %s\n" % (aIP))

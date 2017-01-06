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

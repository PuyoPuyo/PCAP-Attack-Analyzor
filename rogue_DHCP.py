def rogue_DHCP(packets):	

	rogueDHCP_log = open("logs.txt", "a")
	iplist = []
	dhcplist = take_sample(packets, "DHCP")
	for packet in dhcplist:
		if packet[DHCP].options[0][1] != 2:
		# if the packet type is not an offer
			dhcplist.remove(packet)
	for packet in dhcplist:
		if packet[IP].src not in iplist:
			iplist.append(packet[IP].src)
	if len(iplist) > 1:
		rogueDHCP_log.write("<?> There's most likely a rogue DHCP server in your network (more than one DHCP server), list of all the DHCP server IPs: ")
		for ip in iplist:
			rogueDHCP_log.write("	%s" %(ip))
			
	
	
	

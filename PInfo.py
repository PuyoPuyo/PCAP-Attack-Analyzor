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


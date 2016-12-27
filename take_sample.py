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

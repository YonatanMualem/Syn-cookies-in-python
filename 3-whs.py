from scapy.all import *
from queue import Queue
from threading import Thread
import os

from scapy.layers.inet import IP, TCP


PacketFilter = Queue()
AcceptQueue = Queue(1000)
OpenConnection = []
PORT = 8000

def Port_RST_Drop():
    '''
    Drop kernel auto RST responses to packets that come into a specific port
    :return: None
    '''
    os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 80 -j DROP")



class PacketsOrginize(Thread):
    '''
     Listen to all packets that coming through a specific port.
    '''
    def run(self):
        #Sniff tcp packets with specific port
        sniff(filter="tcp and dst port " + str(PORT), prn=self.PacketTransfer, store=0)

    def PacketTransfer(self, pkt):
        connction = {"IP":pkt["IP"].dst, "SPORT": pkt["TCP"].SPORT}
        #Check if the user already have a connection to the server
        if IP in pkt and connction in AcceptQueue.queue:
            #Send packet to start get data
            AcceptQueue.put(pkt)
        else:
            #Send packet to create 3 way handshake
            PacketFilter.put(pkt)



class PacketSplitter(Thread):
    def __init__(self):
        super().__init__()
        # Queue for handle all wait for ack
        self.SynQueue = Queue(1000)
        # Queue for handle all ACK packets
        self.AckQueue = Queue(1000)

    def SYNACK_create(self, packet):
        '''
        Create an syn-ack packet
        :param packet: syn scapy packet
        :return: syn-ack packet
        '''
        saddr = packet["IP"].src
        sport = packet["TCP"].sport
        dport = packet["TCP"].dport
        SeqNr = packet["TCP"].seq
        AckNr = packet["TCP"].seq + 1
        # Create syn-ack packet with scapy
        synack = IP(dst=saddr) / TCP(sport=dport, dport=sport, flags="SA", seq=SeqNr, ack=AckNr)
        return synack

    def run(self):
        '''
        Split between syn packets and ack packets
        :return: None
        '''
        while True:
            if not PacketFilter.empty():
                packet = PacketFilter.get()
                Flag = packet['TCP'].flags
                SYN = 0x02
                ACK = 0x10
                # Check if packet flag is SYN and the queue is full
                if Flag & SYN and not self.SynQueue.full():
                    packet = self.SYNACK_create(packet)
                    # Add packet to SynQueue (need to change description)
                    self.SynQueue.put(packet)
                elif Flag & ACK:
                    # Add packet to AckQueue (need to change description)
                    self.AckQueue.put(packet)


    def SynQueue(self):
        '''
        Goes over all backlog to check 2 things:
        1) If packet match to the ACK
        2) If the timer is below 75 seconds
        If only the first one so the 3 way handshake and the client is verified.
        else, check if the timer is below. If it's below continue to check each one. else delete the packet
        :return: None
        '''
        while True:
            # Check if AckQueue is empty
            if not self.AckQueue.empty():
                packet = self.AckQueue.get()
                # Check if ACK packet is match one in the SynQueue
                if packet in self.SynQueue.queue:
                    IP = packet["IP"].src
                    SPORT = packet["TCP"].sport
                    CompleteConnection = {"IP": IP, "SPORT": SPORT}
                    # Add packet to Established connections
                    AcceptQueue.put(CompleteConnection)
                    print("Connection established!! \n ip:", IP + "\n port:", SPORT)





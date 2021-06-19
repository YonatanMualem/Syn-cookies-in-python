import hashlib
import ipaddress
import queue
import secrets
from threading import *

from scapy.all import *
# Create global file for all functions
from scapy.layers.inet import IP, TCP

secret_key = [secrets.SystemRandom(), secrets.SystemRandom()]
count = 2
HOST = "192.168.1.41"
PORT = 8001
OpenConnection = []
SynCookieQueue = queue.Queue()
SocketPacketQueue = queue.Queue()
SynQueue = queue.Queue()
AckQueue = queue.Queue()


class ProxyServer(Thread):
    def run(self):

        print("Bind: " + HOST, str(PORT))
        sniff(filter="tcp and dst port " + str(PORT), prn=self.PacketTransfer, store=0)

    def PacketTransfer(self, pkt):
        if IP in pkt and pkt[IP].dst in OpenConnection:
            # print("Goes to the socket server")
            SocketPacketQueue.put(pkt)
        else:
            # print("IP not verified, need verifcation", "\n Going to syn-cookies analyzer")
            SynCookieQueue.put(pkt)


class SynCookie(threading.Thread):
    def run(self):
        while True:
            if not SynCookieQueue.empty():
                packet = SynCookieQueue.get()
                Flag = packet['TCP'].flags
                SYN = 0x02
                ACK = 0x10
                if Flag & SYN:
                    SynQueue.put(packet)
                elif Flag & ACK:
                    AckQueue.put(packet)
            time.sleep(0.01)


def cookie_hash(saddr, daddr, sport, dport, count, c):
    special = (int(ipaddress.IPv4Address(saddr)), int(ipaddress.IPv4Address(daddr)), sport, dport, count, secret_key[c])
    return hashlib.sha1(special)


class CreateSYNACK(threading.Thread):

    def run(self):
        while True:
            if not SynQueue.empty():
                packet = SynQueue.get()
                print("Syn!!!")

                saddr = packet["IP"].src
                daddr = packet["IP"].dst
                sport = packet["TCP"].sport
                dport = packet["TCP"].dport
                sseq = packet["TCP"].seq
                MSS = 1480

                H1 = cookie_hash(saddr, daddr, str(sport), str(dport), 0, 0)
                H2 = cookie_hash(saddr, daddr, str(sport), str(dport), count, 1)

                ISN_destination = H1 + sseq + (count * 2 ^ 24) + (H2 + MSS) % 2 ^ 24
                print(ISN_destination)
                Syn_Ack_packet = IP(dst=saddr) / TCP(sport=dport, dport=sport, flags="SA", seq=ISN_destination,
                                                     ack=sseq + 1,
                                                     options=[('MSS', 1460)])
                # print(bytescookie.hexdigest())
                send(Syn_Ack_packet)

            time.sleep(0.01)


class AnalyzeAckPacket(threading.Thread):
    def run(self):

        while True:
            if not AckQueue.empty():
                packet = AckQueue.get()
                # print("ACK!!!!!!!!")
                saddr = packet["IP"].src
                daddr = packet["IP"].dst
                sport = packet["TCP"].sport
                dport = packet["TCP"].dport
                SEQ = packet["TCP"].seq
                ACK = packet["TCP"].ack
                ISN_desination = ACK - 1
                ISN_source = SEQ - 1

                H1 = cookie_hash(saddr, daddr, str(sport), str(dport), 0, 0)
                H2 = cookie_hash(saddr, daddr, str(sport), str(dport), count, 1)
                count = (ISN_desination - int(H1.hexdigest()) - ISN_source) / 2 ^ 24
                MSS = (ISN_desination - int(H1.hexdigest()) - ISN_source) % 2 ^ 24 - int(H2.hexdigest()) % 2 ^ 24
                # print(" ack!!!")

            time.sleep(0.01)


a = CreateSYNACK()
b = AnalyzeAckPacket()
test = ProxyServer()
test1 = SynCookie()

test1.start()
test.start()
b.start()
a.start()

import time
from scapy.all import *
from utils import *

class Session:

    def __init__(self, pak) -> None:
        self.st = pak
        self.length = 0
        self.mark = [pak]

    @property
    def client(self):
        return (self.mark[0][IP].src, self.mark[0][TCP].sport)

    @property
    def server(self):
        return (self.mark[0][IP].dst, self.mark[0][TCP].dport)
    
    @property
    def time(self):
        return self.mark[0].time

    def get_dir(self, o):
        if (o[IP].src, o[TCP].sport) == self.client:
            assert (o[IP].dst, o[TCP].dport) == self.server
            return 'receiving'
        elif (o[IP].src, o[TCP].sport) == self.server:
            assert (o[IP].dst, o[TCP].dport) == self.client
            return 'sending'
        else:
            raise RuntimeError('frame not in session')

    def try_append(self, o: object) -> bool:
        # if o[IP].src in self.magic and o[IP].dst in self.magic \
        #     and o[TCP].sport in self.magic and o[TCP].dport in self.magic:
        if not tuple_eq(self.st, o):
            return False
        d = self.get_dir(o)
        for i in reversed(self.mark):
            if d != self.get_dir(i):
                last_packet = i
                break
        else:
            return False
        if last_packet[TCP].flags == 'S' and o[TCP].flags == 'SA':
            if last_packet[TCP].seq + 1 != o[TCP].ack:
                return False
            self.mark.append(o)
            return True
        if not (last_packet[TCP].ack <= o[TCP].seq <= last_packet[TCP].ack+last_packet[TCP].window):
            return False
        self.mark.append(o)
        return True

    def show(self):
        print(len(self.mark))
        for pkt in self.mark:
            if Raw in pkt:
                hexdump(raw(pkt[Raw]))

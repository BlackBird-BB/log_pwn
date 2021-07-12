from scapy.all import *
class Session:

    def __init__(self, pak) -> None:
        # Initial a Session class with a SYN pcap Fram
        self.st = pak
        self.length = 0
        self.mark = [pak]

    @property
    def client(self):
        # client of this session
        return (self.mark[0][IP].src, self.mark[0][TCP].sport)

    @property
    def server(self):
        # server of this session
        return (self.mark[0][IP].dst, self.mark[0][TCP].dport)
    
    @property
    def time(self):
        # time of this session
        return self.mark[0].time

    @property
    def info(self):
        # infomation of this session with time(lasting), client, server
        return f'''\033[0;37;40mInformation:
Time: {str_time(self.mark[0].time)} —— 
          {str_time(self.mark[-1].time)} 
Server: {self.mark[0][IP].dst}:{self.mark[0][TCP].dport}
Contestant: {self.mark[0][IP].src}:{self.mark[0][TCP].sport}\033[0m
'''
    def get_dir(self, o):
        # get the diretion of current frame
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
        # print every frame of this session in hex 
        print(len(self.mark))
        for pkt in self.mark:
            if Raw in pkt:
                hexdump(raw(pkt[Raw]))
    
    def __str__(self) -> str:
        dialog = f''''''
        for j in self.mark:
            if Raw in j:
                if j[IP].src == session.client[0]:
                    dialog = dialog + \
                        f"\033[0;31;40mContestant:\n{hexdump(raw(j[Raw]))}\033[0m\n"
                else:
                    dialog = dialog + \
                        f"\033[0;34;40mServer:\n{hexdump(raw(j[Raw]))}\033[0m\n"
        return self.info + dialog

def parse(file):
    # divide the pcap into sessions
    ses = []
    pac = rdpcap(file)
    for i in range(len(pac)):
        for s in ses:
            if s.try_append(pac[i]):
                break
        else:
            if pac[i][TCP].flags == 'S':
                s = Session(pac[i])
                ses.append(s)
            else:
                print('warning: no suitable session found')
    return ses
def tuple_eq(pa, pb):
    a = {(pa[IP].src, pa[TCP].sport), (pa[IP].dst, pa[TCP].dport)}
    b = {(pb[IP].src, pb[TCP].sport), (pb[IP].dst, pb[TCP].dport)}
    return a == b

def hexdump(data, length=16):
    # Display via gdb
    filter = ''.join([
        (len(repr(chr(x))) == 3) and chr(x)
        or '.' for x in range(256)
    ])
    lines = []
    digits = 4 if isinstance(data, str) else 2
    for c in range(0, len(data), length):
        chars = data[c:c + length]
        hex = ' '.join(["%0*x" % (digits, (x)) for x in chars])
        printable = ''.join([
            "%s" % (((x) <= 127 and filter[(x)]) or '.')
            for x in chars
        ])
        lines.append("%04x  %-*s | %s\n" % (c, length * 3, hex, printable))
    return ''.join(lines)
def check(tmp):
    if b'Enjoy' in raw(tmp[3][Raw]):
        return 8
    else:
        return 16

def str_time(tm):
    # Transform timestamp into time
    return time.strftime("%Y-%m-%d %H:%M:%S",
        time.localtime(float(tm)))

if __name__ == '__main__':
    name = input("Input the name: ")
    ses = parse(name)
    for i in range(len(ses)):
        session = ses[i]
        print(f"\033[1;37;40mSession {i}\033[0m")
        print(session)

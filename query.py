import bisect
import redis
import pickle
from colorama import init, Fore, Style
from utils import *
from scapy import *
from lib import Session

conn = redis.Redis('1.117.139.210')
count = int(conn.get('count') or 0)

def check(tmp):
    if b'Enjoy' in raw(tmp[3][Raw]):
        return 8
    else:
        return 16

class remote_list(object):
    def __len__(self):
        return int(conn.get('count') or 0)

    def __getitem__(self, index):
        data = conn.get(f'log_{index}')
        return float(data[:data.index(b'|')])


start_time, end_time = map(float, input(
    "Please input start time and end time in timestamp devided by a space: ").split())
l = remote_list()
start_log = bisect.bisect(l, start_time)
end_log = bisect.bisect_right(l, end_time)

cnt = 1
init(autoreset=True)
# port = int(input('Please input port: '))
# ip = input('Please input ip: ')
for i in range(start_log, end_log):
    data = conn.get(f'log_{i}')
    session = pickle.loads(data[data.index(b'|') + 1:])
    # if port != -1 and session.server[1] != port:
        # continue
    # if ip != "all" and session.server[0] != ip:
    #     continue

    print(Style.BRIGHT+f"Session {cnt}")
    tmp = time.strftime("%Y-%m-%d %H:%M:%S",
                        time.localtime(float(session.mark[0].time)))
    print(f'''{Style.DIM}Time:{tmp}
Information:
Server: {session.mark[0][IP].dst}:{session.mark[0][TCP].dport}
Contestant: {session.mark[0][IP].src}:{session.mark[0][TCP].sport}
'''
)
    x = check(session.mark)
    for j in session.mark:
        if Raw in j:
            if j[IP].src == session.client[0]:
                print(Fore.RED+ f"Contestant:\n{hexdump(raw(j[Raw]), x)}")
            else:
                print(Fore.BLUE+ f"Server:\n{hexdump(raw(j[Raw]), x)}")
    cnt = cnt+1

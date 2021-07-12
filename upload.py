import pickle
import redis
from parse import parse

conn = redis.Redis('1.117.139.210')

for i in parse('multi.pcap'):
    count = int(conn.get('count') or 0)
    data = str(i.time).encode() + b'|' + pickle.dumps(i)
    conn.set(f'log_{count}', data)
    conn.set('count', str(count+1))

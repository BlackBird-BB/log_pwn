from scapy.utils import rdpcap
from scapy.all import *
from lib import Session


def parse(file):
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

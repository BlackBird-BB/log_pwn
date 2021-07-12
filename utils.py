from scapy.all import *

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

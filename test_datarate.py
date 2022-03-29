from scapy.all import *
from collections import Counter

interface = "eth0"
sample_interval = 60

traffic = Counter()
hosts={}

def size_check(num):
    for x in ['','K', 'M', 'G', 'T']:
        if num < 1024.: return "%3.1f %sB" % (num, x)
        num /=1024.
        return "3.1f PB" % (num)

def traffic_monitor_callback(pkt):
    if IP in pkt:
        pkt = pkt[IP]
        traffic.update({tuple(sorted(map(atol, (pkt.src, pkt.dst)))): pkt.len})

sniff(iface=interface, prn=traffic_monitor_callback,timeout=sample_interval, store=False)

for(h1,h2), total in traffic.most_common():
    h1, h2 = map(ltoa, (h1,h2))
    for host in (h1,h2):
        if host not in hosts:
            try:
                rhost = socket. gethostbyaddr(host)
                hosts[host] = rhost[0]
            except:
                hosts[host] = None

    h1 = "%s (%s)" % (hosts[h1], h1) if hosts[h1] is not  None else h1
    h2 = "%s (%s)" % (hosts[h2], h2) if hosts[h2] is not None else h2
    print("%s/s: %s - %s" % (size_check(float(total)/sample_interval), h1, h2))
    print("Try num: %s" %(total))
    print("자영바보")
    

from scapy.all import *
from collections import Counter

sample_interval = 60
protocols={1:'icmp', 6:'tcp', 17'udp'}

traffic = Counter()
hosts={}

def size_check(num):
    for x in ['','K', 'M', 'G', 'T']:
        if num < 1024.: return "%3.1f %sB" % (num, x)
        num /=1024.
        return "3.1f PB" % (num)

def traffic_monitor_callback(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        porto = pkt[IP].proto
        time = pkt[IP].time
        ttl = pkt[IP].ttl
        length = pkt[IP].len
        src_mac = packet[0][0].src
        dst_mac = packet[0][0].dst
    
        if proto in protocols:
            if proto == 1:
                message_type = pkt[ICMP].type
                code = pkt[ICMP].code
                traffic.update({tuple(sorted(map(atol, (pkt.src, pkt.dst)))): pkt.len})
                
            if proto == 6:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                seq = pkt[TCP].seq
                ack = pkt[TCP].ack
                flag = pkt[TCP].flags

            if proto == 17:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                udp_lenght = pkt[UDP].len

        traffic.update({tuple(sorted(map(atol, (pkt.src, pkt.dst)))): pkt.len})

sniff(prn=traffic_monitor_callback,timeout=sample_interval, store=False)

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
    

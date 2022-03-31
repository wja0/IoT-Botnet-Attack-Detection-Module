import pcap
from pwn import *

sniffer = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)
sniffer.setfilter("tcp and udp")

for ts, pkt in sniffer:
    pkts = u32(pkt[0:4])
    if(pkts != int(hex(0xFFFFFFFF),16)):
        print('Dst MAC - ', end='', flush=True)
        print(':'.join('%02X' % i for i in pkt[0:6]))
        print('Src MAC - ', end='', flush=True)
        print(':'.join('%02X' % i for i in pkt[6:12]))
        print('Ether type - ', end='', flush=True)
        print(':'.join('%02X' % i for i in pkt[12:14]))
        print('IP ver - ', end='', flush=True)
        print(':'.join('%02X' % i for i in pkt[14:15]))
        print('IP Header length - ', end='', flush=True)
        print(':'.join('%02X' % i for i in pkt[15:16]))
        print('ToS - ',end='',flush=True)
        print(':'.join('%02X' % i for i in pkt[16:18]))
        print('Total Length - ',end='',flush=True)
        print(':'.join('%02X' % i for i in pkt[18:22]))
        print('Identification - ',end='',flush=True)
        print(':'.join('%02X' % i for i in pkt[22:26]))
        print('Fragment Offset - ',end='',flush=True)
        print(':'.join('%02X' % i for i in pkt[26:30]))
        print('TTL(Time To Live) - ',end='',flush=True)
        print(':'.join('%02X' % i for i in pkt[30:32]))
        print('Protocol - ',end='',flush=True)
        print(':'.join('%02X' % i for i in pkt[32:34]))
        print('Header Checksum - ',end='',flush=True)
        print(':'.join('%02X' % i for i in pkt[34:38]))
        print('Source Address - ',end='',flush=True)
        print(':'.join('%02X' % i for i in pkt[38:46]))
        print('Destination Address - ',end='',flush=True)
        print(':'.join('%02X' % i for i in pkt[46:54]))
       
        print('%s\t'%str(pkt))
        if (pkt[32:34] == b'/x06/x00'):
            print("!")


















        #print('IP Option - ',end='',flush=True)
        #print(':'.join('%02X' % i for i in pkt[54:62]))
         
        #print('Protocol - ',end='',flush=True)
        #print(':'.join('%02X' % i for i in pkt[32:34]))

        print()

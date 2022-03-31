import sys
from scapy.all import *
import time

count = 1
protocols={1:'icmp', 6:'tcp', 17:'udp'}
#protocol_type = input("Protocol Type: ")
#sniffing_time = input("Sniffing Time: ")

def sniffing():
    print("Sniffing Start")
    try:
        pcap_file = sniff(prn=showPacket, filter='ip')
    except:
        print("skip packet")
    print("Finish Capture Packet")
    if count == 1:
        print("No Packet")
        sys.exit()
    else:
        print("Total Packet: %s" %(count-1))
        #file_name = input("Enter File Name: ")
        #wrpcap(str(file_name), pacp_file)


def showPacket(packet):
    global count
    

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    time = packet[IP].time
    ttl = packet[IP].ttl
    length = packet[IP].len
    src_mac = packet[0][0].src
    dst_mac = packet[0][0].dst

    if proto in protocols:
        if proto == 1:
            message_type = packet[ICMP].type
            code = packet[ICMP].code

            print("pacekt number: %s protocol : %s" %(count, protocols[proto].upper()))
            print("src: %s -> dst: %s TTL: %s" %(src_ip, dst_ip, ttl))
            print("src_mac: %s -> dst_mac: %s" %(src_mac,dst_mac))
            print("type: %s code: %s" %(message_type, code))
            print('\n')

        if proto == 6:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            seq = packet[TCP].seq
            ack = packet[TCP].ack
            flag = packet[TCP].flags

            print("packet number: %s protocol: %s"%(count, protocols[proto].upper()))
            print("src: %s -> dst: %s" %(src_ip, dst_ip))
            print("src_mac: %s -> dst_mac: %s" %(src_mac,dst_mac))
            print("TTL: %s Length: %s" %(ttl, length))
            print("sport: %s dport: %s" %(sport, dport))
            print("seq: %s ack: %s flag: %s" %(seq, ack, flag))
            print('\n')

        if proto == 17:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            udp_length = packet[UDP].len
            print("packet number: %s protocol: %s"%(count, protocols[proto].upper()))
            print("src: %s -> dst: %s TTL: %s" %(src_ip, dst_ip,ttl))
            print("src_mac: %s -> dst_mac: %s" %(src_mac,dst_mac))
            print("sport: %s dport: %s Packet Length: %s" %(sport, dport,udp_length))
            print("time: %s data rate: %s" %(time, length/time))
            print('\n')
        if proto == 41:
            print("packet number: %s protocol: %s"%(count, protocols[proto].upper()))
            print("src: %s -> dst: %s TTL: %s" %(src_ip, dst_ip,ttl))
            print("src_mac: %s -> dst_mac: %s" %(src_mac,dst_mac))
        count += 1

            
#if protocol_type in protocols.values():
#    sniffing()
#else:
#    print("Unsupported Format")
sniffing()

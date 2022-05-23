

from scapy.all import *
from collections import Counter
import pandas as pd
import csv
from dataclasses import dataclass

@dataclass
class Time_cls:
    src_ip:str = '-1.-1.-1.-1'
    dst_ip:str = '-1.-1.-1.-1'
    sport:str = '-1'
    dport:str = '-1'
    s_time:float = 0
    l_time:float = 0

protocols={6:'tcp', 17:'udp', 47:'gre'}
time_check = []
traffic = Counter()
src_traffic = Counter()
dst_traffic = Counter()



def traffic_monitor_callback(pkt):
    if IP in pkt:
        proto = pkt[IP].proto #protocol
        attack = '?'
        
        if proto not in protocols: # This is not attack of Mirai
            return
        
        src_ip = pkt[IP].src #saddr
        dst_ip = pkt[IP].dst #daddr
        host_ip = get("https://api.ipify.org").text
        
        if src_ip != host_ip and dst_ip != host_ip:
            return 
        
        time = pkt[IP].time # time_atr
        length = pkt[IP].len #length
        src_mac = pkt[0][0].src #smac
        dst_mac = pkt[0][0].dst #dmac
        sport = str(0)
        dport = str(0)
        flag = 0
        flags = 0
            
        try:
            a = pkt[DNS]
            # get a domain addr
            dns = 1
        except:
            dns = 0
            
        if proto == 6:
            sport = str(pkt[TCP].sport)
            dport = str(pkt[TCP].dport)
            proto = 'tcp'
            flag = pkt[TCP].flags
            
        if proto == 17:
            try:
                sport = str(pkt[UDP].sport)
            except:
                sport = str(0)

            try:
                dport = str(pkt[UDP].dport)
            except:
                sport = str(0)
            proto = 'udp'
                
        if proto == 47:
            flag = pkt[GRE].flags
            proto = 'gre'

        src_traffic.update({tuple(src_ip)}) # get conn_p_src_ip
        dst_traffic.update({tuple(dst_ip)}) # get conn_p_dst_ip
        check_time(src_ip, dst_ip, dport, time) # get time and datarate
        flags =  flag_to_int(flag)
        
        traffic.update({tuple(map(str, (src_ip, dst_ip, proto, src_mac, dst_mac, sport, dport, flags, dns, attack))): length})
        print(src_ip," ", dst_ip, " ",proto, " ",src_mac, " ",dst_mac, " ",sport, " ",dport, " ",flags, " ",dns," ", attack)

def flag_to_int(flag):
    flags = 0
    if 'U' in str(flag):
        flags += 32
    if 'A' in str(flag):
        flags += 16
    if 'P' in str(flag):
        flags += 8
    if 'R' in str(flag):
        flags += 4
    if 'S' in str(flag):
        flags += 2
    if 'F' in str(flag):
        flags += 1
    return flags

def add_n_in(df, scan_time):
    time = 1
    for(h1, h2, proto, src_mac, dst_mac, sport, dport, flag,dns, attack), total in traffic.most_common(): # except broadcast
        if src_mac == 'ff:ff:ff:ff:ff:ff' : 
            continue
        elif dst_mac == 'ff:ff:ff:ff:ff:ff':
            continue

        for (src_h), num_s  in src_traffic.most_common(): # save conn_p_src_ip in tuple
            if ''.join(src_h) == h1:
                temp_s = num_s
                break
            
        for (dst_h), num_s in dst_traffic.most_common(): # save conn_p_dst_ip in tuple
            if ''.join(dst_h) == h2:
                temp_d = num_s
                break
            
        for i in time_check: # save tine in tuple
            if(i.src_ip == h1) and (i.dst_ip == h2) and (i.dport == dport):
                if i.s_time == i.l_time:
                   time = 1
                else : 
                    time = i.l_time - i.s_time
                break

        data = pd.DataFrame({'saddr': [h1], 'daddr' : [h2], 'proto' : [proto], 'src_mac' : [src_mac], 'dst_mac' : [dst_mac], 'sport' : [sport], 'dport':[dport], 'flag':[flag], 'N_IN_Conn_P_SrcIP':[temp_s], 'N_IN_Conn_P_DstIP':[temp_d], 'length' :[total] , 'time' : [time], 'datarate' : [total/time], 'dns':[dns], 'category' : [attack]})
        df = pd.concat([df,data], ignore_index=True)
    return df

def init_traffic():
    global traffic
    global src_traffic
    global dst_traffic
    traffic = Counter()
    src_traffic = Counter()
    dst_traffic = Counter()
    tmp = Time_cls()
    time_check.append(tmp)

def do_sniff(scan_time):
    df = pd.DataFrame(columns=['saddr', 'daddr', 'proto', 'src_mac', 'dst_mac', 'sport', 'dport', 'flag', 'N_IN_Conn_P_SrcIP', 'N_IN_Conn_P_DstIP', 'length', 'time', 'datarate','dns', 'category'])
    sniff(iface="br0",prn=traffic_monitor_callback, timeout = scan_time, store=False)
    df = add_n_in(df, scan_time)
    
    return df

def write_csv(df, PATH):
    df.to_csv(PATH, index=False)

def check_time(src_ip, dst_ip, dport, n_time):
    for i in time_check:
        if (i.src_ip == src_ip) and (i.dst_ip == dst_ip) and (i.dport == dport):
            i.l_time = n_time
            return 0
    temp = Time_cls()
    temp.src_ip = src_ip
    temp.dst_ip = dst_ip
    temp.dport = dport
    temp.s_time = n_time
    temp.l_time = n_time
    time_check.append(temp)

    return 0

def scan_data():
    init_traffic()
    sc_time_one = 600
    train_df = do_sniff(sc_time_one)
    write_csv(train_df, './nomal_traffic_cate.csv')
                

if __name__ == "__main__":
    init_traffic()
    sc_time_one = 600
    train_df = do_sniff(sc_time_one)
    write_csv(train_df, './nomal_traffic_cate.csv')

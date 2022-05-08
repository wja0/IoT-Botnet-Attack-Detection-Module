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

protocols={1:'icmp',2:'igmp', 6:'tcp', 17:'udp', 47:'gre', 89:'ospfigp'}
test_PATH = r'../dataset/testData.csv'
train_PATH = r'../dataset/trainData.csv'
new_train_PATH = r'../dataset/newTrainData.csv'
new_test_PATH = r'../dataset/newTestData.csv'
time_check = []
traffic = Counter()
src_traffic = Counter()
dst_traffic = Counter()




def size_check(num):
    try:
        for x in ['','K', 'M', 'G', 'T']:
            if num < 1024.: return "%3.1f %sB" % (num, x)
            num /=1024.
            return "3.1f PB" % (num)
    except:
        return "0 B";

def traffic_monitor_callback(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src #saddr
        dst_ip = pkt[IP].dst #daddr
        proto = pkt[IP].proto #protocol
        time = pkt[IP].time # time_atr
        length = pkt[IP].len #length
        src_mac = pkt[0][0].src #smac
        dst_mac = pkt[0][0].dst #dmac
        attack = 'scan' # delete in later
        sport = str(0)
        dport = str(0)
        flag = 0
        flags = 0

        if ("210.117.181.96" not in str(src_ip)) or ("210.117.181.86" not in str(dst_ip)):
            if ("210.117.181.96" not in str(dst_ip)) or ("210.117.181.86" not in str(src_ip)):
                return
        
        try:
            a = pkt[DNS]
            dns = 1
        except:
            dns = 0
        
        if proto in protocols:
            if proto == 1:
                proto = 'icmp'
            if proto == 2:
                proto = 'igmp'
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
                proto = 'gre'
            if proto == 89:
                proto = 'ospfigp'


        src_traffic.update({tuple(src_ip)})
        dst_traffic.update({tuple(dst_ip)})
        check_ip(src_ip, dst_ip, dport, time)
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
        
        traffic.update({tuple(map(str, (src_ip, dst_ip, proto, src_mac, dst_mac, sport, dport, flags, dns, attack))): length})
        print(src_ip," ", dst_ip, " ",proto, " ",src_mac, " ",dst_mac, " ",sport, " ",dport, " ",flags, " ",dns," ", attack)
    #else:
    #    print(pkt)

def add_n_in(df, scan_time):
    time = 1
    for(h1, h2, proto, src_mac, dst_mac, sport, dport, flag,dns, attack), total in traffic.most_common():
        if src_mac == 'ff:ff:ff:ff:ff:ff' : 
            continue
        elif dst_mac == 'ff:ff:ff:ff:ff:ff':
            continue

        for (src_h), num_s  in src_traffic.most_common():
            if ''.join(src_h) == h1:
                temp_s = num_s
                break
        for (dst_h), num_s in dst_traffic.most_common():
            if ''.join(dst_h) == h2:
                temp_d = num_s
                break
        for i in time_check:
            if(i.src_ip == h1) and (i.dst_ip == h2) and (i.dport == dport):
                if i.s_time == i.l_time:
                   time = 1
                else : 
                    time = i.l_time - i.s_time
                break

        data = pd.DataFrame({'saddr': [h1], 'daddr' : [h2], 'proto' : [proto], 'src_mac' : [src_mac], 'dst_mac' : [dst_mac], 'sport' : [sport], 'dport':[dport], 'flag':[flag], 'N_IN_Conn_P_SrcIP':[temp_s], 'N_IN_Conn_P_DstIP':[temp_d], 'length' :[total] , 'time' : [time], 'datarate' : [total/time], 'dns':[dns], 'category' : [attack]})
        df = pd.concat([df,data], ignore_index=True)
    return df

def load_csv(PATH):
    df_csv = pd.read_csv(PATH)
    return df_csv

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
    hosts={}
    df = pd.DataFrame(columns=['saddr', 'daddr', 'proto', 'src_mac', 'dst_mac', 'sport', 'dport', 'flag', 'N_IN_Conn_P_SrcIP', 'N_IN_Conn_P_DstIP', 'length', 'time', 'datarate','dns', 'category'])
    sniff(iface="br0",prn=traffic_monitor_callback, timeout = scan_time, store=False)
    df = add_n_in(df, scan_time)
    
    return df

def write_csv(df, PATH):
    df.to_csv(PATH, index=False)

def check_ip(src_ip, dst_ip, dport,  n_time):
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


                

if __name__ == "__main__":
    #train_df = load_csv(train_PATH)
    #test_df= load_csv(test_PATH)
    init_traffic()
    sc_time_one = 600
#    sniff(prn=traffic_monitor_callback,filter='ip',timeout=sc_time_one, store=False)
    train_df = do_sniff(sc_time_one)
    write_csv(train_df, './nomal_traffic_cate.csv')

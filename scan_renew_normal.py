from scapy.all import *
from collections import Counter
import pandas as pd
import csv
from dataclasses import dataclass
from requests import get


class Traffic_info:
    ip:str = ''
    mac:str = ''
    t_port:int = -1 #transfer port, just check
    d_port:int = -1 #dynamic port, just check
    weak_port:int = -1
    proto:str = ''
    len_flag:str = ''
    total_length:int= 0
    time:float = 1
    datarate:float = 1
    cnt:int = 0
    s_time:float = 0
    l_time:float = 0
    
    def __init__(self, ip, mac, t_port, d_port, proto, weak_port, len_flag, total_length,s_time, l_time):
        self.ip = ip
        self.mac = mac
        self.t_port = t_port
        self.d_port = d_port
        self.weak_port = weak_port
        self.proto = proto
        self.len_flag = len_flag
        self.total_length = total_length
        self.s_time = s_time
        self.l_time = l_time
        self.time = 1
        self.datarate= 1
        self.cnt = 1
    
    def getNetInfo(self):
        return self.ip, self.mac, self.t_port,self.d_port, self.proto
    
    def getAllInfo(self):
        return self.ip, self.mac, self.t_port,self.d_port, self.proto, self.weak_port, self.len_flag, self.total_length, self.time, self.datarate, self.cnt 
    
    def setCount(self):
        self.cnt = self.cnt + 1
    
    def setTotalLength(self, length):
        self.total_length = self.total_length + length
    
    def setLenFlag(self, flags, length):
        self.len_flag = self.len_flag + '>' + str(flags) + '(' + str(length)  + ')'
        
    def setLastTime(self, l_time):
        self.l_time = l_time
    
    def setTimeValue(self):
        self.time = self.l_time - self.s_time
        self.datarate = self.total_length / self.time
        
    

weak_ports = [22, 23, 2323, 80, 81, 5555, 7574, 8080, 8443, 37215, 49152, 52869]
protocols={6:'tcp', 17:'udp'}
time_check = []
traffic = Counter()
src_traffic = Counter()
dst_traffic = Counter()
cnt_traffic = []



def traffic_monitor_callback(pkt):
    if IP in pkt:
        proto = pkt[IP].proto #protocol
        src_ip = pkt[IP].src #saddr
        dst_ip = pkt[IP].dst #daddr
        host_ip = '210.117.181.96'
        #host_ip = get("https://api.ipify.org").text
        
        if proto not in protocols:
            return
        
        if str(src_ip) not in host_ip:
            if str(dst_ip) not in host_ip:
                return 
        
        time = pkt[IP].time # time_atr
        length = pkt[IP].len #length
        src_mac = pkt[0][0].src #smac
        dst_mac = pkt[0][0].dst #dmac
        sport = 0
        dport = 0
        flags = 0
        
        if proto == 6:
            try:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            except:
                sport = 0
                dport = 0
                
            proto = 'tcp' #tcp
            flags = flag_to_int(pkt[TCP].flags)
            
        elif proto == 17:
            try:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            except:
                sport = 0
                dport = 0
                
            proto = 'udp'
            
        if (sport in weak_ports) or (dport in weak_ports):
            weak_port = 1
        else :
            weak_port = 0
            
        if str(src_ip) in host_ip:
            check_traffic_cls(dst_ip, dst_mac, dport, sport, proto, weak_port, flags, length, time)
        else :
            check_traffic_cls(src_ip, src_mac, sport, dport, proto, weak_port, flags, length, time)
            
        print(src_ip," ", dst_ip, " ",proto, " ",src_mac, " ",dst_mac, " ",sport, " ",dport, " ",flags, " ", length)

def check_traffic_cls(ip, mac, t_port, d_port, proto, weak_port, flags, length,time):
    exist = 0 
    for i in cnt_traffic:
        (tmp_ip, tmp_mac, tmp_t_port, tmp_d_port, tmp_proto) = i.getNetInfo()
        if (tmp_ip, tmp_mac, tmp_t_port, tmp_d_port, tmp_proto) == (ip, mac, t_port, d_port, proto):
            exist = 1
            i.setCount()
            i.setTotalLength(length)
            i.setLenFlag(flags, length)
            i.setLastTime(time)
            break
    
    if exist == 0:
        len_flag = str(flags)+'('+str(length)+')'
        total_length = length
        s_time = time
        l_time = time + 1 # Preventing division by zero
        tmp_traffic_cls = Traffic_info(ip, mac, t_port, d_port, proto, weak_port, len_flag, total_length, s_time, l_time)
        cnt_traffic.append(tmp_traffic_cls)



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

def add_n_in(df):
    for i in cnt_traffic: 
        i.setTimeValue()
        tmp_ip, tmp_mac, tmp_t_port, tmp_d_port, tmp_proto, tmp_weak_port, tmp_len_flag, tmp_total_length, tmp_time, tmp_datarate, tmp_cnt = i.getAllInfo()
        
        if tmp_mac == 'ff:ff:ff:ff:ff:ff' : # except broadcast
            continue

        data = pd.DataFrame({'ip':[tmp_ip], 'mac':[tmp_mac], 't_port':[tmp_t_port], 'd_port':[tmp_d_port], 'weak_port':[tmp_weak_port], 'proto':[tmp_proto], 'len_flag':[tmp_len_flag], 'total_length':[tmp_total_length], 'time':[tmp_time],'datarate':[tmp_datarate], 'cnt':[tmp_cnt], 'attack':[0]})
        print(tmp_ip,' ',tmp_mac, ' ',tmp_t_port, ' ' ,tmp_proto, ' ',tmp_weak_port, ' ',tmp_len_flag, ' ',tmp_total_length, ' ',tmp_time, ' ',tmp_datarate, ' ',tmp_cnt)
        df = pd.concat([df,data], ignore_index=True)
    return df

def init_traffic():
    global cnt_traffic
    cnt_traffic = []

def do_sniff(scan_time):
    df = pd.DataFrame(columns=['ip', 'mac', 't_port', 'd_port', 'weak_port', 'proto', 'len_flag', 'total_length', 'time','datarate', 'cnt', 'attack'])
    sniff(iface="br0",prn=traffic_monitor_callback, timeout = scan_time, store=False)
    df = add_n_in(df)
    
    return df

def write_csv(df, PATH):
    df.to_csv(PATH, index=False)



def scan_data():
    init_traffic()
    sc_time_one = 600
    df = do_sniff(sc_time_one)
    return df

if __name__ == "__main__":
    df = scan_data()
    write_csv(df, './normal_traffic.csv')   


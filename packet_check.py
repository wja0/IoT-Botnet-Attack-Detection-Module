from scapy.all import *
from collections import Counter
import pandas as pd
import csv


sample_interval = 10
protocols={1:'icmp', 6:'tcp', 17:'udp'}
test_PATH = r'./testData.csv'
train_PATH = r'./trainData.csv'

traffic = Counter()
src_traffic = Counter()
hosts={}
dst_traffic = Counter()
#data = {'src_ip': ['init'], 'dst_ip' : ['init'], 'proto' : ['init'], 'src_mac' : ['init'], 'dst_mac' : ['init'], 'sport' : ['init'], 'dport':['init'], 'flag':['init'], 'ack':['init'], 'n_in_src':[0], 'n_in_dst':[0], 'rate':[0]}
df = pd.DataFrame(columns=['saddr', 'daddr', 'proto', 'src_mac', 'dst_mac', 'sport', 'dport', 'flag', 'n_in_src', 'n_in_dst', 'srate', 'length', 'seq','attack','category','subcategory'])

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
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        length = pkt[IP].len
        src_mac = pkt[0][0].src
        dst_mac = pkt[0][0].dst
        attack = str(0) # delete in later
        category = 'Normal'# delete in later
        subcategory = 'Normal' #delete in later
        sport = str(0)
        dport = str(0)
        flag = str(0)
        seq = str(0)

        if proto in protocols:
            if proto == 1:
                message_type = pkt[ICMP].type
                code = pkt[ICMP].code
                #proto = str(proto)
                proto = 'icmp'
            
            if proto == 6:
                sport = str(pkt[TCP].sport)
                dport = str(pkt[TCP].dport)
                #proto = str(proto)
                proto = 'tcp'
                seq = pkt[TCP].seq
                ack = pkt[TCP].ack
                flag = pkt[TCP].flags
                if flag == 4:
                    flag = 1 # RST
                elif flag == 16:
                    flag = 3 #ACK
                elif flag == 1:
                    flag = 2 #FIN
                else:
                    flag = 4
            
            if proto == 17:
                sport = str(pkt[UDP].sport)
                dport = str(pkt[UDP].dport)
                seq = pkt[UDP].seq
                #proto = str(proto)
                proto = 'udp'
        
        src_traffic.update({tuple(map(str,src_ip))})
        dst_traffic.update({tuple(dst_ip)})
        traffic.update({tuple(map(str, (src_ip, dst_ip, proto, src_mac, dst_mac, sport, dport, flag, seq, attack, category, subcategory))): length})

def add_n_in():
    global df
    for(h1, h2, proto, src_mac, dst_mac, sport, dport, flag, seq, attack, category, subcategory), total in traffic.most_common():
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
        data = pd.DataFrame({'saddr': [h1], 'daddr' : [h2], 'proto' : [proto], 'src_mac' : [src_mac], 'dst_mac' : [dst_mac], 'sport' : [sport], 'dport':[dport], 'flag':[flag], 'n_in_src':[temp_s], 'n_in_dst':[temp_d], 'length' : [total], 'srate':[float(total)/sample_interval], 'seq' : [seq], 'attack' : [attack], 'category' : [category], 'subcategory' : [subcategory]})
        df = pd.concat([df,data], ignore_index=True)

def load_csv(PATH):
    df_csv = pd.read_csv(PATH)
    return df_csv

def make_data(original_df):
    global df
    df['pkSeqID'] = 0
    df['stddev'] = 0
    df['min'] = 0
    df['max']=0
    df['mean']=0
    df['state_num'] = 0 # add in latter
    df['stddev'] = 0
    df['drate'] = df['srate']
    #df['srate'] = 0 # add in later
    df = df.drop(['flag', 'length', 'src_mac', 'dst_mac'])
    original_df = pd.concat([orginal_df, df])

if __name__ == "__main__":
    train_df = load_csv(trainPATH)
    test_df= load_csv(testPATH)

    sample_interval = 10
    sniff(prn=traffic_monitor_callback,timeout=sample_interval, store=False)
    add_n_in()




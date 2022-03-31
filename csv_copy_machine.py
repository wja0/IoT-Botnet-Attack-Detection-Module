from scapy.all import *
from collections import Counter
import pandas as pd
import csv


protocols={1:'icmp', 6:'tcp', 17:'udp'}
test_PATH = r'../dataset/testData.csv'
train_PATH = r'../dataset/trainData.csv'
new_train_PATH = r'../dataset/newTrainData.csv'
new_test_PATH = r'../dataset/newTestData.csv'
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
                flag = 5
            
            if proto == 6:
                sport = str(pkt[TCP].sport)
                dport = str(pkt[TCP].dport)
                #proto = str(proto)
                proto = 'tcp'
                seq = pkt[TCP].seq
                ack = pkt[TCP].ack
                flag = pkt[TCP].flags
                if flag == 4:
                    flag = 1
                elif flag == 2:
                    flag = 2
                elif flag == 16:
                    flag = 3
            
            if proto == 17:
                try:
                    sport = str(pkt[UDP].sport)
                except:
                    sport = str(0)

                try:
                    dport = str(pkt[UDP].dport)
                except:
                    sport = str(0)
                #proto = str(proto)
                flag = 4
                proto = 'udp'

        
        src_traffic.update({tuple(map(str,src_ip))})
        dst_traffic.update({tuple(dst_ip)})
        traffic.update({tuple(map(str, (src_ip, dst_ip, proto, src_mac, dst_mac, sport, dport, flag, seq, attack, category, subcategory))): length})

def add_n_in(df, scan_time):
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
        data = pd.DataFrame({'saddr': [h1], 'daddr' : [h2], 'proto' : [proto], 'src_mac' : [src_mac], 'dst_mac' : [dst_mac], 'sport' : [sport], 'dport':[dport], 'flag':[flag], 'N_IN_Conn_P_SrcIP':[temp_s], 'N_IN_Conn_P_DstIP':[temp_d], 'length' : [total], 'srate':[float(total)/scan_time], 'seq' : [seq], 'attack' : [attack], 'category' : [category], 'subcategory' : [subcategory]})
        df = pd.concat([df,data], ignore_index=True)
    return df

def load_csv(PATH):
    df_csv = pd.read_csv(PATH)
    return df_csv

def make_data(original_df, df):
    df['pkSeqID'] = 0
    df['stddev'] = 0
    df['min'] = 0
    df['max']=0
    df['mean']=0
    df['state_num'] = df['flag'] # add in latter
    df['stddev'] = 0
    df['drate'] = df['srate']
    #df['srate'] = 0 # add in later
    df = df.drop(['flag', 'length',  'src_mac', 'dst_mac'],axis=1)
    original_df = pd.concat([original_df, df])
    return original_df

def init_traffic():
    global traffic
    global src_traffic
    global dst_traffic
    traffic = Counter()
    src_traffic = Counter()
    dst_traffic = Counter()

def do_sniff(ori_df, scan_time):
    hosts={}
    df = pd.DataFrame(columns=['saddr', 'daddr', 'proto', 'src_mac', 'dst_mac', 'sport', 'dport', 'flag', 'N_IN_Conn_P_SrcIP', 'N_IN_Conn_P_DstIP', 'rate', 'length', 'seq','attack','category','subcategory'])
    sniff(prn=traffic_monitor_callback, timeout=scan_time, store=False)
    df = add_n_in(df, scan_time)
    ori_df = make_data(ori_df, df)
    return ori_df

def write_csv(df, PATH):
    df.to_csv(PATH, index=False)

if __name__ == "__main__":
    train_df = load_csv(train_PATH)
    test_df= load_csv(test_PATH)
    init_traffic()
    sc_time_one = 300
    sc_time_two = 100
    sniff(prn=traffic_monitor_callback,timeout=sc_time_one, store=False)
    train_df = do_sniff(train_df, sc_time_one)
    write_csv(train_df, new_train_PATH)
    init_traffic()
    sniff(prn=traffic_monitor_callback, timeout= sc_time_two, store=False)
    test_df = do_sniff(test_df, sc_time_two)
    write_csv(test_df, new_test_PATH)
    





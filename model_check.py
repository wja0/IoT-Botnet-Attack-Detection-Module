import os
import pandas as pd
import ids_ap as ids
from sklearn.model_selection import train_test_split
import time
import numpy as np
import joblib
from collections import Counter
import xgboost as xgb
#import tensorflow as tf

def model_init():
    final_model = joblib.load('./RAN_final_morai_1234.h5')
    
    return final_model
    

def check_attack(x_traffic, final_model, host_ip):
    f = open("./check.txt", 'w')
    chk_traffic = x_traffic
    f.write("------x Traffic port------\n") 
    f.write(str(x_traffic['port'].value_counts()))
    x_traffic = x_traffic.drop(['saddr', 'daddr', 'src_mac', 'dst_mac', 'sport', 'dport'], axis = 1)
    y_traffic = final_model.predict(x_traffic)
    print("predict complete!")
    f.write("\n------y Traffic port------\n") 
    f.write(str(Counter(y_traffic)))
    f.close()
    print("write_down")
    #csv_traffic['scan'] = y_atk_traffic
    #ids.write_csv(csv_traffic, './temp.csv')
    ip_cnt = Counter()
    ten_point_ip = []
    result = []
    
    ip_cnt, atk_list = collection_atk_ip(chk_traffic, y_traffic, ip_cnt, host_ip)
            
    for (col_ip), ip_score in ip_cnt.most_common():
        if ip_score > 0: # if ip_score is more than 10 point, we consider this traffic is attack.
            ten_point_ip.append(col_ip)
            
    
    for i in atk_list: #Is this optimization?
        if ''.join(i[0]) == host_ip:
            tmp = ''.join(i[1])
        else:
            tmp = ''.join(i[0])
            
        for j in ten_point_ip:
            if ''.join(j) == tmp:
                result.append(i)
                break
    #for i in atk_list: #Is this optimization?
#        if atk_list.iat[i,0] == host_ip:
#            tmp = atk_list.iat[i,1]
#        else:
#            tmp = atk_list.iat[i,0]
#            
#        for j in ten_point_ip:
#            if ''.join(j) == tmp:
#                result.append(atk_list.loc[i])
#                break
            
    #print(result)   
    attack = False
    print(atk_list)
    if len(result) > 1500:
        attack = True
            
    return attack, result
            
    
    


def collection_atk_ip(chk_traffic, y_traffic, ip_cnt, host_ip):
    atk_list = []
    
    for i in range(0, len(chk_traffic)):
        #score = y_scan_traffic[i] + y_atk_traffic[i] # if scan and atk are 1, score is 2 point. and if just one of them is 1, socre is 1 point.
        score = y_traffic[i]
        if  score > 0 :
            #if chl_traffic[i]['src_ip'] == host_ip: # collect ip of bad traffics. and mark a score. <exclude host_ip, because victim must be host_ip> 
            if chk_traffic.iat[i, 0] == host_ip:
                #ip_cnt.update(chk_traffic[i]['dst_ip']:score)
                ip_cnt.update({tuple(chk_traffic.iat[i,1]):score})
            else:
                ip_cnt.update({tuple(chk_traffic.iat[i,0]):score})
            
            atk_list.append(chk_traffic.loc[i]) # new only attack data frame :)
            
    return ip_cnt, atk_list

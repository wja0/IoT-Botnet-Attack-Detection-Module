import os
import pandas as pd
from sklearn.model_selection import train_test_split
import time
import numpy as np
import joblib
from collections import Counter

def model_init():
    scan_model = joblib.load('./RAN_scan.h5')
    atk_model = joblib.load('./RAN_attack.h5')

    return scan_model, atk_model
    

def check_attack(x_traffic, scan_model, atk_model, host_ip):
    chk_traffic = x_traffic
    x_traffic = x_traffic.drop(['saddr', 'daddr', 'src_mac', 'dst_mac'], axis = 1)
    
    y_scan_traffic = scan_model.predict(x_traffic)
    y_atk_traffic = atk_model.predict(x_traffic)
    ip_cnt = Counter()
    ten_point_ip = []
    result = []
    
    ip_cnt, atk_list = collection_atk_ip(chk_traffic, y_scan_traffic, y_atk_traffic, ip_cnt, host_ip)
            
    for (col_ip), ip_score in ip_cnt.most_common():
        if ip_score > 0: # if ip_score is more than 10 point, we consider this traffic is attack.
            ten_point_ip.append(col_ip)
            
    #atk_list = pd.DataFrame(atk_list)

    
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
    
    if len(result) != 0:
        attack = True
            
    return attack, result
            
    
    


def collection_atk_ip(chk_traffic, y_scan_traffic, y_atk_traffic, ip_cnt, host_ip):
    atk_list = []
    
    for i in range(0, len(chk_traffic)):
        score = y_scan_traffic[i] + y_atk_traffic[i] # if scan and atk are 1, score is 2 point. and if just one of them is 1, socre is 1 point.
        
        if  score > 0 :
            #if chl_traffic[i]['src_ip'] == host_ip: # collect ip of bad traffics. and mark a score. <exclude host_ip, because victim must be host_ip> 
            if chk_traffic.iat[i, 0] == host_ip:
                #ip_cnt.update(chk_traffic[i]['dst_ip']:score)
                ip_cnt.update({tuple(chk_traffic.iat[i,1]):score})
            else:
                ip_cnt.update({tuple(chk_traffic.iat[i,0]):score})
            
            atk_list.append(chk_traffic.loc[i]) # new only attack data frame :)
            
    return ip_cnt, atk_list

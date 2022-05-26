def model_init():
    scan_model = joblib.load('./')
    atk_model = joblib.load('./')

    return scan_model, atk_model
    

def check_attack(x_traffic, scan_model, atk_model, host_ip):
    chk_traffic = x_traffic
    x_traffic = x_traffic.drop(['saddr', 'daddr', 'smac', 'dmac'], axis = 1)
    
    y_scan_traffic = model_scan.predict_classes(x_traffic)
    y_atk_traffic = model_atk.predict_classes(x_traffic)
    ip_cnt = Counter()
    ten_point_ip = []
    result = []
    
    ip_cnt, atk_list = collection_atk_ip(chk_traffic, y_scan_traffic, y_atk_traffic, ip_cnt, host_ip)
            
    for (col_ip), ip_score in score.most_common():
        if ip_score > 10: # if ip_score is more than 10 point, we consider this traffic is attack.
            ten_point_ip.append(col_ip)
    
    for i in atk_list: #Is this optimization?
        if i[0] == host_ip:
            tmp = i[1]
        else:
            tmp = i[0]
        for j in ten_point_ip:
            if j == tmp:
                reslut.append(tmp)
                break
                
    attack = False
    
    if len(ten_point_ip) == 0:
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

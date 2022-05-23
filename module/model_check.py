

def check_attack(x_traffic, scan_model, atk_model, host_ip):
    y_scan_traffic = model_scan.predict_classes(x_traffic)
    y_atk_traffic = model_atk.predict_classes(x_traffic)
    ip_cnt = Counter()
    ten_point_ip = []
    result = []
    
    ip_cnt, atk_list = collection_atk_ip(x_traffic, y_scan_traffic, y_atk_traffic, ip_cnt, host_ip)
            
    for (col_ip), ip_score in score.most_common():
        if ip_score > 10: # if ip_score is more than 10 point, we consider this traffic is attack.
            ten_point_ip.append(col_ip)
    
    for i in atk_list: #Is this optimization?
        if i['src_ip'] == host_ip:
            for i['dst_ip'] in ten_point_ip:
                result.append(i)
                break
        else:
            for i['src_ip'] in ten_point_ip:
                result.append(i)
                break
            
    #for i in atk_list:
    #    for i['dst_ip'] in ten_point_ip or i['src_ip'] in ten_point_ip:
    #        result.append(i)
    #        break
            
    return result
            
    
    


def collection_atk_ip(x_traffic, y_scan_traffic, y_atk_traffic, ip_cnt, host_ip):
    atk_list = []
    
    for i in range(0, len(x_traffic)):
        score = y_scan_traffic[i] + y_atk_traffic[i] # if scan and atk are 1, score is 2 point. and if just one of them is 1, socre is 1 point.
        
        if  score > 0 :
            if x_traffic[i]['src_ip'] == host_ip: # collect ip of bad traffics. and mark a score. <exclude host_ip, because victim must be host_ip> 
                ip_cnt.update(x_traffic[i]['dst_ip']:score)
            else:
                ip_cnt.update(x_traffic[i]['src_ip']:score)
            
            atk_list.append() # new only attack data frame :)
            
    return ip_cnt, atk_list
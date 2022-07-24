import ids_ap_pcap as ids
import model_check as mdc
import client as srv
import os
import get_user as gusr
from requests import get
#import requests

if __name__ == "__main__":
    #host_ip = get("https://api.ipify.org").text
    host_ip = '210.117.181.96'
    attack = False
    c_socket = srv.connection_server()
    final_model = mdc.model_init()
    
    while(True):
        traffic_df = ids.scan_data()
        print(traffic_df)
        if os.fork() == 0:
            #err = srv.check_server(c_socket)
                       
            #if err:
            #    print("Can't connect to secure server!")

            attack, bad_traffic = mdc.check_attack(traffic_df, final_model, host_ip)
            
            if attack == True:
                gusr.inform_user()
                srv.send_to_server(c_socket, bad_traffic)
            
            exit(0)#child process down
        
        print("restart scan data")
                
        
        
            

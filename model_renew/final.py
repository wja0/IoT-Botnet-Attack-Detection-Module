import ids_ap as ids
import model_check as mdc
import client as srv
import os
import get_user as gusr
from requests import get
#import requests

if __name__ == "__main__":
    #host_ip = get("https://api.ipify.org").text
    print("Select type of traffic (0: exit, 1: Network, 2: pcap)")
    in_chk = True
    while(in_chk):
        type_traffic = input()
        if type_traffic == '0':
            print("Exit proccess")
            exit(0)
        elif type_traffic == '1':
            print("Scan this network!")
            in_chk = False
        elif type_traffic == '2':
            print("Read pcap!")
            in_chk = False
        else:
            print("Please select in (0: exit, 1: Network, 2: pcap)")
    
    
    host_ip = '210.117.181.96'
    attack = False
    c_socket = srv.connection_server()
    final_model = mdc.model_init()
    
    while(True):
        traffic_df = ids.scan_data(type_traffic)
        
        #if os.fork() == 0:
        if True:
            #err = srv.check_server(c_socket)
                       
            #if err:
            #    print("Can't connect to secure server!")

            attack, bad_traffic = mdc.check_attack(traffic_df, final_model, host_ip)
            
            if attack == True:
                gusr.inform_user()
                srv.send_to_server(c_socket, bad_traffic)
            else :
                srv.send_to_server_no_scan(c_socket)
            exit(0)#child process down
        
        print("restart scan data")
                
        
        
            

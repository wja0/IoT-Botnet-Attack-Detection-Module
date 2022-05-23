import ids_ap as ids
import os
from requests import get


if __name__ == "__main__":
    host_ip = get("https://api.ipify.org").text
    attack = False
    c_socket = connection_server()
    model_init()
    
    while(True):
        pd_csv = scan_data()
        
        if os.fork() == 0:
            err = check_server(c_socket)
            
            if err:
                print("Can't connect to secure server!")
                
            write_csv(pd_csv)
            attack = check_attack()
            
            if attack:
                infrom_usr()
                send_to_server()
            
            return #child process down
        
        print("restart scan data")
                
        
        
            
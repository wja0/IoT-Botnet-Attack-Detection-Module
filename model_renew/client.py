import socket
import pandas as pd

def connection_server():
    #domain = 'cncloader.shop'
    #ip = socket.gethostbyname_ex(domain)
    HOST = '210.117.181.86'
    #HOST = '210.117.181.86'
    PORT = 20226
    #PORT = 20226
    
    c_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c_socket.connect((HOST, PORT))
    
    return c_socket

def check_connetion(c_socket):
    msg = 'hello';
    data = msg.encode();
    length = len(data);
    c_socket.sendall(length.to_bytes(4, byteorder="little"));
    c_socket.sendall(data);
    data = c_socket.recv(4);
    length = int.from_bytes(data, "little");
    data = c_socket.recv(length);
    msg = data.decode();
    
    if err : #err check plz
        for i in range(0,10):
                err = check_server(c_socket)
                if not err:
                    break
    
    print('Received from : ', msg);
    
    return False #check error plz

def send_to_server(c_socket, df):
    print(df)
    bad_traffic = pd.DataFrame(df)
    bad_traffic = bad_traffic.to_string().encode()
    length = len(bad_traffic);
    c_socket.sendall(length.to_bytes(4, byteorder="little"));
    c_socket.sendall(bad_traffic)
    
def send_to_server_no_scan(c_socket):
    no_scan = "no scan"
    no_scan = no_scan.encode()
    length = len(no_scan);
    c_socket.sendall(length.to_bytes(4, byteorder="little"));
    c_socket.sendall(no_scan)
    
    


import socket
import pandas as pd

def connection_server():
    domain = 'cncbotnet.shop'
    #ip = socket.gethostbyname_ex(domain)
    HOST = '210.117.181.86'
    PORT = 20226
    
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
    bad_traffic = pd.DataFrame(df)
    bad_traffic = bad_traffic.to_string().encode()
    length = len(bad_traffic);
    c_socket.sendall(length.to_bytes(4, byteorder="little"));
    c_socket.sendall(bad_traffic)
    
    
#for i in range(1,10):
#    msg = 'hello';
#    data = msg.encode();
#    length = len(data);
#    client_socket.sendall(length.to_bytes(4, byteorder="little"));
#    client_socket.sendall(data);
#    data = client_socket.recv(4);
#    length = int.from_bytes(data, "little");
#    data = client_socket.recv(length);
#    msg = data.decode();
#    print('Received from : ', msg);
    
#client_socket.close();

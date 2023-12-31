import socket
import argparse
import ipaddress
import csv
import threading
import signal
import pickle
import ssl
import hashlib

# Command line interface
parser = argparse.ArgumentParser(description="TCP server. Usage: python server.py -sIP <server IPv4 address> (default: localhost) -p <port number> (default: 12345)")
# Adding arguments/options
parser.add_argument("-sIP", dest="server_ip", default= '0.0.0.0', help="Server IPv4 address")
parser.add_argument("-p", dest="port", default=12345, type=int, help="Port number")

args = parser.parse_args()

server_ip = args.server_ip  # Extracting server IP from Command line
port = args.port    # Extracting port number from Command line

# Validate the provided server IP as a valid IPv4 address
try:
    ipaddress.IPv4Address(server_ip)
except ipaddress.AddressValueError as err:
    print("Error: The provided server IP is not a valid IPv4 address.")
    print(err)
    exit()

# Define server address and port
server_address = (server_ip, port)

# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Wrap the socket in an SSL context
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain(certfile='certificates/server-cert.pem', keyfile='certificates/server-key.pem')

ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3

ssl_socket = ssl_context.wrap_socket(server_socket, server_side=True, do_handshake_on_connect=True)

# context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# context.load_cert_chain('server.crt', 'server_private.key')
# ssl_socket = context.wrap_socket(server_socket, server_side=True)
server_socket = ssl_socket
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Trying to bind the socket to the address and port
try:
    server_socket.bind(server_address)
except Exception as e:
    print(f"Error while binding: {e}")
    exit()

# Listen for incoming connections
max_clients = 5
server_socket.listen(max_clients)

print(f"Server is waiting for connections @ {server_ip}:{port}...")

server_close_flag = threading.Event()

# Function for authentication
def user_credentials_exist_in_csv(file_path, username_to_check, password_to_check):
    try:
        with open(file_path, 'r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                if row['username'] == username_to_check and row['password'] == password_to_check:
                    return True
        return False
    except:
        print("Error while reading the CSV file.")

def authenticate(client_socket)->(bool, str):

    try:
        # Receive the username and encrypted password from the client
        received_data = client_socket.recv(4096+1024)
        (username, encrypted_password) = pickle.loads(received_data)
        
        decrypted_password = hashlib.sha256(encrypted_password.encode()).hexdigest()

        # Check if the received password matches the stored password
        if user_credentials_exist_in_csv("auth_data.csv",username,decrypted_password):
            client_socket.sendall(b"Authentication successful.")
            print(f"Authentication successful with user {username}.")
            return (True, username)
        else:
            client_socket.sendall(b"0")
            print(f"Authentication failed with user {username}: Either username or password is incorrect")
            client_socket.close()
            return (False, None)
    except Exception as e:
        print(e)
        client_socket.close()
        return (False, None)

# rec_buff is a global buffer that can be accessed by all the threads (in this case two threads)
rcv_buff = {}

def shouldStop(rcv_buffer, accepted_username):
    # using another 
    if(len(rcv_buffer) != 1):  # case where the buffer has data of both the trains
        # No need to stop the trains on different tracks
        for other_user in rcv_buffer.keys():
            if(other_user != accepted_username):
                if(rcv_buffer[accepted_username].get('trackID') != rcv_buffer[other_user].get('trackID')):
                    return False
                else:
                    # If the trains are on the same track, check the distance between them
                    if(abs(rcv_buffer[accepted_username].get('posID') - rcv_buffer[other_user].get('posID')) <= 3):
                        if(rcv_buffer[accepted_username].get('direction') != rcv_buffer[other_user].get('direction')):
                            return True
                        else:
                            if (rcv_buffer[accepted_username].get('direction') == 1):
                                if(rcv_buffer[accepted_username].get('posID') <= rcv_buffer[other_user].get('posID')):
                                    return True
                                else:
                                    return False
                            if (rcv_buffer[accepted_username].get('direction') == -1):
                                if(rcv_buffer[accepted_username].get('posID') >= rcv_buffer[other_user].get('posID')):
                                    return True
                                else:
                                    return False
                        return True
    return False

def handle_client(client_socket):
    authenticated_flag, accepted_username = authenticate(client_socket)
    if(authenticated_flag):
        # for noting direction of train
        direction_flag = 0
        # rcv_buff[accepted_username]["direction"] = direction_flag
        while server_close_flag.is_set() == False:
            # update rec buffer
            # make necessary decision by examining rec_buff data of train of its own thread and other thread
            # send decision to the train corresponding to that particular thread
            try:
                message= client_socket.recv(1024).decode() # decoding the data received in string "message"
                if(len(message) != 0):
                    message_dict = eval(message) # converting the string to a dictionary to access trackID and posID
                    global rcv_buff
                    if rcv_buff.get(accepted_username) == None:
                        rcv_buff[accepted_username] = message_dict
                        rcv_buff[accepted_username]["direction"] = direction_flag
                    else:
                        if rcv_buff[accepted_username].get('trackID') == message_dict.get('trackID'):
                            if rcv_buff[accepted_username].get('posID') > message_dict.get('posID'):
                                direction_flag = -1 # train is moving in the negative direction
                            elif rcv_buff[accepted_username].get('posID') < message_dict.get('posID'):
                                direction_flag = 1 # train is moving in the positive direction
                            else:
                                direction_flag = 0 # train is not moving
                        rcv_buff[accepted_username] = message_dict
                        rcv_buff[accepted_username]["direction"] = direction_flag
                    print(f"{accepted_username} : {rcv_buff}") # printing for testing purposes
                if not message:
                    print(f"Client {accepted_username} disconnected due to no keepalive...")
                    break
            except:
                pass
            if(shouldStop(rcv_buff, accepted_username)):
                        # send message to the train to stop
                        print(f"Stopping the train {accepted_username} as signal received...")
                        try:
                            client_socket.sendall(b"stop") 
                        except:
                            break
    client_socket.close()
    print(f"Connection with {accepted_username} closed.") 
                
# client_count = 0
threads = []

# For closing the server gracefully in case of Keyboard interrupt
def handle_interrupt(signum, frame):
    server_close_flag.set()
    # server_socket.close()
    # exit("Keyboard interrupt. Closing server...")
    print("Keyboard interrupt. Closing server...")

signal.signal(signal.SIGINT, handle_interrupt)

server_socket.settimeout(1)

def set_keepalive(sock, interval=1, retries=3):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, interval)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, retries)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)

while server_close_flag.is_set() == False:
    # Accept an incoming connection
    # Main thread -> to keep the server open for new incoming connections
    # print(f"Main prints {rcv_buff}")
    try:
        client_socket, client_address = server_socket.accept()

        # The below timeout is to ensure that the thread closes too because recv is a blocking call
        client_socket.settimeout(1)

        # Enabling keepalive for client autoexit
        # set_keepalive(client_socket)

    except socket.timeout:
        continue
    except Exception as e:
        print(f"Error while accepting client : {e}")
        continue

    print(f"Connection request from {client_address}")

    # Authenticate the client
    # Create a thread for the client
    # this thread is dedicated to each client
    thread = threading.Thread(target=handle_client, args=(client_socket,))
    thread.start()
    threads.append(thread)

server_socket.close()
import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import argparse
import ipaddress
import csv
import threading

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

# Generate a server RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Extract the public key for sharing with clients
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

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

# Define server address and port
server_address = (server_ip, port)

# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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

def authenticate(client_socket)->(bool, str):

    try:
        # Receive the username
        username = client_socket.recv(1024).decode()
        # Send the public key to the client
        client_socket.send(public_pem)
        # Receive the encrypted password from the client
        encrypted_password = client_socket.recv(4096)
        # Decrypt the password using the server's private key
        decrypted_password = private_key.decrypt(
            encrypted_password,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

        # Check if the received password matches the stored password
        if user_credentials_exist_in_csv("auth_data.csv",username,decrypted_password):
            client_socket.send(b"Authentication successful.")
            print(f"Authentication successful with user {username}.")
            return (True, username)
        else:
            client_socket.send(b"Forbidden.")
            print(f"Authentication failed with user {username}: Either username or password is incorrect")
            client_socket.close()
            return (False, None)
    except Exception as e:
        print(e)
        client_socket.close()
        return (False, None)

# rec_buff is a global buffer that can be accessed by all the threads (in this case two threads)
rcv_buff = {}
# rcv_buff_lock = threading.Lock()

def shouldStop(rcv_buffer):
    # using another 
    if(len(rcv_buffer) != 1):  # case where the buffer has data of both the trains
        # No need to stop the trains on different tracks
        if(rcv_buffer["user1"].get('trackID') != rcv_buffer["user2"].get('trackID')):
            return False
        else:
            if(abs(rcv_buffer["user1"].get('tagID') - rcv_buffer["user2"].get('tagID')) <= 3):
                return True 
    return False

def handle_client(client_socket):
      authenticated_flag, accepted_username = authenticate(client_socket)
      if(authenticated_flag):
        while True:
            # update rec buffer
            # make necessary decision by examining rec_buff data of train of its own thread and other thread
            # send decision to the train corresponding to that particular thread
            try:
                message= client_socket.recv(1024).decode() # decoding the data received in string "message"
                if(len(message) != 0):
                    message_dict = eval(message) # converting the string to a dictionary to access trackID and tagID
                    global rcv_buff
                    rcv_buff[accepted_username] = message_dict # storing the data from the trains in buffer rcv_buff
                    print(f"{accepted_username} : {rcv_buff}") # printing for testing purposes
                    if(shouldStop(rcv_buff)):
                        # send message to the train to stop
                        print(f"Stopping the train {accepted_username} as signal received...")
                        client_socket.send(b"stop")
            except:
                pass
                      
                
# client_count = 0
# threads = []


while True:
    # Accept an incoming connection
    # Main thread -> to keep the server open for new incoming connections
    # print(f"Main prints {rcv_buff}")
    client_socket, client_address = server_socket.accept()
    print(f"Connection request from {client_address}")

    # Authenticate the client
    # Create a thread for the client
    # this thread is dedicated to each client
    thread = threading.Thread(target=handle_client, args=(client_socket,))
    thread.start()
    # threads.append(thread)

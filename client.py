import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import argparse
import ipaddress
import json
import time

# Command line interface
parser = argparse.ArgumentParser(description="TCP Client. Usage: python client.py -sIP <server IPv4 address> (default: localhost) -p <port number> (defualt: 12345)")
# Adding arguments/options
parser.add_argument("-sIP", dest="server_ip", default='127.0.0.1', help="Server IPv4 address")
parser.add_argument("-p", dest="port", default=12345, type=int, help="Port number")
parser.add_argument("-sim", dest="simulation_number", default=0, type=int, help="Simulation number\n 0: Trains on different tracks\n 1: Trains moving towards each other on same track\n 2: Both trains moving in opposite direction on same track\n 3: Trains moving in same direction on same track ")
parser.add_argument("-train", dest="trainID", default="A",choices=["A", "B"], help="Train ID\n A: train A, B: Train B")

args = parser.parse_args()

server_ip = args.server_ip  # Extracting server IP from Command line
port = args.port    # Extracting port number from Command line
sim = args.simulation_number
trainID = args.trainID
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
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to the server
try:
    client_socket.connect(server_address)
except Exception as e:
    print(f"Error while connecting: {e}")
    exit()
# Get user input for username and password
username = input("Enter your username: ")
password = input("Enter your password: ")
# Send the username to the server
client_socket.send(username.encode())
# Receive the public key from the server
public_key_pem = client_socket.recv(4096)
# Load the server's public key
try:
    server_public_key = serialization.load_pem_public_key(public_key_pem)
except:
    print(str(public_key_pem))
    client_socket.close()
    exit("Incorrect username or password...closing...")
# Encrypt the password with the server's public key
encrypted_password = server_public_key.encrypt(
    password.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# Send the encrypted password to the server
client_socket.send(encrypted_password)
# Receive the authentication result
response = client_socket.recv(1024).decode()
print(response)

# Loading Simulation Data
data_file = open("simulation_data.json")
sim_data = json.load(data_file)
train_data= "trainB_data" if(trainID=="B") else "trainA_data"
packets_data_to_send = sim_data["sim"+str(sim)][train_data]

# Sending packets with 1 sec gap
try:
    for packet in packets_data_to_send:
        # Send data to the server
        packet_str = str(packet)
        client_socket.sendall(packet_str.encode())
        print(f"Sent: {packet}")
        # Sleep for 1 second before sending the next data
        time.sleep(1)

finally:
    client_socket.close()
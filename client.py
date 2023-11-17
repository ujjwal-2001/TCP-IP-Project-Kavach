import socket
import argparse
import ipaddress
import json
import time
import threading
import pickle
import ssl

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
    exit("Closing...")

# Get user input for username and password
username = input("Enter your username: ")
password = input("Enter your password: ")

# Define server address and port
server_address = (server_ip, port)
# Create a socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_socket = ssl.wrap_socket(client_socket, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLSv1_2)
client_socket = ssl_socket

# Connect to the server
try:
    client_socket.connect(server_address)
except Exception as e:
    print(f"Error while connecting: {e}")
    exit()

# Create a tuple with username and encrypted password
data_to_send = (username, password)

# Serialize the tuple using pickle
serialized_data = pickle.dumps(data_to_send)

# Send the encrypted password to the server
client_socket.send(serialized_data)

# Receive the authentication result
response = client_socket.recv(1024).decode()
if response == "0":
    client_socket.close()
    exit("Incorrect username or password...closing...")
print(response)

signal_event = threading.Event()

# Function to stop the train
def stop_train(client_socket):
    while signal_event.is_set() == False:
        try:
            message = client_socket.recv(1024).decode()
            # stop = input("Enter 'stop' to stop the train: ")
            if message == "stop":
                print("Stopping the train as signal received...")
                signal_event.set()
                # sys.exit(0)
        except:
            break

stopper_thread = threading.Thread(target=stop_train, args=(client_socket,))
stopper_thread.start() 

# Loading Simulation Data
data_file = open("simulation_data.json")
sim_data = json.load(data_file)
train_data= "trainB_data" if(trainID=="B") else "trainA_data"
packets_data_to_send = sim_data["sim"+str(sim)][train_data]

# Sending packets with 1 sec gap
try:
    for packet in packets_data_to_send:
        # Send data to the server
        if(not signal_event.is_set()):
            packet_str = str(packet)
            client_socket.sendall(packet_str.encode())
            print(f"Sent: {packet}")
            # Sleep for 1 second before sending the next data
            time.sleep(1)
except KeyboardInterrupt:
    print("Keyboard Interrupt...closing...")
except Exception as e:
    print(f"Error while sending data: {e}")
finally:
    client_socket.close()
    signal_event.set()
    stopper_thread.join()
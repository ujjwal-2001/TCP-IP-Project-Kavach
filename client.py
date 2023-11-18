import socket
import argparse
import ipaddress
import json
import time
import threading
import pickle
import ssl
import signal
import getpass
import hashlib

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
try:
    username = input("Enter your username: ")
    # password = input("Enter your password: ")
    password = getpass.getpass("Enter your password: ")
    # Hash the password
    # password = hashlib.md5(password.encode()).hexdigest()
    password = hashlib.sha256(password.encode()).hexdigest()
except:
    exit()

# Define server address and port
server_address = (server_ip, port)
# Create a socket
try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Wrap the socket in an SSL context
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations('certificates/ca-cert.pem')  # Certificate Authority's public key

    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3

    ssl_socket = ssl_context.wrap_socket(client_socket, do_handshake_on_connect=True, server_hostname= "server")
    # ssl_socket = ssl.wrap_socket(client_socket, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLSv1_2)
    client_socket = ssl_socket
except Exception as e:
    exit(f"Error creating socket: {e}")

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

signal_stop_event = threading.Event()

def set_keepalive(sock, interval=1, retries=3):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, interval)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, retries)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)

# Function to stop the train
def stop_train(client_socket):
    # Keepalive timer check
    client_socket.settimeout(2)
    set_keepalive(client_socket)
    while signal_stop_event.is_set() == False:
        try:
            message = client_socket.recv(1024).decode()

            if not message:
                print("Server not reachable (keepalive failure). Closing...")
                break

            # stop = input("Enter 'stop' to stop the train: ")
            if message == "stop":
                print("Stopping the train as signal received...")
                signal_stop_event.set()
                # sys.exit(0)
        except:
            continue
    client_socket.close()

stopper_thread = threading.Thread(target=stop_train, args=(client_socket,))
stopper_thread.start() 

# Loading Simulation Data
data_file = open("simulation_data.json")
sim_data = json.load(data_file)
train_data= "trainB_data" if(trainID=="B") else "trainA_data"
packets_data_to_send = sim_data["sim"+str(sim)][train_data]

# For closing the client gracefully in case of Keyboard interrupt
def handle_interrupt(signum, frame):
    signal_stop_event.set()
    # server_socket.close()
    # exit("Keyboard interrupt. Closing server...")
    print("Keyboard interrupt. Closing client...")

signal.signal(signal.SIGINT, handle_interrupt)

# Sending packets with 1 sec gap
try:
    for packet in packets_data_to_send:
        # Send data to the server
        if(not signal_stop_event.is_set()):
            packet_str = str(packet)
            client_socket.sendall(packet_str.encode())
            print(f"Sent: {packet}")
            # Sleep for 1 second before sending the next data
            time.sleep(1)
except KeyboardInterrupt:
    print("Keyboard Interrupt...closing...")
    signal_stop_event.set()
except Exception as e:
    print(f"Error while sending data: {e}")
    signal_stop_event.set()
finally:
    # signal_stop_event.set()
    while stopper_thread.is_alive():
        time.sleep(1)
    stopper_thread.join()
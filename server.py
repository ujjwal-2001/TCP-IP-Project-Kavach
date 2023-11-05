import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import argparse
import ipaddress

# Command line interface
parser = argparse.ArgumentParser(description="TCP server")
# Adding arguments/options
parser.add_argument("-sIP", dest="server_ip", required=True, help="Server IPv4 address")
parser.add_argument("-p", dest="port", required=True, type=int, help="Port number")

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

# Dummy authentication data (replace with a database in a real application)
auth_data = {
    "user1": "password1",
    "user2": "password2",
}

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
server_socket.listen(1)

print("Server is waiting for connections...")

def authenticate(client_socket):
    # Receive the username
    username = client_socket.recv(1024).decode()

    if username in auth_data:
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
        if auth_data[username] == decrypted_password:
            client_socket.send(b"Authentication successful.")
            print("Authentication successful.")
        else:
            client_socket.send(b"Authentication failed.")
            print("Authentication failed.")
    else:
        client_socket.send(b"User not found.")

    client_socket.close()

while True:
    # Accept an incoming connection
    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    # Authenticate the client
    authenticate(client_socket)

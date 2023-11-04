import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import ssl

# Define server address and port
server_address = ('127.0.0.1', 12345)

# Create a socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Wrap the socket with SSL for secure communication
ssl_client_socket = ssl.wrap_socket(client_socket, keyfile=None, certfile=None, server_side=False)

# Connect to the server
ssl_client_socket.connect(server_address)

# Get user input for username and password
username = input("Enter your username: ")
password = input("Enter your password: ")

# Send the username to the server
ssl_client_socket.send(username.encode())

# Receive the public key from the server
public_key_pem = ssl_client_socket.recv(4096)

# Load the server's public key
server_public_key = serialization.load_pem_public_key(public_key_pem)

# Encrypt the password with the server's public key
encrypted_password = server_public_key.encrypt(
    password.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=padding.ALGORITHMS.SHA256),
        algorithm=padding.ALGORITHMS.SHA256,
        label=None
    )
)

# Send the encrypted password to the server
ssl_client_socket.send(encrypted_password)

# Receive the authentication result
response = ssl_client_socket.recv(1024).decode()
print(response)

# Close the connection
ssl_client_socket.close()

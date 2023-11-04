import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
# Define server address and port
server_address = ('localhost', 12345)
# Create a socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to the server
client_socket.connect(server_address)
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
# Close the connection
client_socket.close()
import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

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
server_address = ('10.114.240.86', 12345)

# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
server_socket.bind(server_address)

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
        else:
            client_socket.send(b"Authentication failed.")
    else:
        client_socket.send(b"User not found.")

    client_socket.close()

while True:
    # Accept an incoming connection
    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    # Authenticate the client
    authenticate(client_socket)

# TCP-IP-Project-Kavach
Project for the grading of TCP/IP Networking course 
Course Code: E2 232

## Project Features

1. TLS connection for secure communication.
2. Authentication of user for further communication.
3. Keepalive feature included.
4. Threading for simultaneous client handling.
5. SHA256 hashing for password protection on both server and client side. This allows less security for stored passwords.

## Setup
There are three files:-
1. server.py: It contains the python code for running the server.
2. client.py: It contains the python code for running the client.
3. auth_data.csv: It contains the list of valid usernames and passwords in SHA256 hashed format.
4. certificates/CA_cert.sh: It creates the necessary certificates and keys using OpenSSL.

Code to run server at IPv4 10.0.0.1 with port 3000
```python
python3 server.py -sIP 10.0.0.1 -p 3000
```

Code to run client with port 3000 to connect to server at IPv4 10.0.0.1 
```python
python3 client.py -sIP 10.0.0.1 -p 3000
```

After running the client, enter valid username and password for further communication.

### Team Members
1. UJJWAL CHAUDHARY, M. Tech. ESE'25
2. R. GUHAN,         M. Tech. ESE'25
3. SUNDARESAN G.,    M. Tech. CDS'24

# TCP-IP-Project-Kavach
Project for the grading of TCP/IP Networking course 
Course Code: E2 232

## Project Features

1. TCP connection for reliable communication
2. Authentication of user for further communication

## Setup
There are three files:-
1. server.py: It contains the python code for running the server.
1. client.py: It contains the python code for running the client.
1. auth_data.csv: It contains the list of valid usernames and passwords.

Code to run server at IPv4 10.0.0.1 with port 3000
```python
python3 server.py -sIP 10.0.0.1 -p 3000
```

Code to run client with port 3000 to connect to server at IPv4 10.0.0.1 
```python
python3 server.py -sIP 10.0.0.1 -p 3000
```

After running the client, enter valid username and password for further communication.

### Team Members
1. UJJWAL CHAUDHARY, M. Tech. ESE'25
2. R. GUHAN,         M. Tech. ESE'25
3. SUNDARESAN G.,    M. Tech. CDS'24

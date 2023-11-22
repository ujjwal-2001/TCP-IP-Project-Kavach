# TCP-IP-Project-Kavach
Project for the grading of TCP/IP Networking course 
Course Code: E2 232

## About

This is a train collision avoidance system. This project deals with very specific situation with following constrains/assumptions:-
1. Two Trains are moving on the same track with a maximum speed of 100 Km/hr or 27.77 m/s.
2. RFID tags are kept every 1 km.
3. Both the trains have RFID tag readers with a range of 40m approx.
4. RFID tags can store two things (in user data section): position ID and Track ID.
5. Track ID inform on which track the tag is present.
6. Position ID infrom about the posion of the train on the given track. ( tags are placed in increasing order of Position ID in one direction of the track)
7. Hosts are Rpi4. 

## Project Features

1. **TLS connection for secure communication**
    - Only valid host( who have valid certificate) can connect with the server.
    - Data is encrypetd. 
3. **Authentication of user for further communication**: Valid host must also know the user-name and password.
4. **Keepalive feature included**: Clients will be informed if server is down.
5. **Threading for simultaneous client handling**.
6. **SHA256 hashing**: Password protection on both server and client side. This provides more security for stored passwords.
7. **Latency**:
     - Authentication: 300 - 350 ms 
     - Receiving STOP signal (RTT+processing): 5 ms
9. **Reliability**
    - TLS performs retransmission in case of a packet loss
    - For the speed of 27m/s and reader range of 40m, clients(trains) have approximately 2 sec for whole process (reading tag + procession infromation + sending packet + receiving of packet by server + processing infromation + sending a reply + receiveing the reply + taking action accordingly) which is more then enough (check latency).
    - Trains receive stop signal way before breaking distance (minimum distance before which trains need to apply breaks to avoide head on collision). If a train misses a tag it will still have another chance.

## Setup
Brief info about the files:-
1. server.py: It contains the python code for running the server.
2. client.py: It contains the python code for running the client.
3. auth_data.csv: It contains the list of valid usernames and passwords in SHA256 hashed format.
4. certificates/CA_cert.sh: It creates the necessary certificates and keys using OpenSSL.

Command to run server at IPv4 10.0.0.1 with port 3000
```python
python3 server.py -sIP 10.0.0.1 -p 3000
```

Command to run client with port 3000 to connect to server at IPv4 10.0.0.1 
```python
python3 client.py -sIP 10.0.0.1 -p 3000
```

## Running Simulation 

We can simulate four scenarios, and every scenario has its own simulation number.
| Simulation Number | Scenario |
|-------------------|----------|
| 0 | Train A and Train B are on different tracks |
| 1 | Train A and Train B are moving towards each other on same track |
| 2 | Train A and Train B are moving away from each other on same track |
| 3 | Train A and Train B are moving in same direction on same track |

### Example for running a simulation
In this example we are running simulation 1 where server IP is 10.0.0.1

Train A
```python
python3 client.py -sIP 10.0.0.1 -p 3000 -train A -sim 1
```

Train B
```python
python3 client.py -sIP 10.0.0.1 -p 3000 -train B -sim 1
```

Server
```python
python3 server.py -sIP 10.0.0.1
```

For more information about the option run
```python
python3 client.py -h
python3 server.py -h
```

Dummy username and password
```csv
username   password
user1      password1
user2      password2
```

### Team Members
1. [UJJWAL CHAUDHARY, M. Tech. ESE'25](https://www.linkedin.com/in/ujjwal-chaudhary-4436701aa/)
2. [R. GUHAN,         M. Tech. ESE'25](https://www.linkedin.com/in/guhan-rajasekar-996a95185/)
3. [SUNDARESAN G.,    M. Tech. CDS'24](https://www.linkedin.com/in/sundaresan-g-614956285/)


# Traceroute

This is an implementation of traceroute in Python. It sends ICMP echo requests with increasing TTL values to probe each hop between the source and destination. 

## Features

- Prints hop-by-hop latency and IP address 
- Handles ICMP time exceeded messages
- Resolves IPs to hostnames using reverse DNS 
- Adjustable packet size, count, timeouts
- Handles Ctrl+C keyboard interrupt

## Usage

```
usage: traceroute.py [-h] [-c COUNT] [-m MAXHOPS] [-a MAX_TTL] [-l TTL]
                     [-t TIMEOUT] [-p PACKET_SIZE]
                     dest_host

positional arguments:
  dest_host             Destination host

optional arguments:
  -h, --help            show this help message and exit
  -c COUNT, --count COUNT  
                        Number of packets (default 3)
  -m MAXHOPS, --maxhops MAXHOPS
                        Max hops (default 64)
  -a MAX_TTL, --max_ttl MAX_TTL
                        Max TTL (default 10) 
  -l TTL, --ttl TTL     Start TTL (default 1)
  -t TIMEOUT, --timeout TIMEOUT  
                        Timeout in ms (default 1000)
  -p PACKET_SIZE, --packet_size PACKET_SIZE
                        Packet size (default 52)
```

Example:

```
python traceroute.py google.com
```

## How it works

1. Socket opens raw ICMP socket 
2. Sends ICMP echo request with increasing TTL 
3. Handles ICMP time exceeded and echo reply
4. Calculates RTT based on sent and receive time
5. Resolves IP to hostname with reverse DNS
6. Prints traceroute hop result line
7. Increments TTL and repeats

## To Do

- [ ] Better input validation
- [ ] IPv6 support
- [ ] Asynchronous socket handling
- [ ] Support more packet sizes

## References

- RFC 792 - ICMP
- RFC 1122 - ICMP host unreachable codes
- Raw sockets - https://www.binarytides.com/raw-socket-programming-in-python-linux/

Let me know if you would like me to explain or expand on any part of the README!

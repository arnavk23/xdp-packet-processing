"""
Test script for XDP → AF_XDP forwarding via UDP/4242
Sends UDP packets to port 4242 on the test interface.

Usage:
  sudo python3 test_udp_4242.py <destination_ip> <peer_interface>

Example:
  sudo python3 test_udp_4242.py 192.168.1.10 eth1
"""
import sys
import time
from scapy.all import send, IP, UDP, Ether
import subprocess

if len(sys.argv) != 3:
    print("Usage: sudo python3 test_udp_4242.py <destination_ip> <peer_interface>")
    sys.exit(1)

dst_ip = sys.argv[1]
peer_if = sys.argv[2]

print(f"Sending 5 UDP packets to {dst_ip}:4242...")
for i in range(5):
    pkt = Ether()/IP(dst=dst_ip)/UDP(dport=4242, sport=12345)/b"hello-xdp"
    send(pkt, iface=peer_if, verbose=False)
    time.sleep(0.2)

print(f"Now run the following to verify packets on the peer interface:")
print(f"  sudo tcpdump -i {peer_if} udp port 4242 -vv -c 5")

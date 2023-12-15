import sys
import time
from scapy.all import * 

# Steps to create ARP Spoofer:

# Get the IP address that we want to spoof
# Get the MAC address of the IP that we want to spoof
# Then create a spoofing packet using the ARP() function to set the target IP, Spoof IP and it’s MAC address that we found above.
# Start the spoofing
# Display the information of the numbers of packets sent
# Finally, re-set the ARP tables of the spoofed address to defaults after spoofing
# Localip = input("ip à scanner : ")
# Srcip = input("Votre ip : ")
i=0
common_ports_25 = (80, 443, 67, 68, 20, 21, 23, 22, 53, 8080, 123, 25, 3389, 110, 554, 445, 587, 993, 137, 139, 8008, 500, 143, 161, 162, 389, 1434, 5900)  

for i in common_ports_25 :
    x = common_ports_25
    packet = IP(dst="127.0.0.1", src="127.0.0.1") / TCP(dport=x, flags="S")
    send(packet)

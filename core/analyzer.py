"""
This module contains the logic for analyzing intercepted network packets .
it maintains the state of the network ,performs a deep packet inspection(DPI) and detects anomalies such as : ARP spoofing,
ICMP flood and ICMP Tunneling(via payload size or entropy analysis)

"""

import time 
import math
from scapy.all import ARP, ICMP, IP, Raw
from utils.logger import SecurityLogger
from utils.config import Config 


class ThreatDetector : 
    """
    This class represents the main analyzer for network traffic
    It keeps track of device MACs ,ICMP packet frequency and alert cooldown
    
    """
    def __init__(self):
        self.known_devices = {} #to map IP addresses to MAC addresses
        self.traffic_tracker = {} #tracks ICMP packet timestamps per IP
        self.stats = {"total_packets": 0, "total_alerts": 0}
        self.alert_history ={} #aims to prevent alert fatigue
    
    
    def _launch_alert(self,ip,alert_type,cooldown=10):
        """Ensures that a specific attack type for the same IP is logged once
        per cooldown period .
        """
        key=(ip,alert_type)
        now=time.time()
        if key in self.alert_history:
            time_gap = now - self.alert_history[key]
            if time_gap < cooldown :
                return False 
        self.alert_history[key] = now
        return True
     
    def entropy_estimation(self,data):
        """Estimates the Shannon entropy of a payload to detect encrypted 
        or compressed data (to detect exfiltration)
        
        """
        if not data : return 0
        entropy = 0 
        for i in range(256):
            px= float(data.count(i))/ len(data)
            if px > 0:
                entropy -= px  * math.log(px,2)
        return entropy
    
    def packet_treatment(self,packet) : 
        """Routes the packet to the appropriate sub-analyzer according to 
        its protocol layers
        """
        self.stats["total_packets"] += 1
        if packet.haslayer(ARP) :
            self._analyze_arp(packet)   
        elif packet.haslayer(ICMP) and packet.haslayer(IP):
            self._analyze_icmp(packet)
    
    def _analyze_arp(self,packet) :
        """Detects IP-MAC Conflicts (ARP spoofing) """
        ipSrc, mac_src = packet[ARP].psrc, packet[ARP].hwsrc
        if ipSrc in Config.WHITELIST: return
        
        if ipSrc in self.known_devices and self.known_devices[ipSrc] != mac_src:
            if self._launch_alert(ipSrc, "ARP_SPOOFING"):
                SecurityLogger.log("ARP_SPOOFING", "CRITICAL", f"Conflict on {ipSrc}")
                self.stats["total_alerts"] += 1
        else:
            self.known_devices[ipSrc] = mac_src
    
    def _analyze_icmp(self, packet):
        """Detects ICMP floods and ICMP Tunneling"""
        if packet[ICMP].type != 8 : return
        ipSrc = packet[IP].src   
        if ipSrc in Config.WHITELIST: return
        now = time.time()

        #       ****  Flood Detection  ****
        history = self.traffic_tracker.get(ipSrc, []) 
        # for a specific IP address , we keep only the packets from the last second
        self.traffic_tracker[ipSrc] = [t for t in history if now - t < 1]
        self.traffic_tracker[ipSrc].append(now)

        if len(self.traffic_tracker[ipSrc]) > Config.ICMP_FLOOD_THRESHOLD:
            if self._launch_alert(ipSrc, "ICMP_FLOOD"):
                SecurityLogger.log("ICMP_FLOOD", "HIGH", f"Flood from {ipSrc}")
                self.stats["total_alerts"] += 1

        #       **** Tunneling Detection ****
        if packet.haslayer(Raw):
            load = packet[Raw].load
            if len(load)>50:
                entropy = self.entropy_estimation(load)
                if len(load) > Config.ICMP_TUNNEL_SIZE_LIMIT or entropy > 5.0:
                    if self._launch_alert(ipSrc, "ICMP_TUNNEL"):
                        SecurityLogger.log("ICMP_TUNNEL", "HIGH", f"Suspect payload from {ipSrc} (Entropy: {entropy:.2f})")
                        self.stats["total_alerts"] += 1
        

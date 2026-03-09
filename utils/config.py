""" 
NIDS Global Configuration
this module gathers all the configuration parameters of the NIDS
"""

class Config:
    #Network interface to monitor(for example: "eth0", "wlan0", "enp0s3")
    INTERFACE = "your_interface"
    SECURITY_ALERTS_FILE = "security_alerts.json"
    ICMP_FLOOD_THRESHOLD = 15 #packets per second
    ICMP_TUNNEL_SIZE_LIMIT = 175 #Bytes
    WHITELIST = [] 

#Color codes for terminal output
class Color:
    RED = "\033[91m"
    ORANGE = "\033[38;5;208m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    RESET = "\033[0m"

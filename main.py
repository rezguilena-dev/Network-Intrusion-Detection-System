"""
This script is the project entry point
Its purpose is to sniff traffic on the configured interface then transmit captured
packets to the packet analyzer (analyzer.py)
It guarantees an efficient memory management(store=0) and a graceful shutdown(Ctrl+C)
"""

import sys
import signal
from datetime import datetime 
from scapy.all import sniff
from core.analyzer import ThreatDetector
from utils.config import Config, Color

detector = ThreatDetector()
def displaySecurityReport(signal,frame):
    """
    Callback function launched by SIGINT signal to summarize session statistics.
    """
    print(f"\n\n{Color.BLUE}{'='*47}{Color.RESET}")
    print(f"{Color.BLUE}        SESSION SECURITY SUMMARY{Color.RESET}")
    print(f"{Color.BLUE}{'='*47}{Color.RESET}")
    print(f"Packets Analyzed : {detector.stats['total_packets']}")
    print(f"Alerts Triggered : {Color.RED if detector.stats['total_alerts'] > 0 else Color.GREEN }{detector.stats['total_alerts']}{Color.RESET }")
    print(f"Devices Tracked : {len(detector.known_devices)}")
    print(f"{Color.BLUE}{'='*47}{Color.RESET}")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, displaySecurityReport)
    print(f"----- {Color.BLUE} NETWORK INTRUSION DETECTION SYSTEM ... -----{Color.RESET}")
    print(f"{Color.PURPLE} Monitoring started at : {datetime.now().strftime('%H:%M:%S')}{Color.RESET} ")
    sniff(iface=Config.INTERFACE, prn=detector.packet_treatment, store=0)

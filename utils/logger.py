"""
This module handles the recording of security alerts in JSON Lines format.
It also serves as an intermediary between the detection engine and the Dashboard.
"""

from datetime import datetime 
import json 
from  utils.config import Config,Color

class SecurityLogger: 
    @staticmethod
    def log( alert_type , severity , message):
        """
        Logs a security event to the JSON file and displays it in the terminal.
        Args:
            alert_type(str): The name of the attack (for example: 'ARP Spoofing','ICMP Flood').
            severity(str): The threat level('HIGH' or 'CRITICAL').
            message(str): Detailed description of the event.
        """
        color = Color.RED if severity == "CRITICAL" else Color.ORANGE
        event ={
            "event_type" : alert_type,
            "occurred_at": datetime.now().isoformat(),
            "severity_level": severity ,
            "description" : message ,      
        }
        with open(Config.SECURITY_ALERTS_FILE,"a") as file : 
            file.write(json.dumps(event) + "\n")

        print(f" {color}[{severity}]{Color.RESET} {Color.BLUE}{alert_type}{Color.RESET} : {message} ") 

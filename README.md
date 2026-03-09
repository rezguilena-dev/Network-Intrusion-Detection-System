# 🛡️ Network Intrusion Detection System (NIDS)

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet_Sniffing-red?style=for-the-badge)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Status](https://img.shields.io/badge/Status-Finished-brightgreen?style=for-the-badge)

## Project Overview
This project has been developed to monitor, analyze, and alert on suspicious network traffic in real-time. The system combines a powerful backend sniffing engine with an interactive **Streamlit** dashboard for live threat visualization .

---

## Architecture & Detection Logic

This project was built with a **modular backend/frontend architecture** to ensure efficient packet processing and real-time responsiveness.

### Technical Implementations
The detection engine uses **Scapy** to perform deep packet inspection (DPI) :

| Feature | Description |
| :--- | :--- |
| **Real-time Sniffing** | Asynchronous packet capture using Scapy with `store=0` to optimize memory usage. |
| **ARP Spoofing Detection** | Detects ARP spoofing by identifying conflicting IP–MAC associations, preventing potential Man-in-the-Middle attacks.|
| **ICMP Flood Detection** | Implements frequency-based analysis to identify potential DoS/DDoS attacks. |
| **ICMP Tunneling Detection** | Detects potential data exfiltration by combining a payload size threshold and Shannon entropy calculation (for encrypted data) |
| **Live Dashboard** | Interactive UI with auto-refreshing metrics, visual alerts, and full log management (filtering and clearing). |
| **Redundancy Filter** |cooldown  mechanism to prevent alert fatigue . |

---

## Installation & Execution

### 1. Virtual Machine Configuration
To monitor external network traffic (and not just the VM's internal traffic), the environment must be configured as follows:
* **Network Adapter**: Set to **Bridged Adapter** .
* **Promiscuous Mode**: Set to **Allow All** . (To bypass the hardware MAC address filtering and allow Scapy to sniff the entire network segment)
### 2.Environment Setup & Dependencies
To avoid conflicts , a virtual environment was used ;follow these steps to create one :
```bash
# Create the virtual environment
python3 -m venv venv

# Activate the virtual environment 
source venv/bin/activate

# Install the required libraries
pip install -r requirements.txt
```
### 3.Configuration 
Before launching the main script ,open `utils/config.py` and update the `INTERFACE` variable with your network interface name .
 *(you can find the interface name using the `ip a` command in your terminal)*

### 4. Launch the Detection Engine:
```bash
sudo python3 main.py
```

### 5.Launch the Monitoring Dashboard:
in a separate terminal , run the Streamlit interface :
```bash
streamlit run app.py
```
## Attack Simulation 
Depending on the type of attack and OS-level security constraints, the testing methodology is divided into two approaches: external and local.

### 1. ICMP Attacks (External Testing: Windows Host ➔ VM)
Since ICMP traffic is routed normally, these attacks can be simulated from an external host.Open a Command Prompt(`cmd`) on the Windows host and run the following commands (replace `<adrIp>` with your VM's IP address):

* **ICMP Flood Simulation:**
    ```cmd
    for /l %i in (1,1,500) do ping -n 1 -w 1 <adrIp>
    ```
* **ICMP Tunneling Simulation:**
    ```cmd
    ping -n 5 -l 1000 <adrIp>
    ```

### 2. ARP Spoofing (Local Testing: Linux VM)

Unlike ICMP traffic, ARP spoofing cannot be simulated directly from a Windows host using standard tools, as the OS blocks it.
Because Linux allows low-level network manipulation (when running as `root`), we simulate this attack directly from within the Linux VM.
make sure you specify your target ip by updating the `target_ip` variable inside the script before running it.
```bash
# run the attack script in a new terminal 
   sudo python3 arp.py

```
## Project's structure :
```
.
├── core/               # Detection logic 
├── utils/              # Configuration (Interface, Thresholds, Whitelists) and Logger
├── security_alerts.json #  log file (JSON format)
├── app.py              # Streamlit dashboard interface
├── arp.py              # ARP Spoofing simulation script
├── main.py             # System entry point (Sniffing engine)
├── requirements.txt    # List of dependencies
└── .gitignore         
```

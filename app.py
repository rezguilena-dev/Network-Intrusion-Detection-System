"""
This script manages the graphical display of security alerts.
Its main role is to : read , parse and vizualize alerts contained in the JSON logs file.
It works independently from the sniffing engine (main.py) which ensures that the vizualisation
process does not interfere with the packet sniffing process .

"""
import streamlit as st
import pandas as pd
import io
from datetime import datetime
from streamlit_autorefresh import st_autorefresh 
from utils.config import Config

st.set_page_config(page_title="IDS Monitoring Dashboard", layout="wide")
st.markdown("""
<style>
    [data-testid="stMetric"] {
        background-color: #000000; 
        border: 1px solid #464b5d; 
        padding: 15px;
        border-radius: 10px;        
        color: white;             
    }
   
    [data-testid="stMetricLabel"] {
        color: #e0e0e0 !important;
    }
    [data-testid="stMetricValue"] {
        color: #B0B0B0 !important; 
    }
</style>
""", unsafe_allow_html=True)

count = st_autorefresh(interval=10000, key="ids_refresh")
now = datetime.now().strftime("%H:%M:%S")
st.markdown(f"*Monitoring interface - Last update: {now}*")
st.title("🛡️ Network Intrusion Detection System")

def clear_data():
    try: 
        with open(Config.SECURITY_ALERTS_FILE,"w") as f : 
            f.truncate(0)
        st.sidebar.success("logs cleared successfully")
        st.rerun()
    except Exception as e:
        st.sidebar.error(f"Error clearing logs: {e}")
        
if st.sidebar.button("Clear all logs", help="This will permanently delete all recorded alerts"):
    clear_data()


def load_data():
    """Loads alerts from the JSON file and prepares the Streamlit dataframe."""
    try:
        with open(Config.SECURITY_ALERTS_FILE,"r") as f: 
            raw = f.read()
        lines = raw.split('\n')
        clean_lines = []
        for line in lines:
            if line.strip().startswith('{'):
                clean_lines.append(line)
        
        if clean_lines: 
            json_data = "\n".join(clean_lines)
            df = pd.read_json(io.StringIO(json_data), lines=True)
            df = df.iloc[::-1] 

            #    **** Filters logic**** 
            if 'severity_level' in df.columns:
                levels = st.sidebar.multiselect("Filter by Severity", options=df['severity_level'].unique(),default=df['severity_level'].unique())
                df = df[df['severity_level'].isin(levels)]
            
            #   **** System status logic ****
            critical_count = len(df[df['severity_level'] == 'CRITICAL'])
            high_count = len(df[df['severity_level'] == 'HIGH'])
            
            if critical_count > 0:
                status = "CRITICAL"
                st.error(f"🚨 SYSTEM STATUS: {status} - IMMEDIATE ACTION REQUIRED")
            elif high_count > 0:
                status = "DANGER"
                st.warning(f"⚠️ SYSTEM STATUS: {status} - HIGH SEVERITY EVENTS DETECTED")
            else:
                status = "PROTECTED"
                st.success(f"✅ SYSTEM STATUS: {status} - ALL CLEAR")

            #   **** Metrics Management ****
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric(label="Total Alerts", value=len(df), delta=f"+{len(clean_lines)}")
      
            with col2:
                st.metric(label="Critical Events", value=critical_count, delta="Active", delta_color="inverse")
        
            with col3:
                status = "CRITICAL" if critical_count > 0 else ("DANGER" if high_count > 0 else "PROTECTED")
                st.metric(label="System Status", value=status, delta="Live")
          

            st.subheader("Recent Security Events")
            st.dataframe(df, use_container_width=True)
            
        else:
            st.info("📡 Monitoring active... No valid logs found yet.")
            
    except Exception as e:
        st.error(f"Error loading data : {e}")

load_data()

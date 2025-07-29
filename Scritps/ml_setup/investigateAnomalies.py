#!/usr/bin/env python3
"""
Quick Anomaly Investigation Tool
Path: Scripts/ml/investigateAnomalies.py
"""

import json
import pandas as pd
from datetime import datetime

def investigate_top_threats(results_file):
    """Investigate specific high-priority anomalies"""
    
    with open(results_file, 'r') as f:
        data = json.load(f)
    
    df = pd.DataFrame(data)
    anomalies = df[df['is_anomaly'] == True]
    
    print("🔍 HIGH-PRIORITY THREAT INVESTIGATION")
    print("="*50)
    
    # 1. Investigate top anomalous IP: 192.168.1.110
    ip_110 = anomalies[anomalies['src_ip'] == '192.168.1.110']
    if len(ip_110) > 0:
        print(f"\n🚨 CRITICAL: 192.168.1.110 Analysis ({len(ip_110)} anomalies)")
        print(f"Top destinations: {ip_110['dest_ip'].value_counts().head(3).to_dict()}")
        print(f"Applications used: {ip_110['data_app'].value_counts().head(3).to_dict()}")
        print(f"Risk levels: {ip_110['data_apprisk'].value_counts().to_dict()}")
        print(f"Time range: {ip_110['@timestamp'].min()} → {ip_110['@timestamp'].max()}")
    
    # 2. SSH anomaly investigation
    ssh_anomalies = anomalies[anomalies['data_app'] == 'SSH']
    if len(ssh_anomalies) > 0:
        print(f"\n🔐 SSH THREAT ANALYSIS ({len(ssh_anomalies)} anomalies)")
        print(f"Top SSH sources: {ssh_anomalies['src_ip'].value_counts().head(5).to_dict()}")
        print(f"Top SSH destinations: {ssh_anomalies['dest_ip'].value_counts().head(5).to_dict()}")
        
        # Check for brute force patterns
        ssh_by_hour = ssh_anomalies.groupby(['src_ip', 'hour']).size().sort_values(ascending=False)
        if len(ssh_by_hour) > 0:
            print(f"Potential brute force (IP, hour, attempts): {ssh_by_hour.head(3).to_dict()}")
    
    # 3. High-risk events
    high_risk = anomalies[anomalies['data_apprisk'] == 'high']
    if len(high_risk) > 0:
        print(f"\n⚠️  HIGH-RISK EVENTS ({len(high_risk)} anomalies)")
        for idx, row in high_risk.head(5).iterrows():
            print(f"  {row['@timestamp']}: {row['src_ip']} → {row['dest_ip']} ({row['data_app']})")
    
    # 4. Geographic threats
    foreign_traffic = anomalies[~anomalies['dest_geo_country'].isin(['unknown', 'India'])]
    if len(foreign_traffic) > 0:
        print(f"\n🌍 INTERNATIONAL THREATS ({len(foreign_traffic)} anomalies)")
        country_counts = foreign_traffic['dest_geo_country'].value_counts().head(5)
        for country, count in country_counts.items():
            country_data = foreign_traffic[foreign_traffic['dest_geo_country'] == country]
            top_apps = country_data['data_app'].value_counts().head(2).to_dict()
            print(f"  {country}: {count} anomalies, apps: {top_apps}")

def main():
    results_file = "ml_results/results/firewall_anomalies_20250729_130201.json"
    investigate_top_threats(results_file)
    
    print(f"\n✅ Investigation complete!")
    print(f"🎯 Recommended actions:")
    print(f"  1. Block/monitor 192.168.1.110 immediately")
    print(f"  2. Review SSH access policies")
    print(f"  3. Investigate US/UAE connections")
    print(f"  4. Implement geo-blocking for suspicious countries")

if __name__ == "__main__":
    main()
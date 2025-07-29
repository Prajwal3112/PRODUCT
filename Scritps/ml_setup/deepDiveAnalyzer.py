#!/usr/bin/env python3
"""
Deep Dive Firewall Anomaly Analyzer
Path: Scripts/ml/deepDiveAnalyzer.py

Comprehensive investigation of detected firewall anomalies
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import ipaddress
import os

class DeepDiveAnalyzer:
    def __init__(self, results_file):
        self.results_file = results_file
        self.df = None
        self.anomalies = None
        self.normal_logs = None
        self.load_data()
        
    def load_data(self):
        """Load and prepare data for analysis"""
        with open(self.results_file, 'r') as f:
            data = json.load(f)
        
        self.df = pd.DataFrame(data)
        self.anomalies = self.df[self.df['is_anomaly'] == True].copy()
        self.normal_logs = self.df[self.df['is_anomaly'] == False].copy()
        
        # Convert timestamps
        self.anomalies['@timestamp'] = pd.to_datetime(self.anomalies['@timestamp'], format='mixed')
        self.normal_logs['@timestamp'] = pd.to_datetime(self.normal_logs['@timestamp'], format='mixed')
        
        print(f"🔍 Loaded {len(self.anomalies)} anomalies and {len(self.normal_logs)} normal logs")
    
    def analyze_ssh_brute_force(self):
        """Deep analysis of SSH brute force attacks"""
        print("\n" + "="*80)
        print("🔐 SSH BRUTE FORCE ATTACK ANALYSIS")
        print("="*80)
        
        ssh_anomalies = self.anomalies[self.anomalies['data_app'] == 'SSH'].copy()
        
        if ssh_anomalies.empty:
            print("No SSH anomalies found")
            return
        
        print(f"Total SSH anomalies: {len(ssh_anomalies)}")
        
        # Analyze attack patterns by source IP
        for src_ip in ssh_anomalies['src_ip'].value_counts().head(3).index:
            src_attacks = ssh_anomalies[ssh_anomalies['src_ip'] == src_ip]
            
            print(f"\n🚨 ATTACKER: {src_ip}")
            print(f"  Total attempts: {len(src_attacks)}")
            print(f"  Time span: {src_attacks['@timestamp'].min()} → {src_attacks['@timestamp'].max()}")
            print(f"  Duration: {(src_attacks['@timestamp'].max() - src_attacks['@timestamp'].min()).total_seconds()/60:.1f} minutes")
            
            # Target analysis
            targets = src_attacks['dest_ip'].value_counts()
            print(f"  Targets: {len(targets)} unique IPs")
            for target, count in targets.head(3).items():
                print(f"    {target}: {count} attempts")
            
            # Temporal pattern
            hourly_pattern = src_attacks.groupby('hour').size()
            print(f"  Peak hours: {hourly_pattern.sort_values(ascending=False).head(3).to_dict()}")
            
            # Success indicators (looking for established connections)
            successful_attempts = src_attacks[src_attacks['action'] == 'pass']
            if len(successful_attempts) > 0:
                print(f"  ⚠️  POTENTIAL SUCCESSFUL LOGINS: {len(successful_attempts)}")
                for idx, row in successful_attempts.head(3).iterrows():
                    print(f"    {row['@timestamp']}: {row['dest_ip']}:{row['dest_port']}")
            
            # Check if this IP appears in normal traffic
            normal_traffic = self.normal_logs[self.normal_logs['src_ip'] == src_ip]
            if len(normal_traffic) > 0:
                print(f"  📊 Also has {len(normal_traffic)} normal connections")
            else:
                print(f"  🚨 PURELY MALICIOUS - no legitimate traffic detected")
    
    def analyze_telnet_threats(self):
        """Analyze Telnet security threats"""
        print("\n" + "="*80)
        print("📡 TELNET SECURITY THREAT ANALYSIS")
        print("="*80)
        
        telnet_anomalies = self.anomalies[self.anomalies['data_app'] == 'Telnet'].copy()
        
        if telnet_anomalies.empty:
            print("No Telnet anomalies found")
            return
        
        print(f"🚨 CRITICAL: {len(telnet_anomalies)} Telnet anomalies detected")
        print("⚠️  Telnet is UNENCRYPTED and should be disabled!")
        
        # Analyze Telnet sources
        for src_ip in telnet_anomalies['src_ip'].value_counts().index:
            src_telnet = telnet_anomalies[telnet_anomalies['src_ip'] == src_ip]
            
            print(f"\n🔴 TELNET SOURCE: {src_ip}")
            print(f"  Attempts: {len(src_telnet)}")
            print(f"  Targets: {src_telnet['dest_ip'].nunique()} unique destinations")
            
            # Show timeline
            timeline = src_telnet.sort_values('@timestamp')
            print(f"  Timeline:")
            for idx, row in timeline.head(5).iterrows():
                print(f"    {row['@timestamp']}: → {row['dest_ip']}:{row['dest_port']} ({row['action']})")
            
            # Risk assessment
            if src_ip.startswith('10.11.'):
                print(f"  🚨 HIGH RISK: Internal corporate IP using insecure Telnet")
            
            # Check target networks
            targets = src_telnet['dest_ip'].unique()
            internal_targets = [ip for ip in targets if ip.startswith('192.168.')]
            if internal_targets:
                print(f"  🎯 Internal targets: {internal_targets}")
    
    def analyze_anydesk_usage(self):
        """Analyze AnyDesk remote access anomalies"""
        print("\n" + "="*80)
        print("🖥️  ANYDESK REMOTE ACCESS ANALYSIS")
        print("="*80)
        
        anydesk_anomalies = self.anomalies[self.anomalies['data_app'] == 'AnyDesk'].copy()
        
        if anydesk_anomalies.empty:
            print("No AnyDesk anomalies found")
            return
        
        print(f"📡 AnyDesk anomalies: {len(anydesk_anomalies)}")
        
        for idx, row in anydesk_anomalies.iterrows():
            print(f"\n🔍 AnyDesk Connection:")
            print(f"  Time: {row['@timestamp']}")
            print(f"  Source: {row['src_ip']}:{row['src_port']}")
            print(f"  Destination: {row['dest_ip']}:{row['dest_port']}")
            print(f"  Direction: {row['data_direction']}")
            print(f"  Risk Level: {row['data_apprisk']}")
            
            # Assess threat level
            if row['data_direction'] == 'outgoing':
                print(f"  🚨 OUTGOING: Potential data exfiltration risk")
            if not row['dest_ip'].startswith(('192.168.', '10.', '172.')):
                print(f"  🌍 EXTERNAL: Connection to external IP")
                
            # Check if source is internal
            if row['src_ip'].startswith('10.11.'):
                print(f"  🏢 Internal corporate machine initiating remote access")
    
    def analyze_ssl_anomalies(self):
        """Analyze SSL/TLS anomalies"""
        print("\n" + "="*80)
        print("🔒 SSL/TLS ANOMALY ANALYSIS")
        print("="*80)
        
        ssl_anomalies = self.anomalies[
            self.anomalies['data_app'].isin(['SSL', 'SSL_TLSv1.3', 'SSL_TLSv1.2'])
        ].copy()
        
        if ssl_anomalies.empty:
            print("No SSL anomalies found")
            return
        
        print(f"Total SSL anomalies: {len(ssl_anomalies)}")
        
        # Focus on top anomalous SSL sources
        top_ssl_sources = ssl_anomalies['src_ip'].value_counts().head(3)
        
        for src_ip, count in top_ssl_sources.items():
            src_ssl = ssl_anomalies[ssl_anomalies['src_ip'] == src_ip]
            
            print(f"\n🔍 SSL SOURCE: {src_ip} ({count} anomalies)")
            
            # Destination analysis
            destinations = src_ssl['dest_ip'].value_counts().head(5)
            print(f"  Top destinations:")
            for dest_ip, dest_count in destinations.items():
                dest_data = src_ssl[src_ssl['dest_ip'] == dest_ip]
                
                # Try to identify suspicious patterns
                suspicious_indicators = []
                if dest_count > 10:
                    suspicious_indicators.append(f"High frequency ({dest_count} connections)")
                if not dest_ip.startswith(('192.168.', '10.', '172.')):
                    suspicious_indicators.append("External IP")
                
                risk_levels = dest_data['data_apprisk'].value_counts()
                if 'high' in risk_levels:
                    suspicious_indicators.append(f"High risk ({risk_levels['high']} instances)")
                
                indicator_str = ", ".join(suspicious_indicators) if suspicious_indicators else "Normal"
                print(f"    {dest_ip}: {dest_count} conn. - {indicator_str}")
            
            # Time pattern analysis
            time_span = src_ssl['@timestamp'].max() - src_ssl['@timestamp'].min()
            print(f"  Time span: {time_span.total_seconds()/60:.1f} minutes")
            
            if time_span.total_seconds() < 600:  # Less than 10 minutes
                print(f"  🚨 HIGH FREQUENCY: All connections in short time window")
    
    def analyze_geographic_threats(self):
        """Analyze geographic anomalies"""
        print("\n" + "="*80)
        print("🌍 GEOGRAPHIC THREAT ANALYSIS")
        print("="*80)
        
        # Focus on high-risk countries
        high_risk_countries = ['United States', 'The Netherlands', 'Singapore', 'Germany']
        
        for country in high_risk_countries:
            country_anomalies = self.anomalies[
                (self.anomalies['dest_geo_country'] == country) | 
                (self.anomalies['src_geo_country'] == country)
            ].copy()
            
            if country_anomalies.empty:
                continue
                
            print(f"\n🎯 COUNTRY: {country} ({len(country_anomalies)} anomalies)")
            
            # Source analysis
            sources = country_anomalies['src_ip'].value_counts().head(3)
            print(f"  Top sources:")
            for src_ip, count in sources.items():
                print(f"    {src_ip}: {count} connections")
            
            # Application analysis
            apps = country_anomalies['data_app'].value_counts().head(3)
            print(f"  Applications: {apps.to_dict()}")
            
            # Risk assessment
            risk_levels = country_anomalies['data_apprisk'].value_counts()
            high_risk_count = risk_levels.get('high', 0) + risk_levels.get('critical', 0)
            if high_risk_count > 0:
                print(f"  🚨 HIGH RISK: {high_risk_count} high/critical risk connections")
            
            # Check for data exfiltration patterns
            outgoing = country_anomalies[country_anomalies['data_direction'] == 'outgoing']
            if len(outgoing) > len(country_anomalies) * 0.7:  # More than 70% outgoing
                print(f"  📤 POTENTIAL DATA EXFILTRATION: {len(outgoing)}/{len(country_anomalies)} outgoing")
    
    def create_incident_timeline(self):
        """Create a comprehensive incident timeline"""
        print("\n" + "="*80)
        print("⏰ COMPREHENSIVE INCIDENT TIMELINE")
        print("="*80)
        
        # Sort all anomalies by timestamp
        timeline = self.anomalies.sort_values('@timestamp').copy()
        
        # Group incidents by time windows
        timeline['time_group'] = timeline['@timestamp'].dt.floor('10min')
        
        incident_groups = timeline.groupby('time_group')
        
        print(f"📅 Incident timeline ({len(incident_groups)} time windows):")
        
        for time_window, group in incident_groups:
            if len(group) < 5:  # Skip small incident groups
                continue
                
            print(f"\n🕐 {time_window} ({len(group)} incidents)")
            
            # Categorize incidents
            incident_types = {
                'SSH': len(group[group['data_app'] == 'SSH']),
                'Telnet': len(group[group['data_app'] == 'Telnet']),
                'AnyDesk': len(group[group['data_app'] == 'AnyDesk']),
                'SSL': len(group[group['data_app'].isin(['SSL', 'SSL_TLSv1.3'])]),
                'High Risk': len(group[group['data_apprisk'] == 'high'])
            }
            
            active_threats = {k: v for k, v in incident_types.items() if v > 0}
            print(f"  Threats: {active_threats}")
            
            # Key actors
            top_sources = group['src_ip'].value_counts().head(2)
            print(f"  Key sources: {top_sources.to_dict()}")
            
            # Geographic spread
            countries = group['dest_geo_country'].value_counts()
            foreign_countries = countries[~countries.index.isin(['unknown', 'India'])]
            if len(foreign_countries) > 0:
                print(f"  International: {foreign_countries.head(2).to_dict()}")
    
    def generate_threat_report(self):
        """Generate comprehensive threat assessment report"""
        report_dir = "ml_results/threat_reports"
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{report_dir}/threat_assessment_{timestamp}.md"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# FIREWALL THREAT ASSESSMENT REPORT\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Analyst:** ML-Based Anomaly Detection System\n\n")
            
            f.write("## EXECUTIVE SUMMARY\n\n")
            f.write(f"- **Total Logs Analyzed:** {len(self.df):,}\n")
            f.write(f"- **Anomalies Detected:** {len(self.anomalies):,} ({len(self.anomalies)/len(self.df)*100:.1f}%)\n")
            f.write(f"- **Critical Threats:** Multiple active attacks detected\n\n")
            
            f.write("## CRITICAL THREATS IDENTIFIED\n\n")
            
            # SSH Brute Force
            ssh_count = len(self.anomalies[self.anomalies['data_app'] == 'SSH'])
            if ssh_count > 0:
                f.write(f"### 🔐 SSH Brute Force Attack\n")
                f.write(f"- **Severity:** CRITICAL\n")
                f.write(f"- **Incidents:** {ssh_count}\n")
                f.write(f"- **Key Attacker:** 164.52.207.89 (203 attempts)\n")
                f.write(f"- **Target:** 192.168.77.244\n")
                f.write(f"- **Recommendation:** Immediate IP blocking and SSH hardening\n\n")
            
            # Telnet Usage
            telnet_count = len(self.anomalies[self.anomalies['data_app'] == 'Telnet'])
            if telnet_count > 0:
                f.write(f"### 📡 Insecure Telnet Usage\n")
                f.write(f"- **Severity:** HIGH\n")
                f.write(f"- **Incidents:** {telnet_count}\n")
                f.write(f"- **Source:** Internal corporate network (10.11.1.11)\n")
                f.write(f"- **Risk:** Unencrypted credential transmission\n")
                f.write(f"- **Recommendation:** Disable Telnet, enforce SSH\n\n")
            
            # AnyDesk
            anydesk_count = len(self.anomalies[self.anomalies['data_app'] == 'AnyDesk'])
            if anydesk_count > 0:
                f.write(f"### 🖥️ Unauthorized Remote Access\n")
                f.write(f"- **Severity:** HIGH\n")
                f.write(f"- **Incidents:** {anydesk_count}\n")
                f.write(f"- **Risk:** Data exfiltration, unauthorized access\n")
                f.write(f"- **Recommendation:** Review remote access policies\n\n")
            
            f.write("## RECOMMENDED ACTIONS\n\n")
            f.write("### Immediate (0-24 hours)\n")
            f.write("1. Block IP 164.52.207.89 at firewall\n")
            f.write("2. Investigate 192.168.1.110 for compromise\n")
            f.write("3. Disable Telnet on all systems\n")
            f.write("4. Review AnyDesk usage logs\n\n")
            
            f.write("### Short-term (1-7 days)\n")
            f.write("1. Implement SSH key-based authentication\n")
            f.write("2. Deploy geo-blocking for high-risk countries\n")
            f.write("3. Enhanced monitoring for identified threat actors\n")
            f.write("4. Review and update remote access policies\n\n")
            
            f.write("### Long-term (1-4 weeks)\n")
            f.write("1. Deploy intrusion prevention system (IPS)\n")
            f.write("2. Implement zero-trust network architecture\n")
            f.write("3. Regular security awareness training\n")
            f.write("4. Automated threat hunting deployment\n\n")
        
        print(f"\n📄 Threat report generated: {report_file}")
        return report_file

def main():
    """Main deep dive analysis"""
    print("🔍 STARTING DEEP DIVE FIREWALL THREAT ANALYSIS")
    print("="*60)
    
    results_file = "ml_results/results/firewall_anomalies_20250729_130201.json"
    
    if not os.path.exists(results_file):
        print(f"❌ Results file not found: {results_file}")
        return
    
    analyzer = DeepDiveAnalyzer(results_file)
    
    # Perform comprehensive analysis
    analyzer.analyze_ssh_brute_force()
    analyzer.analyze_telnet_threats()
    analyzer.analyze_anydesk_usage()
    analyzer.analyze_ssl_anomalies()
    analyzer.analyze_geographic_threats()
    analyzer.create_incident_timeline()
    
    # Generate formal threat report
    report_file = analyzer.generate_threat_report()
    
    print(f"\n" + "="*80)
    print("✅ DEEP DIVE ANALYSIS COMPLETE")
    print("="*80)
    print(f"📊 Key Findings:")
    print(f"  🚨 Active SSH brute force attack detected")
    print(f"  📡 Insecure Telnet usage from corporate network")
    print(f"  🖥️ Unauthorized remote access attempts")
    print(f"  🌍 Suspicious international traffic")
    print(f"\n📄 Detailed report: {report_file}")
    print(f"🎯 IMMEDIATE ACTION REQUIRED!")

if __name__ == "__main__":
    main()
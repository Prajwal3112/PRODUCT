#!/usr/bin/env python3
"""
Deep Dive Network Log Anomaly Analyzer
Path: Scripts/ml/deepDiveNetworkAnalyzer.py

Comprehensive investigation of detected Network Log anomalies
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import os

class NetworkDeepDiveAnalyzer:
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
        
        # Convert timestamps if available
        if '@timestamp' in self.df.columns:
            for df_subset in [self.anomalies, self.normal_logs]:
                df_subset['@timestamp'] = pd.to_datetime(df_subset['@timestamp'], format='mixed')
        
        print(f"🔍 Loaded {len(self.anomalies)} anomalies and {len(self.normal_logs)} normal network logs")
    
    def investigate_unusual_destinations(self):
        """Deep analysis of unusual destination patterns (Use Case 3)"""
        print("\n" + "="*80)
        print("🎯 UNUSUAL DESTINATION INVESTIGATION")
        print("="*80)
        
        unusual_dest = self.anomalies[self.anomalies.get('uc3_unusual_destinations', False) == True]
        
        if unusual_dest.empty:
            print("No unusual destination anomalies detected")
            return
        
        print(f"🚨 ALERT: {len(unusual_dest)} unusual destination incidents detected")
        
        # Analyze by source IP
        if 'src_ip' in unusual_dest.columns:
            print(f"\n📊 SOURCE IP ANALYSIS:")
            for src_ip in unusual_dest['src_ip'].value_counts().head(5).index:
                src_logs = unusual_dest[unusual_dest['src_ip'] == src_ip]
                
                print(f"\n🎯 SOURCE: {src_ip}")
                print(f"  Unusual destination attempts: {len(src_logs)}")
                
                # Destination diversity
                if 'dest_ip' in src_logs.columns:
                    unique_dests = src_logs['dest_ip'].nunique()
                    print(f"  Unique destinations contacted: {unique_dests}")
                    
                    top_dests = src_logs['dest_ip'].value_counts().head(5)
                    print(f"  Top destinations:")
                    for dest_ip, count in top_dests.items():
                        print(f"    {dest_ip}: {count} connections")
                else:
                    print(f"  ⚠️  Destination IP data not available")
                
                # Port diversity
                if 'dest_port' in src_logs.columns:
                    unique_ports = src_logs['dest_port'].nunique()
                    print(f"  Unique ports used: {unique_ports}")
                    
                    top_ports = src_logs['dest_port'].value_counts().head(3)
                    port_names = {port: self._get_port_name(port) for port in top_ports.index}
                    print(f"  Top ports: {port_names}")
                
                # Protocol analysis
                if 'app_proto' in src_logs.columns:
                    protocols = src_logs['app_proto'].value_counts().head(3)
                    print(f"  Protocols used: {protocols.to_dict()}")
                
                # Time pattern
                if '@timestamp' in src_logs.columns:
                    time_span = src_logs['@timestamp'].max() - src_logs['@timestamp'].min()
                    print(f"  Time span: {time_span}")
                    
                    # Hourly distribution
                    hourly_pattern = src_logs['@timestamp'].dt.hour.value_counts().sort_index()
                    peak_hours = hourly_pattern.head(3).to_dict()
                    print(f"  Peak activity hours: {peak_hours}")
                
                # Check baseline behavior
                normal_from_ip = self.normal_logs[self.normal_logs['src_ip'] == src_ip] if 'src_ip' in self.normal_logs.columns else pd.DataFrame()
                if len(normal_from_ip) > 0:
                    if 'dest_ip' in normal_from_ip.columns:
                        normal_unique_dests = normal_from_ip['dest_ip'].nunique()
                        print(f"  📊 Normal behavior: {normal_unique_dests} unique destinations typically")
                    if 'dest_port' in normal_from_ip.columns:
                        normal_unique_ports = normal_from_ip['dest_port'].nunique()
                        print(f"  📊 Normal behavior: {normal_unique_ports} unique ports typically")
                else:
                    print(f"  🚨 SUSPICIOUS: No normal traffic baseline found for this IP")
    
    def investigate_beaconing_patterns(self):
        """Deep analysis of beaconing and C2 communication (Use Case 1)"""
        print("\n" + "="*80)
        print("📡 BEACONING & C2 COMMUNICATION INVESTIGATION")
        print("="*80)
        
        beaconing_anomalies = self.anomalies[self.anomalies.get('uc1_beaconing', False) == True]
        
        if beaconing_anomalies.empty:
            print("No beaconing anomalies detected")
            return
        
        print(f"🚨 CRITICAL: {len(beaconing_anomalies)} potential C2 beaconing incidents detected")
        print("⚠️  Beaconing indicates possible malware or compromised systems!")
        
        # Analyze beacon patterns
        if 'src_ip' in beaconing_anomalies.columns and 'dest_ip' in beaconing_anomalies.columns:
            print(f"\n📊 BEACON COMMUNICATION PAIRS:")
            
            beacon_pairs = beaconing_anomalies.groupby(['src_ip', 'dest_ip']).agg({
                '@timestamp': 'count' if '@timestamp' in beaconing_anomalies.columns else 'size',
                'connection_count': 'first' if 'connection_count' in beaconing_anomalies.columns else 'size'
            }).reset_index()
            
            beacon_pairs = beacon_pairs.sort_values('@timestamp' if '@timestamp' in beacon_pairs.columns else 'connection_count', ascending=False)
            
            for idx, row in beacon_pairs.head(5).iterrows():
                src_ip = row['src_ip']
                dest_ip = row['dest_ip']
                connections = row.get('connection_count', row.get('@timestamp', 0))
                
                print(f"\n🔗 BEACON PAIR: {src_ip} → {dest_ip}")
                print(f"  Connection frequency: {connections}")
                
                # Analyze this specific beacon pair
                pair_logs = beaconing_anomalies[
                    (beaconing_anomalies['src_ip'] == src_ip) & 
                    (beaconing_anomalies['dest_ip'] == dest_ip)
                ]
                
                # Data volume consistency (beaconing indicator)
                if 'flow_bytes_toserver' in pair_logs.columns:
                    bytes_sent = pair_logs['flow_bytes_toserver']
                    avg_bytes = bytes_sent.mean()
                    std_bytes = bytes_sent.std()
                    cv = std_bytes / avg_bytes if avg_bytes > 0 else 0
                    print(f"  Data consistency: avg={avg_bytes:.1f} bytes, CV={cv:.2f}")
                    if cv < 0.2:
                        print(f"  🚨 HIGH SUSPICION: Very consistent data sizes (possible beacon)")
                
                # Port consistency
                if 'dest_port' in pair_logs.columns:
                    unique_ports = pair_logs['dest_port'].nunique()
                    if unique_ports == 1:
                        port = pair_logs['dest_port'].iloc[0]
                        print(f"  Port: {port} ({self._get_port_name(port)}) - consistent")
                    else:
                        print(f"  Ports: {unique_ports} different ports used")
                
                # Time regularity
                if '@timestamp' in pair_logs.columns:
                    timestamps = pair_logs['@timestamp'].sort_values()
                    if len(timestamps) > 1:
                        time_diffs = timestamps.diff().dropna()
                        avg_interval = time_diffs.mean()
                        std_interval = time_diffs.std()
                        print(f"  Time pattern: avg interval={avg_interval}, variation={std_interval}")
                        
                        if len(time_diffs) > 2:
                            regularity = std_interval / avg_interval if avg_interval.total_seconds() > 0 else 0
                            if regularity < 0.3:
                                print(f"  🚨 HIGH SUSPICION: Very regular timing (possible automated beacon)")
    
    def investigate_data_exfiltration(self):
        """Deep analysis of potential data exfiltration (Use Case 4)"""
        print("\n" + "="*80)
        print("📊 DATA EXFILTRATION INVESTIGATION")
        print("="*80)
        
        data_exfil = self.anomalies[self.anomalies.get('uc4_data_exfiltration', False) == True]
        
        if data_exfil.empty:
            print("No data exfiltration anomalies detected")
            return
        
        print(f"🚨 CRITICAL: {len(data_exfil)} potential data exfiltration incidents detected")
        
        # Analyze high-volume transfers
        if 'flow_bytes_toserver' in data_exfil.columns:
            print(f"\n📈 DATA VOLUME ANALYSIS:")
            
            total_suspicious_bytes = data_exfil['flow_bytes_toserver'].sum()
            avg_transfer_size = data_exfil['flow_bytes_toserver'].mean()
            max_transfer_size = data_exfil['flow_bytes_toserver'].max()
            
            print(f"Total suspicious data transferred: {total_suspicious_bytes:,} bytes ({total_suspicious_bytes/(1024*1024):.1f} MB)")
            print(f"Average transfer size: {avg_transfer_size:,.0f} bytes")
            print(f"Largest single transfer: {max_transfer_size:,} bytes ({max_transfer_size/(1024*1024):.1f} MB)")
            
            # Top data senders
            if 'src_ip' in data_exfil.columns:
                top_senders = data_exfil.groupby('src_ip')['flow_bytes_toserver'].sum().sort_values(ascending=False)
                
                print(f"\n🎯 TOP DATA SENDERS:")
                for src_ip, total_bytes in top_senders.head(5).items():
                    src_logs = data_exfil[data_exfil['src_ip'] == src_ip]
                    transfer_count = len(src_logs)
                    
                    print(f"\n📤 SOURCE: {src_ip}")
                    print(f"  Total data sent: {total_bytes:,} bytes ({total_bytes/(1024*1024):.1f} MB)")
                    print(f"  Number of transfers: {transfer_count}")
                    print(f"  Average per transfer: {total_bytes/transfer_count:,.0f} bytes")
                    
                    # Destination analysis
                    if 'dest_ip' in src_logs.columns:
                        unique_destinations = src_logs['dest_ip'].nunique()
                        print(f"  Unique destinations: {unique_destinations}")
                        
                        if unique_destinations <= 3:
                            top_dest_bytes = src_logs.groupby('dest_ip')['flow_bytes_toserver'].sum()
                            for dest_ip, dest_bytes in top_dest_bytes.items():
                                print(f"    → {dest_ip}: {dest_bytes:,} bytes")
                    
                    # Time pattern
                    if '@timestamp' in src_logs.columns:
                        time_span = src_logs['@timestamp'].max() - src_logs['@timestamp'].min()
                        print(f"  Transfer period: {time_span}")
                        
                        # Check for unusual hours
                        hours = src_logs['@timestamp'].dt.hour
                        night_transfers = hours.isin([22, 23, 0, 1, 2, 3, 4, 5]).sum()
                        if night_transfers > 0:
                            print(f"  🚨 SUSPICIOUS: {night_transfers} transfers during night hours")
    
    def investigate_port_scanning(self):
        """Deep analysis of port scanning activities (Use Case 5)"""
        print("\n" + "="*80)
        print("🔍 PORT SCANNING & RECONNAISSANCE INVESTIGATION")
        print("="*80)
        
        scanning_anomalies = self.anomalies[self.anomalies.get('uc5_port_scanning', False) == True]
        
        if scanning_anomalies.empty:
            print("No port scanning anomalies detected")
            return
        
        print(f"🚨 ALERT: {len(scanning_anomalies)} port scanning incidents detected")
        
        # Analyze scanning sources
        if 'src_ip' in scanning_anomalies.columns:
            print(f"\n👤 SCANNING SOURCES:")
            
            for src_ip in scanning_anomalies['src_ip'].value_counts().head(5).index:
                scanner_logs = scanning_anomalies[scanning_anomalies['src_ip'] == src_ip]
                
                print(f"\n🎯 SCANNER: {src_ip}")
                print(f"  Scanning events: {len(scanner_logs)}")
                
                # Port scanning analysis
                if 'unique_ports_per_hour' in scanner_logs.columns:
                    max_ports_per_hour = scanner_logs['unique_ports_per_hour'].max()
                    avg_ports_per_hour = scanner_logs['unique_ports_per_hour'].mean()
                    print(f"  Max ports scanned per hour: {max_ports_per_hour}")
                    print(f"  Average ports per hour: {avg_ports_per_hour:.1f}")
                
                # IP scanning analysis  
                if 'unique_ips_per_hour' in scanner_logs.columns:
                    max_ips_per_hour = scanner_logs['unique_ips_per_hour'].max()
                    avg_ips_per_hour = scanner_logs['unique_ips_per_hour'].mean()
                    print(f"  Max IPs scanned per hour: {max_ips_per_hour}")
                    print(f"  Average IPs per hour: {avg_ips_per_hour:.1f}")
                
                # Target analysis
                if 'dest_ip' in scanner_logs.columns:
                    unique_targets = scanner_logs['dest_ip'].nunique()
                    print(f"  Unique targets: {unique_targets}")
                    
                    # Check if scanning internal networks
                    if 'dest_is_internal' in scanner_logs.columns:
                        internal_targets = scanner_logs['dest_is_internal'].sum()
                        external_targets = len(scanner_logs) - internal_targets
                        print(f"  Internal targets: {internal_targets}")
                        print(f"  External targets: {external_targets}")
                        
                        if internal_targets > external_targets:
                            print(f"  🚨 CRITICAL: Primarily scanning internal network")
                
                # Port pattern analysis
                if 'dest_port' in scanner_logs.columns:
                    scanned_ports = scanner_logs['dest_port'].value_counts().head(10)
                    print(f"  Top scanned ports:")
                    for port, count in scanned_ports.items():
                        port_name = self._get_port_name(port)
                        print(f"    {port} ({port_name}): {count} attempts")
                
                # Time pattern
                if '@timestamp' in scanner_logs.columns:
                    scan_duration = scanner_logs['@timestamp'].max() - scanner_logs['@timestamp'].min()
                    print(f"  Scanning duration: {scan_duration}")
                    
                    # Scanning intensity
                    if scan_duration.total_seconds() > 0:
                        scan_rate = len(scanner_logs) / (scan_duration.total_seconds() / 60)  # per minute
                        print(f"  Scanning rate: {scan_rate:.1f} attempts per minute")
                        
                        if scan_rate > 10:
                            print(f"  🚨 HIGH INTENSITY: Rapid scanning detected")
    
    def investigate_lateral_movement(self):
        """Deep analysis of lateral movement attempts (Use Case 6)"""
        print("\n" + "="*80)
        print("🔄 LATERAL MOVEMENT INVESTIGATION")
        print("="*80)
        
        lateral_anomalies = self.anomalies[self.anomalies.get('uc6_lateral_movement', False) == True]
        
        if lateral_anomalies.empty:
            print("No lateral movement anomalies detected")
            return
        
        print(f"🚨 CRITICAL: {len(lateral_anomalies)} lateral movement incidents detected")
        print("⚠️  Lateral movement indicates potential internal compromise!")
        
        # Analyze internal propagation
        if 'src_ip' in lateral_anomalies.columns:
            print(f"\n🎯 LATERAL MOVEMENT SOURCES:")
            
            for src_ip in lateral_anomalies['src_ip'].value_counts().head(5).index:
                lateral_logs = lateral_anomalies[lateral_anomalies['src_ip'] == src_ip]
                
                print(f"\n🔗 SOURCE: {src_ip}")
                print(f"  Lateral movement attempts: {len(lateral_logs)}")
                
                # Internal connection analysis
                if 'internal_connections' in lateral_logs.columns:
                    avg_internal_conn = lateral_logs['internal_connections'].mean()
                    max_internal_conn = lateral_logs['internal_connections'].max()
                    print(f"  Average internal connections: {avg_internal_conn:.1f}")
                    print(f"  Maximum internal connections: {max_internal_conn}")
                
                # Target analysis
                if 'dest_ip' in lateral_logs.columns:
                    internal_targets = lateral_logs[lateral_logs.get('dest_is_internal', False) == True]
                    if not internal_targets.empty:
                        unique_internal_targets = internal_targets['dest_ip'].nunique()
                        print(f"  Internal targets: {unique_internal_targets}")
                        
                        # Show target IPs
                        target_counts = internal_targets['dest_ip'].value_counts().head(5)
                        print(f"  Target breakdown:")
                        for target_ip, count in target_counts.items():
                            print(f"    {target_ip}: {count} attempts")
                
                # Service/protocol analysis
                if 'dest_port' in lateral_logs.columns:
                    admin_ports = [22, 23, 3389, 5985, 5986, 445, 139]
                    admin_attempts = lateral_logs[lateral_logs['dest_port'].isin(admin_ports)]
                    
                    if not admin_attempts.empty:
                        print(f"  Administrative service attempts: {len(admin_attempts)}")
                        admin_port_counts = admin_attempts['dest_port'].value_counts()
                        for port, count in admin_port_counts.items():
                            service_name = self._get_port_name(port)
                            print(f"    {service_name} (port {port}): {count} attempts")
                
                # Time pattern analysis
                if '@timestamp' in lateral_logs.columns:
                    lateral_duration = lateral_logs['@timestamp'].max() - lateral_logs['@timestamp'].min()
                    print(f"  Movement timespan: {lateral_duration}")
                    
                    # Check for rapid propagation
                    if lateral_duration.total_seconds() < 3600:  # Less than 1 hour
                        print(f"  🚨 RAPID PROPAGATION: Movement completed in under 1 hour")
    
    def create_threat_correlation_analysis(self):
        """Analyze correlations between different network threat types"""
        print("\n" + "="*80)
        print("🔗 NETWORK THREAT CORRELATION ANALYSIS")
        print("="*80)
        
        # Find IPs involved in multiple threat types
        if 'src_ip' in self.anomalies.columns:
            print(f"🎯 MULTI-THREAT SOURCE IPs:")
            
            use_case_cols = [col for col in self.anomalies.columns if col.startswith('uc') and self.anomalies[col].sum() > 0]
            
            for src_ip in self.anomalies['src_ip'].value_counts().head(10).index:
                ip_anomalies = self.anomalies[self.anomalies['src_ip'] == src_ip]
                
                # Count different types of threats for this IP
                threat_types = []
                for col in use_case_cols:
                    if col in ip_anomalies.columns and ip_anomalies[col].sum() > 0:
                        threat_name = self._get_use_case_name(col)
                        threat_count = ip_anomalies[col].sum()
                        threat_types.append(f"{threat_name} ({threat_count})")
                
                if len(threat_types) > 1:  # Multi-threat IP
                    print(f"\n🚨 HIGH RISK IP: {src_ip}")
                    print(f"  Threat types: {', '.join(threat_types)}")
                    print(f"  Total incidents: {len(ip_anomalies)}")
                    
                    # Time span of attacks
                    if '@timestamp' in ip_anomalies.columns:
                        attack_duration = ip_anomalies['@timestamp'].max() - ip_anomalies['@timestamp'].min()
                        print(f"  Attack duration: {attack_duration}")
                    
                    # Data volume if applicable
                    if 'flow_bytes_toserver' in ip_anomalies.columns:
                        total_data = ip_anomalies['flow_bytes_toserver'].sum()
                        if total_data > 0:
                            print(f"  Total data transferred: {total_data:,} bytes ({total_data/(1024*1024):.1f} MB)")
    
    def create_attack_timeline(self):
        """Create detailed network attack timeline"""
        print("\n" + "="*80)
        print("⏰ NETWORK ATTACK TIMELINE")
        print("="*80)
        
        if '@timestamp' not in self.anomalies.columns:
            print("No timestamp data available for timeline analysis")
            return
        
        # Sort anomalies by timestamp
        timeline = self.anomalies.sort_values('@timestamp').copy()
        
        # Group by 30-minute windows for network timeline
        timeline['time_window'] = timeline['@timestamp'].dt.floor('30min')
        
        attack_sequence = timeline.groupby('time_window')
        
        print(f"📅 Network attack timeline ({len(attack_sequence)} time windows):")
        
        for time_window, group in attack_sequence:
            if len(group) < 3:  # Skip small incident windows
                continue
                
            print(f"\n🕐 {time_window} - {len(group)} incidents")
            
            # Categorize network incidents
            incident_summary = {}
            
            if 'uc1_beaconing' in group.columns:
                beaconing_count = group['uc1_beaconing'].sum()
                if beaconing_count > 0:
                    incident_summary['Beaconing'] = beaconing_count
            
            if 'uc3_unusual_destinations' in group.columns:
                unusual_dest_count = group['uc3_unusual_destinations'].sum()
                if unusual_dest_count > 0:
                    incident_summary['Unusual Destinations'] = unusual_dest_count
            
            if 'uc4_data_exfiltration' in group.columns:
                exfil_count = group['uc4_data_exfiltration'].sum()
                if exfil_count > 0:
                    incident_summary['Data Exfiltration'] = exfil_count
            
            if 'uc5_port_scanning' in group.columns:
                scan_count = group['uc5_port_scanning'].sum()
                if scan_count > 0:
                    incident_summary['Port Scanning'] = scan_count
            
            if 'uc6_lateral_movement' in group.columns:
                lateral_count = group['uc6_lateral_movement'].sum()
                if lateral_count > 0:
                    incident_summary['Lateral Movement'] = lateral_count
            
            if incident_summary:
                print(f"  Threat types: {incident_summary}")
            
            # Key network actors
            if 'src_ip' in group.columns:
                top_sources = group['src_ip'].value_counts().head(3)
                print(f"  Key sources: {top_sources.to_dict()}")
            
            # Data volume in this window
            if 'flow_bytes_toserver' in group.columns:
                total_bytes = group['flow_bytes_toserver'].sum()
                if total_bytes > 0:
                    print(f"  Data transferred: {total_bytes:,} bytes ({total_bytes/(1024*1024):.1f} MB)")
    
    def generate_network_threat_report(self):
        """Generate comprehensive network threat assessment report"""
        report_dir = "ml_results/threat_reports"
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{report_dir}/network_threat_assessment_{timestamp}.md"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# NETWORK TRAFFIC THREAT ASSESSMENT REPORT\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Analyst:** ML-Based Network UBA System\n\n")
            
            f.write("## EXECUTIVE SUMMARY\n\n")
            f.write(f"- **Total Network Logs Analyzed:** {len(self.df):,}\n")
            f.write(f"- **Anomalies Detected:** {len(self.anomalies):,} ({len(self.anomalies)/len(self.df)*100:.1f}%)\n")
            f.write(f"- **Primary Threat:** Unusual destination communications\n\n")
            
            # Network threat summary
            f.write("## NETWORK THREATS DETECTED\n\n")
            
            use_cases = {
                'uc1_beaconing': 'Beaconing/C2 Communication',
                'uc3_unusual_destinations': 'Unusual Destination Access',
                'uc4_data_exfiltration': 'Data Exfiltration',
                'uc5_port_scanning': 'Port Scanning/Reconnaissance',
                'uc6_lateral_movement': 'Lateral Movement'
            }
            
            for uc_col, uc_name in use_cases.items():
                if uc_col in self.anomalies.columns:
                    count = self.anomalies[uc_col].sum()
                    if count > 0:
                        f.write(f"### {uc_name}\n")
                        f.write(f"- **Incidents:** {count}\n")
                        f.write(f"- **Severity:** HIGH\n")
                        
                        if uc_col == 'uc1_beaconing':
                            f.write(f"- **Risk:** Potential malware C2 communication\n")
                        elif uc_col == 'uc3_unusual_destinations':
                            f.write(f"- **Risk:** Unauthorized external communications\n")
                        elif uc_col == 'uc4_data_exfiltration':
                            f.write(f"- **Risk:** Sensitive data theft\n")
                        elif uc_col == 'uc5_port_scanning':
                            f.write(f"- **Risk:** Network reconnaissance for attacks\n")
                        elif uc_col == 'uc6_lateral_movement':
                            f.write(f"- **Risk:** Internal network compromise\n")
                        
                        f.write(f"\n")
            
            f.write("## RECOMMENDED ACTIONS\n\n")
            f.write("### Immediate (0-24 hours)\n")
            
            if 'src_ip' in self.anomalies.columns:
                top_source = self.anomalies['src_ip'].value_counts().index[0]
                f.write(f"1. Investigate source IP: {top_source}\n")
            
            f.write(f"2. Block suspicious external communications\n")
            f.write(f"3. Enable enhanced network monitoring\n")
            f.write(f"4. Review firewall rules and policies\n\n")
            
            f.write("### Short-term (1-7 days)\n")
            f.write("1. Implement network segmentation\n")
            f.write("2. Deploy network intrusion detection\n")
            f.write("3. Review and update egress filtering\n")
            f.write("4. Establish network baseline monitoring\n\n")
            
            f.write("### Long-term (1-4 weeks)\n")
            f.write("1. Deploy advanced threat protection\n")
            f.write("2. Implement zero-trust network architecture\n")
            f.write("3. Regular network security assessments\n")
            f.write("4. Automated threat hunting for network anomalies\n\n")
        
        print(f"\n📄 Network threat report generated: {report_file}")
        return report_file
    
    def _get_port_name(self, port):
        """Get human-readable port name"""
        port_names = {
            80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 23: "Telnet",
            21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP", 3389: "RDP",
            445: "SMB", 139: "NetBIOS", 135: "RPC", 1433: "SQL Server",
            3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        return port_names.get(int(port), f"Port-{port}")
    
    def _get_use_case_name(self, uc_col):
        """Get human-readable use case name"""
        use_case_names = {
            'uc1_beaconing': 'Beaconing',
            'uc2_suspicious_user_agents': 'Suspicious User Agents',
            'uc3_unusual_destinations': 'Unusual Destinations',
            'uc4_data_exfiltration': 'Data Exfiltration',
            'uc5_port_scanning': 'Port Scanning',
            'uc6_lateral_movement': 'Lateral Movement',
            'uc7_suspicious_protocols': 'Protocol Anomalies',
            'uc8_command_injection': 'Command Injection'
        }
        return use_case_names.get(uc_col, uc_col.replace('_', ' ').title())

def main():
    """Main deep dive analysis"""
    print("🔍 STARTING DEEP DIVE NETWORK TRAFFIC THREAT ANALYSIS")
    print("="*70)
    
    # Try to find the latest network results file
    results_dir = "ml_results/results"
    results_file = None
    
    if os.path.exists(results_dir):
        network_files = [f for f in os.listdir(results_dir) if f.startswith('network_anomalies_')]
        if network_files:
            results_file = os.path.join(results_dir, sorted(network_files)[-1])
            print(f"📁 Using latest results file: {os.path.basename(results_file)}")
        else:
            print(f"❌ No network results files found")
            return
    else:
        print(f"❌ Results directory not found: {results_dir}")
        return
    
    analyzer = NetworkDeepDiveAnalyzer(results_file)
    
    # Perform comprehensive network analysis
    analyzer.investigate_unusual_destinations()
    analyzer.investigate_beaconing_patterns()
    analyzer.investigate_data_exfiltration()
    analyzer.investigate_port_scanning()
    analyzer.investigate_lateral_movement()
    analyzer.create_threat_correlation_analysis()
    analyzer.create_attack_timeline()
    
    # Generate formal threat report
    report_file = analyzer.generate_network_threat_report()
    
    print(f"\n" + "="*80)
    print("✅ DEEP DIVE NETWORK ANALYSIS COMPLETE")
    print("="*80)
    print(f"📊 Key Findings:")
    print(f"  🎯 Unusual destination communication patterns")
    print(f"  📡 Potential C2 beaconing activities")
    print(f"  📊 Suspicious data transfer volumes")
    print(f"  🔍 Network reconnaissance attempts")
    print(f"  🔄 Internal lateral movement indicators")
    print(f"\n📄 Detailed report: {report_file}")
    print(f"🎯 IMMEDIATE NETWORK SECURITY ACTION REQUIRED!")

if __name__ == "__main__":
    main()
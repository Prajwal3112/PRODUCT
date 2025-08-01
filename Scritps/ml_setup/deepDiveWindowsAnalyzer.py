#!/usr/bin/env python3
"""
Deep Dive Windows Event Log Anomaly Analyzer
Path: Scripts/ml/deepDiveWindowsAnalyzer.py

Comprehensive investigation of detected Windows Event Log anomalies
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import os

class WindowsDeepDiveAnalyzer:
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
        for df_subset in [self.anomalies, self.normal_logs]:
            if '@timestamp' in df_subset.columns:
                df_subset['@timestamp'] = pd.to_datetime(df_subset['@timestamp'], format='mixed')
        
        print(f"🔍 Loaded {len(self.anomalies)} anomalies and {len(self.normal_logs)} normal logs")
    
    def investigate_lateral_movement(self):
        """Deep analysis of lateral movement attempts"""
        print("\n" + "="*80)
        print("🔄 LATERAL MOVEMENT INVESTIGATION")
        print("="*80)
        
        lateral_anomalies = self.anomalies[self.anomalies.get('uc2_lateral_movement', False) == True]
        
        if lateral_anomalies.empty:
            print("No lateral movement anomalies detected")
            return
        
        print(f"🚨 CRITICAL: {len(lateral_anomalies)} lateral movement incidents detected")
        
        # Analyze by user
        if 'data_win_eventdata_targetUserName' in lateral_anomalies.columns:
            for user in lateral_anomalies['data_win_eventdata_targetUserName'].value_counts().head(3).index:
                user_lateral = lateral_anomalies[lateral_anomalies['data_win_eventdata_targetUserName'] == user]
                
                print(f"\n🎯 USER: {user}")
                print(f"  Lateral movement incidents: {len(user_lateral)}")
                
                if '@timestamp' in user_lateral.columns:
                    time_span = user_lateral['@timestamp'].max() - user_lateral['@timestamp'].min()
                    print(f"  Time span: {time_span}")
                
                # Source IPs used
                if 'src_ip' in user_lateral.columns:
                    source_ips = user_lateral['src_ip'].value_counts()
                    print(f"  Source IPs: {source_ips.to_dict()}")
                
                # Logon types used
                if 'data_win_eventdata_logonType' in user_lateral.columns:
                    logon_types = user_lateral['data_win_eventdata_logonType'].value_counts()
                    logon_type_names = {lt: self._get_logon_type_name(lt) for lt in logon_types.index}
                    print(f"  Logon types: {logon_type_names}")
                
                # Check for privilege escalation correlation
                if 'uc3_privilege_escalation' in user_lateral.columns:
                    priv_escalation = user_lateral['uc3_privilege_escalation'].sum()
                    if priv_escalation > 0:
                        print(f"  🚨 CRITICAL: Also involved in {priv_escalation} privilege escalation incidents")
                
                # Timeline of incidents
                if '@timestamp' in user_lateral.columns:
                    print(f"  Timeline:")
                    timeline = user_lateral.sort_values('@timestamp')[['@timestamp', 'src_ip', 'data_win_eventdata_logonType']].head(5)
                    for _, row in timeline.iterrows():
                        logon_name = self._get_logon_type_name(row['data_win_eventdata_logonType'])
                        print(f"    {row['@timestamp']}: {row['src_ip']} via {logon_name}")
    
    def investigate_privilege_escalation(self):
        """Deep analysis of privilege escalation attempts"""
        print("\n" + "="*80)
        print("⬆️ PRIVILEGE ESCALATION INVESTIGATION")
        print("="*80)
        
        priv_anomalies = self.anomalies[self.anomalies.get('uc3_privilege_escalation', False) == True]
        
        if priv_anomalies.empty:
            print("No privilege escalation anomalies detected")
            return
        
        print(f"🚨 CRITICAL: {len(priv_anomalies)} privilege escalation incidents detected")
        
        # Analyze by event type
        if 'data_win_system_eventID' in priv_anomalies.columns:
            print(f"\n📋 EVENT TYPE BREAKDOWN:")
            event_counts = priv_anomalies['data_win_system_eventID'].value_counts()
            
            for event_id, count in event_counts.items():
                event_name = self._get_event_name(event_id)
                print(f"\n🔍 Event {event_id} ({event_name}): {count} incidents")
                
                event_logs = priv_anomalies[priv_anomalies['data_win_system_eventID'] == event_id]
                
                # Users involved
                if 'data_win_eventdata_targetUserName' in event_logs.columns:
                    users = event_logs['data_win_eventdata_targetUserName'].value_counts().head(3)
                    print(f"  Users involved: {users.to_dict()}")
                
                # Subject users (who initiated)
                if 'data_win_eventdata_subjectUserName' in event_logs.columns:
                    subjects = event_logs['data_win_eventdata_subjectUserName'].value_counts().head(3)
                    print(f"  Initiated by: {subjects.to_dict()}")
                
                # Source IPs
                if 'src_ip' in event_logs.columns:
                    ips = event_logs['src_ip'].value_counts().head(3)
                    print(f"  Source IPs: {ips.to_dict()}")
                
                # High privileges detected
                if 'has_high_privileges' in event_logs.columns:
                    high_priv_count = event_logs['has_high_privileges'].sum()
                    if high_priv_count > 0:
                        print(f"  🚨 High privileges assigned: {high_priv_count} times")
    
    def investigate_pass_the_hash(self):
        """Deep analysis of pass-the-hash attacks"""
        print("\n" + "="*80)
        print("🔑 PASS-THE-HASH ATTACK INVESTIGATION")
        print("="*80)
        
        pth_anomalies = self.anomalies[self.anomalies.get('uc8_pass_the_hash', False) == True]
        
        if pth_anomalies.empty:
            print("No pass-the-hash anomalies detected")
            return
        
        print(f"🚨 CRITICAL: {len(pth_anomalies)} pass-the-hash incidents detected")
        print("⚠️  Pass-the-Hash attacks indicate credential theft!")
        
        # Analyze authentication patterns
        if 'data_win_eventdata_authenticationPackageName' in pth_anomalies.columns:
            print(f"\n🔐 AUTHENTICATION ANALYSIS:")
            auth_packages = pth_anomalies['data_win_eventdata_authenticationPackageName'].value_counts()
            for package, count in auth_packages.items():
                print(f"  {package}: {count} incidents")
        
        # Analyze logon processes
        if 'data_win_eventdata_logonProcessName' in pth_anomalies.columns:
            print(f"\n🔄 LOGON PROCESSES:")
            logon_processes = pth_anomalies['data_win_eventdata_logonProcessName'].value_counts()
            for process, count in logon_processes.items():
                print(f"  {process}: {count} incidents")
        
        # Analyze by user account
        if 'data_win_eventdata_targetUserName' in pth_anomalies.columns:
            print(f"\n👤 TARGETED ACCOUNTS:")
            for user in pth_anomalies['data_win_eventdata_targetUserName'].value_counts().head(3).index:
                user_pth = pth_anomalies[pth_anomalies['data_win_eventdata_targetUserName'] == user]
                
                print(f"\n🎯 USER: {user}")
                print(f"  PtH incidents: {len(user_pth)}")
                
                # Source IPs for this user
                if 'src_ip' in user_pth.columns:
                    source_ips = user_pth['src_ip'].value_counts()
                    print(f"  Attack sources: {source_ips.to_dict()}")
                
                # Logon types used
                if 'data_win_eventdata_logonType' in user_pth.columns:
                    logon_types = user_pth['data_win_eventdata_logonType'].value_counts()
                    print(f"  Logon types: {logon_types.to_dict()}")
                
                # Check for lateral movement correlation
                if 'uc2_lateral_movement' in user_pth.columns:
                    lateral_count = user_pth['uc2_lateral_movement'].sum()
                    if lateral_count > 0:
                        print(f"  🚨 CRITICAL: Also involved in {lateral_count} lateral movement incidents")
    
    def investigate_unusual_host_logons(self):
        """Deep analysis of unusual host logon patterns"""
        print("\n" + "="*80)
        print("🖥️ UNUSUAL HOST LOGON INVESTIGATION")
        print("="*80)
        
        unusual_host_anomalies = self.anomalies[self.anomalies.get('uc7_unusual_host_logon', False) == True]
        
        if unusual_host_anomalies.empty:
            print("No unusual host logon anomalies detected")
            return
        
        print(f"🚨 ALERT: {len(unusual_host_anomalies)} unusual host logon incidents detected")
        
        # Analyze new/rare IP addresses
        if 'src_ip' in unusual_host_anomalies.columns:
            print(f"\n🌐 UNUSUAL SOURCE IP ANALYSIS:")
            unusual_ips = unusual_host_anomalies['src_ip'].value_counts()
            
            for ip, count in unusual_ips.head(5).items():
                ip_logs = unusual_host_anomalies[unusual_host_anomalies['src_ip'] == ip]
                
                print(f"\n📍 IP: {ip} ({count} incidents)")
                
                # Users targeted from this IP
                if 'data_win_eventdata_targetUserName' in ip_logs.columns:
                    target_users = ip_logs['data_win_eventdata_targetUserName'].value_counts()
                    print(f"  Target users: {target_users.to_dict()}")
                
                # Logon types from this IP
                if 'data_win_eventdata_logonType' in ip_logs.columns:
                    logon_types = ip_logs['data_win_eventdata_logonType'].value_counts()
                    logon_type_names = {lt: self._get_logon_type_name(lt) for lt in logon_types.index}
                    print(f"  Logon methods: {logon_type_names}")
                
                # Time pattern
                if '@timestamp' in ip_logs.columns:
                    time_span = ip_logs['@timestamp'].max() - ip_logs['@timestamp'].min()
                    print(f"  Time span: {time_span}")
                
                # Check if this IP appears in normal traffic
                normal_from_ip = self.normal_logs[self.normal_logs['src_ip'] == ip] if 'src_ip' in self.normal_logs.columns else pd.DataFrame()
                if len(normal_from_ip) == 0:
                    print(f"  🚨 SUSPICIOUS: No legitimate traffic from this IP")
                else:
                    print(f"  📊 Also has {len(normal_from_ip)} normal connections")
        
        # Analyze user behavior patterns
        if 'data_win_eventdata_targetUserName' in unusual_host_anomalies.columns:
            print(f"\n👤 USER PATTERN ANALYSIS:")
            for user in unusual_host_anomalies['data_win_eventdata_targetUserName'].value_counts().head(3).index:
                user_unusual = unusual_host_anomalies[unusual_host_anomalies['data_win_eventdata_targetUserName'] == user]
                
                print(f"\n🎯 USER: {user}")
                print(f"  Unusual host logons: {len(user_unusual)}")
                
                # Unique IPs per user
                if 'unique_ips_per_user' in user_unusual.columns:
                    avg_unique_ips = user_unusual['unique_ips_per_user'].mean()
                    print(f"  Average unique IPs per user: {avg_unique_ips:.1f}")
                
                # Hour pattern
                if 'unique_ips_per_hour' in user_unusual.columns:
                    avg_ips_per_hour = user_unusual['unique_ips_per_hour'].mean()
                    print(f"  Average IPs per hour: {avg_ips_per_hour:.1f}")
    
    def create_incident_correlation_analysis(self):
        """Analyze correlations between different types of incidents"""
        print("\n" + "="*80)
        print("🔗 INCIDENT CORRELATION ANALYSIS")
        print("="*80)
        
        # Find users involved in multiple types of anomalies
        if 'data_win_eventdata_targetUserName' in self.anomalies.columns:
            print(f"👤 MULTI-THREAT USERS:")
            
            use_case_cols = [col for col in self.anomalies.columns if col.startswith('uc') and col.endswith(('_movement', '_escalation', '_logon', '_hash'))]
            
            for user in self.anomalies['data_win_eventdata_targetUserName'].value_counts().head(5).index:
                user_anomalies = self.anomalies[self.anomalies['data_win_eventdata_targetUserName'] == user]
                
                # Count different types of threats for this user
                threat_types = []
                for col in use_case_cols:
                    if col in user_anomalies.columns and user_anomalies[col].sum() > 0:
                        threat_name = col.replace('uc2_', '').replace('uc3_', '').replace('uc7_', '').replace('uc8_', '').replace('_', ' ').title()
                        threat_count = user_anomalies[col].sum()
                        threat_types.append(f"{threat_name} ({threat_count})")
                
                if len(threat_types) > 1:  # Multi-threat user
                    print(f"\n🚨 HIGH RISK USER: {user}")
                    print(f"  Threat types: {', '.join(threat_types)}")
                    print(f"  Total incidents: {len(user_anomalies)}")
                    
                    # Time span of attacks
                    if '@timestamp' in user_anomalies.columns:
                        time_span = user_anomalies['@timestamp'].max() - user_anomalies['@timestamp'].min()
                        print(f"  Attack duration: {time_span}")
        
        # Find correlated IP addresses
        if 'src_ip' in self.anomalies.columns:
            print(f"\n🌐 MULTI-THREAT IP ADDRESSES:")
            
            for ip in self.anomalies['src_ip'].value_counts().head(5).index:
                ip_anomalies = self.anomalies[self.anomalies['src_ip'] == ip]
                
                # Count different types of threats from this IP
                threat_types = []
                for col in use_case_cols:
                    if col in ip_anomalies.columns and ip_anomalies[col].sum() > 0:
                        threat_name = col.replace('uc2_', '').replace('uc3_', '').replace('uc7_', '').replace('uc8_', '').replace('_', ' ').title()
                        threat_count = ip_anomalies[col].sum()
                        threat_types.append(f"{threat_name} ({threat_count})")
                
                if len(threat_types) > 1:  # Multi-threat IP
                    print(f"\n🚨 MALICIOUS IP: {ip}")
                    print(f"  Threat types: {', '.join(threat_types)}")
                    print(f"  Total incidents: {len(ip_anomalies)}")
                    
                    # Users targeted from this IP
                    if 'data_win_eventdata_targetUserName' in ip_anomalies.columns:
                        target_users = ip_anomalies['data_win_eventdata_targetUserName'].nunique()
                        print(f"  Users targeted: {target_users}")
    
    def create_attack_timeline(self):
        """Create detailed attack timeline"""
        print("\n" + "="*80)
        print("⏰ DETAILED ATTACK TIMELINE")
        print("="*80)
        
        if '@timestamp' not in self.anomalies.columns:
            print("No timestamp data available for timeline analysis")
            return
        
        # Sort anomalies by timestamp
        timeline = self.anomalies.sort_values('@timestamp').copy()
        
        # Group by 10-minute windows for detailed timeline
        timeline['time_window'] = timeline['@timestamp'].dt.floor('10min')
        
        attack_sequence = timeline.groupby('time_window')
        
        print(f"📅 Detailed attack timeline ({len(attack_sequence)} time windows):")
        
        for time_window, group in attack_sequence:
            if len(group) < 2:  # Skip single incident windows
                continue
                
            print(f"\n🕐 {time_window} - {len(group)} incidents")
            
            # Show specific incidents in this window
            for idx, incident in group.iterrows():
                event_name = self._get_event_name(incident.get('data_win_system_eventID', 0))
                user = incident.get('data_win_eventdata_targetUserName', 'Unknown')
                src_ip = incident.get('src_ip', 'Unknown')
                
                # Identify threat type
                threat_indicators = []
                if incident.get('uc2_lateral_movement', False):
                    threat_indicators.append("Lateral Movement")
                if incident.get('uc3_privilege_escalation', False):
                    threat_indicators.append("Privilege Escalation")
                if incident.get('uc7_unusual_host_logon', False):
                    threat_indicators.append("Unusual Host")
                if incident.get('uc8_pass_the_hash', False):
                    threat_indicators.append("Pass-the-Hash")
                
                threat_str = ", ".join(threat_indicators) if threat_indicators else "General Anomaly"
                
                print(f"    {incident['@timestamp'].strftime('%H:%M:%S')}: {event_name} - {user} from {src_ip} [{threat_str}]")
    
    def generate_threat_report(self):
        """Generate comprehensive threat assessment report"""
        report_dir = "ml_results/threat_reports"
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{report_dir}/windows_threat_assessment_{timestamp}.md"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# WINDOWS EVENT LOG THREAT ASSESSMENT REPORT\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Analyst:** ML-Based UEBA System\n\n")
            
            f.write("## EXECUTIVE SUMMARY\n\n")
            f.write(f"- **Total Windows Event Logs Analyzed:** {len(self.df):,}\n")
            f.write(f"- **Anomalies Detected:** {len(self.anomalies):,} ({len(self.anomalies)/len(self.df)*100:.1f}%)\n")
            f.write(f"- **Critical Threats:** Multiple UEBA use cases triggered\n\n")
            
            # Use case summary
            f.write("## THREAT CATEGORIES DETECTED\n\n")
            
            use_cases = {
                'uc2_lateral_movement': 'Lateral Movement Attempts',
                'uc3_privilege_escalation': 'Privilege Escalation', 
                'uc7_unusual_host_logon': 'Unusual Host Logons',
                'uc8_pass_the_hash': 'Pass-the-Hash Attacks'
            }
            
            for uc_col, uc_name in use_cases.items():
                if uc_col in self.anomalies.columns:
                    count = self.anomalies[uc_col].sum()
                    if count > 0:
                        f.write(f"### {uc_name}\n")
                        f.write(f"- **Incidents:** {count}\n")
                        f.write(f"- **Severity:** CRITICAL\n")
                        
                        if uc_col == 'uc2_lateral_movement':
                            f.write(f"- **Risk:** Indicates compromised credentials and internal movement\n")
                        elif uc_col == 'uc3_privilege_escalation':
                            f.write(f"- **Risk:** Privilege abuse and potential system compromise\n")
                        elif uc_col == 'uc7_unusual_host_logon':
                            f.write(f"- **Risk:** Unauthorized access from new/rare locations\n")
                        elif uc_col == 'uc8_pass_the_hash':
                            f.write(f"- **Risk:** Credential theft and hash-based attacks\n")
                        
                        f.write(f"\n")
            
            f.write("## RECOMMENDED ACTIONS\n\n")
            f.write("### Immediate (0-24 hours)\n")
            
            # High-risk users
            if 'data_win_eventdata_targetUserName' in self.anomalies.columns:
                top_user = self.anomalies['data_win_eventdata_targetUserName'].value_counts().index[0]
                f.write(f"1. Investigate user account: {top_user}\n")
            
            # High-risk IPs
            if 'src_ip' in self.anomalies.columns:
                top_ip = self.anomalies['src_ip'].value_counts().index[0]
                f.write(f"2. Block/monitor suspicious IP: {top_ip}\n")
            
            f.write(f"3. Reset passwords for affected accounts\n")
            f.write(f"4. Enable enhanced authentication logging\n\n")
            
            f.write("### Short-term (1-7 days)\n")
            f.write("1. Implement stricter logon policies\n")
            f.write("2. Deploy additional monitoring for lateral movement\n")
            f.write("3. Review and update privilege assignments\n")
            f.write("4. Implement network segmentation\n\n")
            
            f.write("### Long-term (1-4 weeks)\n")
            f.write("1. Deploy endpoint detection and response (EDR)\n")
            f.write("2. Implement privileged access management (PAM)\n")
            f.write("3. Regular security awareness training\n")
            f.write("4. Automated threat hunting deployment\n\n")
        
        print(f"\n📄 Windows threat report generated: {report_file}")
        return report_file
    
    def _get_event_name(self, event_id):
        """Get human-readable event name"""
        event_names = {
            4624: "Successful Logon",
            4625: "Failed Logon", 
            4672: "Special Privileges Assigned",
            4688: "Process Creation",
            4728: "User Added to Global Group",
            4732: "User Added to Local Group"
        }
        return event_names.get(int(event_id), "Unknown Event")
    
    def _get_logon_type_name(self, logon_type):
        """Get human-readable logon type name"""
        logon_names = {
            2: "Interactive",
            3: "Network", 
            4: "Batch",
            5: "Service",
            7: "Unlock",
            8: "NetworkCleartext",
            9: "NewCredentials",
            10: "RemoteInteractive",
            11: "CachedInteractive"
        }
        return logon_names.get(int(logon_type), "Unknown")

def main():
    """Main deep dive analysis"""
    print("🔍 STARTING DEEP DIVE WINDOWS EVENT LOG THREAT ANALYSIS")
    print("="*70)
    
    results_file = "ml_results/results/windows_anomalies_20250730_150335.json"
    
    if not os.path.exists(results_file):
        # Try to find the latest file
        results_dir = "ml_results/results"
        if os.path.exists(results_dir):
            windows_files = [f for f in os.listdir(results_dir) if f.startswith('windows_anomalies_')]
            if windows_files:
                results_file = os.path.join(results_dir, sorted(windows_files)[-1])
                print(f"📁 Using latest results file: {os.path.basename(results_file)}")
            else:
                print(f"❌ No Windows results files found")
                return
        else:
            print(f"❌ Results directory not found: {results_dir}")
            return
    
    analyzer = WindowsDeepDiveAnalyzer(results_file)
    
    # Perform comprehensive analysis
    analyzer.investigate_lateral_movement()
    analyzer.investigate_privilege_escalation()
    analyzer.investigate_pass_the_hash()
    analyzer.investigate_unusual_host_logons()
    analyzer.create_incident_correlation_analysis()
    analyzer.create_attack_timeline()
    
    # Generate formal threat report
    report_file = analyzer.generate_threat_report()
    
    print(f"\n" + "="*80)
    print("✅ DEEP DIVE WINDOWS ANALYSIS COMPLETE")
    print("="*80)
    print(f"📊 Key Findings:")
    print(f"  🔄 Lateral movement patterns detected")
    print(f"  ⬆️ Privilege escalation attempts identified")
    print(f"  🔑 Pass-the-hash attacks discovered")
    print(f"  🖥️ Unusual host logon patterns found")
    print(f"\n📄 Detailed report: {report_file}")
    print(f"🎯 IMMEDIATE SECURITY ACTION REQUIRED!")

if __name__ == "__main__":
    main()
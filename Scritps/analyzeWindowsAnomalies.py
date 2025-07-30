#!/usr/bin/env python3
"""
Windows Event Log Anomaly Analysis Dashboard
Path: Scripts/ml/analyzeWindowsAnomalies.py

Analyzes and visualizes Windows Event Log ML detection results
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import numpy as np
from collections import Counter
import os

class WindowsAnomalyAnalyzer:
    def __init__(self, results_file_path):
        self.results_file = results_file_path
        self.df = None
        self.anomalies = None
        self.load_data()
        
    def load_data(self):
        """Load Windows Event Log anomaly detection results"""
        print(f"📁 Loading results from: {self.results_file}")
        
        with open(self.results_file, 'r') as f:
            data = json.load(f)
        
        self.df = pd.DataFrame(data)
        self.anomalies = self.df[self.df['is_anomaly'] == True]
        
        print(f"✅ Loaded {len(self.df)} total Windows Event logs")
        print(f"🚨 Found {len(self.anomalies)} anomalies ({len(self.anomalies)/len(self.df)*100:.2f}%)")
        
    def generate_summary_report(self):
        """Generate comprehensive UEBA analysis report"""
        print("\n" + "="*80)
        print("🔍 WINDOWS EVENT LOG UEBA ANALYSIS REPORT")
        print("="*80)
        
        # Basic Statistics
        print(f"\n📊 BASIC STATISTICS:")
        print(f"Total Windows Event Logs: {len(self.df):,}")
        print(f"Anomalies Detected: {len(self.anomalies):,}")
        print(f"Anomaly Rate: {len(self.anomalies)/len(self.df)*100:.2f}%")
        
        # Event ID Distribution
        if 'data_win_system_eventID' in self.df.columns:
            print(f"\n🔍 EVENT ID DISTRIBUTION:")
            event_counts = self.df['data_win_system_eventID'].value_counts()
            for event_id, count in event_counts.head(5).items():
                event_name = self._get_event_name(event_id)
                print(f"  {event_id} ({event_name}): {count}")
        
        # Model Performance
        print(f"\n🤖 MODEL PERFORMANCE:")
        models = ['isolation_forest', 'one_class_svm', 'gaussian_mixture', 'hdbscan']
        for model in models:
            anomaly_col = f'{model}_anomaly'
            if anomaly_col in self.df.columns:
                count = self.df[anomaly_col].sum()
                print(f"{model.replace('_', ' ').title()}: {count:,} ({count/len(self.df)*100:.2f}%)")
        
        # Ensemble Analysis
        ensemble_scores = self.df['ensemble_anomaly_score'].value_counts().sort_index()
        print(f"\n🎯 ENSEMBLE AGREEMENT:")
        for score, count in ensemble_scores.items():
            agreement = "No models" if score == 0 else f"{int(score)} model(s)"
            print(f"{agreement} agree: {count:,} logs ({count/len(self.df)*100:.2f}%)")
        
        if len(self.anomalies) > 0:
            self.analyze_use_case_patterns()
        else:
            print("\n⚠️  No anomalies detected to analyze patterns")
    
    def analyze_use_case_patterns(self):
        """Analyze patterns by UEBA use cases"""
        print(f"\n🚨 UEBA USE CASE ANALYSIS:")
        
        # Use case breakdown
        use_cases = {
            'uc1_anomalous_logon_time': 'Anomalous Logon Time',
            'uc2_lateral_movement': 'Lateral Movement Attempts',
            'uc3_privilege_escalation': 'Privilege Escalation',
            'uc4_unusual_process': 'Unusual Process Creation',
            'uc5_geoip_rdp_anomaly': 'GeoIP RDP Anomaly',
            'uc6_unusual_logon_times': 'Unusual Logon Times',
            'uc7_unusual_host_logon': 'Unusual Host Logons',
            'uc8_pass_the_hash': 'Pass-the-Hash Attacks',
            'uc9_impossible_travel': 'Impossible Travel',
            'uc10_brute_force': 'Brute Force Attacks'
        }
        
        active_use_cases = {}
        for uc_col, uc_name in use_cases.items():
            if uc_col in self.anomalies.columns:
                count = self.anomalies[uc_col].sum()
                if count > 0:
                    active_use_cases[uc_name] = count
        
        if active_use_cases:
            print(f"Active threat categories:")
            for uc_name, count in sorted(active_use_cases.items(), key=lambda x: x[1], reverse=True):
                print(f"  🎯 {uc_name}: {count} incidents")
        
        # Time-based patterns
        print(f"\n⏰ TEMPORAL PATTERNS:")
        if '@timestamp' in self.anomalies.columns:
            self.anomalies['@timestamp'] = pd.to_datetime(self.anomalies['@timestamp'], format='mixed')
            hour_counts = self.anomalies['@timestamp'].dt.hour.value_counts().sort_index()
            print(f"Peak anomaly hours: {hour_counts.head(3).to_dict()}")
        
        if 'is_business_hours' in self.anomalies.columns:
            business_hours_anomalies = self.anomalies['is_business_hours'].sum()
            print(f"Business hours anomalies: {business_hours_anomalies} ({business_hours_anomalies/len(self.anomalies)*100:.1f}%)")
        
        if 'is_weekend' in self.anomalies.columns:
            weekend_anomalies = self.anomalies['is_weekend'].sum()
            print(f"Weekend anomalies: {weekend_anomalies} ({weekend_anomalies/len(self.anomalies)*100:.1f}%)")
        
        # User analysis
        print(f"\n👤 USER BEHAVIOR ANALYSIS:")
        if 'data_win_eventdata_targetUserName' in self.anomalies.columns:
            top_users = self.anomalies['data_win_eventdata_targetUserName'].value_counts().head(5)
            print(f"Top anomalous users:")
            for user, count in top_users.items():
                print(f"  {user}: {count} anomalies")
        
        # Host/IP analysis
        print(f"\n🖥️ HOST & IP ANALYSIS:")
        if 'src_ip' in self.anomalies.columns:
            top_ips = self.anomalies['src_ip'].value_counts().head(5)
            print(f"Top anomalous source IPs:")
            for ip, count in top_ips.items():
                print(f"  {ip}: {count} anomalies")
        
        # Geographic analysis
        if 'src_geo_country' in self.anomalies.columns:
            print(f"\n🌍 GEOGRAPHIC ANALYSIS:")
            countries = self.anomalies['src_geo_country'].value_counts().head(5)
            for country, count in countries.items():
                print(f"  {country}: {count} anomalies")
    
    def analyze_critical_threats(self):
        """Analyze the most critical security threats"""
        print(f"\n" + "="*60)
        print("🚨 CRITICAL THREAT ANALYSIS")
        print("="*60)
        
        # Lateral Movement Analysis
        lateral_movement = self.anomalies[self.anomalies.get('uc2_lateral_movement', False) == True]
        if len(lateral_movement) > 0:
            print(f"\n🔄 LATERAL MOVEMENT THREATS ({len(lateral_movement)} incidents)")
            
            # Analyze logon types for lateral movement
            if 'data_win_eventdata_logonType' in lateral_movement.columns:
                logon_types = lateral_movement['data_win_eventdata_logonType'].value_counts()
                for logon_type, count in logon_types.items():
                    logon_name = self._get_logon_type_name(logon_type)
                    print(f"  Logon Type {logon_type} ({logon_name}): {count} incidents")
            
            # Top source IPs for lateral movement
            if 'src_ip' in lateral_movement.columns:
                lateral_ips = lateral_movement['src_ip'].value_counts().head(3)
                print(f"  Top lateral movement sources: {lateral_ips.to_dict()}")
        
        # Privilege Escalation Analysis
        privilege_escalation = self.anomalies[self.anomalies.get('uc3_privilege_escalation', False) == True]
        if len(privilege_escalation) > 0:
            print(f"\n⬆️ PRIVILEGE ESCALATION THREATS ({len(privilege_escalation)} incidents)")
            
            # Event IDs involved
            if 'data_win_system_eventID' in privilege_escalation.columns:
                event_ids = privilege_escalation['data_win_system_eventID'].value_counts()
                for event_id, count in event_ids.items():
                    event_name = self._get_event_name(event_id)
                    print(f"  Event {event_id} ({event_name}): {count} incidents")
            
            # Users involved in privilege escalation
            if 'data_win_eventdata_targetUserName' in privilege_escalation.columns:
                priv_users = privilege_escalation['data_win_eventdata_targetUserName'].value_counts().head(3)
                print(f"  Users involved: {priv_users.to_dict()}")
        
        # Pass-the-Hash Analysis
        pth_attacks = self.anomalies[self.anomalies.get('uc8_pass_the_hash', False) == True]
        if len(pth_attacks) > 0:
            print(f"\n🔑 PASS-THE-HASH ATTACKS ({len(pth_attacks)} incidents)")
            
            # Authentication packages
            if 'data_win_eventdata_authenticationPackageName' in pth_attacks.columns:
                auth_packages = pth_attacks['data_win_eventdata_authenticationPackageName'].value_counts()
                print(f"  Authentication packages: {auth_packages.to_dict()}")
            
            # Logon processes
            if 'data_win_eventdata_logonProcessName' in pth_attacks.columns:
                logon_processes = pth_attacks['data_win_eventdata_logonProcessName'].value_counts()
                print(f"  Logon processes: {logon_processes.to_dict()}")
        
        # Unusual Host Logons
        unusual_hosts = self.anomalies[self.anomalies.get('uc7_unusual_host_logon', False) == True]
        if len(unusual_hosts) > 0:
            print(f"\n🖥️ UNUSUAL HOST LOGONS ({len(unusual_hosts)} incidents)")
            
            # New/rare IP addresses
            if 'src_ip' in unusual_hosts.columns:
                unusual_ips = unusual_hosts['src_ip'].value_counts()
                print(f"  Unusual source IPs: {unusual_ips.head(5).to_dict()}")
            
            # Target users for unusual logons
            if 'data_win_eventdata_targetUserName' in unusual_hosts.columns:
                target_users = unusual_hosts['data_win_eventdata_targetUserName'].value_counts().head(3)
                print(f"  Target users: {target_users.to_dict()}")
    
    def create_timeline_analysis(self):
        """Create incident timeline analysis"""
        print(f"\n" + "="*60)
        print("⏰ INCIDENT TIMELINE ANALYSIS")
        print("="*60)
        
        if '@timestamp' not in self.anomalies.columns:
            print("No timestamp data available for timeline analysis")
            return
        
        # Convert timestamps
        self.anomalies['@timestamp'] = pd.to_datetime(self.anomalies['@timestamp'], format='mixed')
        timeline = self.anomalies.sort_values('@timestamp').copy()
        
        # Group incidents by time windows (15-minute intervals)
        timeline['time_window'] = timeline['@timestamp'].dt.floor('15min')
        
        incident_groups = timeline.groupby('time_window')
        
        print(f"📅 Timeline analysis ({len(incident_groups)} time windows):")
        
        for time_window, group in incident_groups:
            if len(group) < 2:  # Skip single incident windows
                continue
                
            print(f"\n🕐 {time_window} ({len(group)} incidents)")
            
            # Categorize incidents by use case
            use_case_counts = {}
            use_case_cols = [col for col in group.columns if col.startswith('uc') and col.endswith(('_movement', '_escalation', '_logon', '_hash', '_time', '_process', '_anomaly', '_travel', '_force'))]
            
            for col in use_case_cols:
                count = group[col].sum()
                if count > 0:
                    uc_name = col.replace('uc1_', '').replace('uc2_', '').replace('uc3_', '').replace('uc4_', '').replace('uc5_', '').replace('uc6_', '').replace('uc7_', '').replace('uc8_', '').replace('uc9_', '').replace('uc10_', '').replace('_', ' ').title()
                    use_case_counts[uc_name] = count
            
            if use_case_counts:
                print(f"  Threat types: {use_case_counts}")
            
            # Key actors
            if 'data_win_eventdata_targetUserName' in group.columns:
                top_users = group['data_win_eventdata_targetUserName'].value_counts().head(2)
                print(f"  Key users: {top_users.to_dict()}")
            
            # Event types
            if 'data_win_system_eventID' in group.columns:
                event_types = group['data_win_system_eventID'].value_counts().head(2)
                event_names = {eid: self._get_event_name(eid) for eid in event_types.index}
                print(f"  Event types: {event_names}")
    
    def create_visualizations(self):
        """Create comprehensive visualization plots"""
        print("\n📊 Creating Windows Event Log visualizations...")
        
        # Set up plotting style
        plt.style.use('default')
        sns.set_palette("husl")
        
        # Create output directory
        viz_dir = "ml_results/visualizations"
        os.makedirs(viz_dir, exist_ok=True)
        
        # 1. UEBA Use Case Overview
        plt.figure(figsize=(15, 10))
        
        # Use case breakdown
        plt.subplot(2, 3, 1)
        use_case_cols = [col for col in self.anomalies.columns if col.startswith('uc') and '_' in col]
        use_case_counts = {}
        for col in use_case_cols:
            if self.anomalies[col].sum() > 0:
                uc_name = col.replace('uc1_', '').replace('uc2_', '').replace('uc3_', '').replace('uc4_', '').replace('uc5_', '').replace('uc6_', '').replace('uc7_', '').replace('uc8_', '').replace('uc9_', '').replace('uc10_', '').replace('_', ' ').title()
                use_case_counts[uc_name] = self.anomalies[col].sum()
        
        if use_case_counts:
            plt.bar(range(len(use_case_counts)), list(use_case_counts.values()))
            plt.xticks(range(len(use_case_counts)), list(use_case_counts.keys()), rotation=45, ha='right')
            plt.title('UEBA Use Case Distribution')
            plt.ylabel('Number of Anomalies')
        
        # Event ID distribution
        plt.subplot(2, 3, 2)
        if 'data_win_system_eventID' in self.anomalies.columns:
            event_counts = self.anomalies['data_win_system_eventID'].value_counts().head(5)
            plt.bar(range(len(event_counts)), event_counts.values)
            plt.xticks(range(len(event_counts)), [f"{eid}\n({self._get_event_name(eid)})" for eid in event_counts.index], rotation=45)
            plt.title('Top Event IDs in Anomalies')
            plt.ylabel('Count')
        
        # Hourly distribution
        plt.subplot(2, 3, 3)
        if '@timestamp' in self.anomalies.columns:
            self.anomalies['@timestamp'] = pd.to_datetime(self.anomalies['@timestamp'], format='mixed')
            hourly_dist = self.anomalies['@timestamp'].dt.hour.value_counts().sort_index()
            plt.plot(hourly_dist.index, hourly_dist.values, marker='o')
            plt.title('Anomalies by Hour of Day')
            plt.xlabel('Hour')
            plt.ylabel('Number of Anomalies')
            plt.grid(True, alpha=0.3)
        
        # Top users
        plt.subplot(2, 3, 4)
        if 'data_win_eventdata_targetUserName' in self.anomalies.columns:
            top_users = self.anomalies['data_win_eventdata_targetUserName'].value_counts().head(8)
            plt.barh(range(len(top_users)), top_users.values)
            plt.yticks(range(len(top_users)), top_users.index)
            plt.title('Top Anomalous Users')
            plt.xlabel('Number of Anomalies')
        
        # Logon types
        plt.subplot(2, 3, 5)
        if 'data_win_eventdata_logonType' in self.anomalies.columns:
            logon_types = self.anomalies['data_win_eventdata_logonType'].value_counts()
            labels = [f"Type {lt}\n({self._get_logon_type_name(lt)})" for lt in logon_types.index]
            plt.pie(logon_types.values, labels=labels, autopct='%1.1f%%')
            plt.title('Logon Types in Anomalies')
        
        # Model performance
        plt.subplot(2, 3, 6)
        models = ['isolation_forest_anomaly', 'one_class_svm_anomaly', 'gaussian_mixture_anomaly']
        model_counts = []
        model_names = []
        for model in models:
            if model in self.df.columns:
                model_counts.append(self.df[model].sum())
                model_names.append(model.replace('_anomaly', '').replace('_', ' ').title())
        
        if model_counts:
            plt.bar(model_names, model_counts)
            plt.title('Model Detection Counts')
            plt.ylabel('Anomalies Detected')
            plt.xticks(rotation=45)
        
        plt.tight_layout()
        plt.savefig(f'{viz_dir}/windows_anomaly_overview.png', dpi=300, bbox_inches='tight')
        print(f"✅ Saved overview plot: {viz_dir}/windows_anomaly_overview.png")
        
        plt.show()
    
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
    """Main analysis function"""
    print("🔍 Starting Windows Event Log Anomaly Analysis...")
    
    # Find the latest results file
    results_dir = "ml_results/results"
    
    if not os.path.exists(results_dir):
        print("❌ Results directory not found. Run mlWindowsDetector.py first.")
        return
    
    # Get the latest windows anomalies file
    anomaly_files = [f for f in os.listdir(results_dir) if f.startswith('windows_anomalies_')]
    
    if not anomaly_files:
        print("❌ No Windows anomaly results files found.")
        return
    
    # Use the latest file
    latest_file = sorted(anomaly_files)[-1]
    results_path = os.path.join(results_dir, latest_file)
    
    print(f"📁 Using results file: {latest_file}")
    
    # Initialize analyzer
    analyzer = WindowsAnomalyAnalyzer(results_path)
    
    # Generate comprehensive analysis
    analyzer.generate_summary_report()
    analyzer.analyze_critical_threats()
    analyzer.create_timeline_analysis()
    
    # Create visualizations
    analyzer.create_visualizations()
    
    print("\n✅ Windows Event Log Analysis complete!")
    print("📊 Check ml_results/visualizations/ for plots")

if __name__ == "__main__":
    main()
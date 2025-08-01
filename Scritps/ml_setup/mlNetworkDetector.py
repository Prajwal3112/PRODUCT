#!/usr/bin/env python3
"""
Network Log ML Anomaly Detector
Path: Scripts/ml/mlNetworkDetector.py

Comprehensive UBA for Network Logs covering:
1. Beaconing Detection (C2 Communication)
2. Suspicious User-Agents / Tools
3. Unusual Destination IP or Port
4. Data Exfiltration / Unusual Volume
5. Port Scanning / Reconnaissance
6. Lateral Movement Attempts
7. Suspicious Protocol Usage
8. Command Injection / Suspicious URLs

Enhanced with BombalAutoencoderDetector integration
"""

import os
import json
import pickle
import pandas as pd
import numpy as np
import re
import argparse
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.mixture import GaussianMixture
from sklearn.cluster import HDBSCAN
from sklearn.preprocessing import StandardScaler, LabelEncoder
from fetchNetworkData import NetworkDataFetcher

# Import autoencoder with error handling
try:
    from bombalAutoencoderDetector import BombalAutoencoderDetector
    AUTOENCODER_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  BombalAutoencoderDetector not available: {e}")
    AUTOENCODER_AVAILABLE = False

import warnings
warnings.filterwarnings('ignore')

class NetworkMLDetector:
    def __init__(self, detection_mode='traditional'):
        """
        Initialize Network ML Detector
        
        Args:
            detection_mode (str): 'traditional', 'autoencoder', or 'ensemble'
        """
        self.detection_mode = detection_mode
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_columns = []
        self.results_dir = "ml_results"
        self.autoencoder_detector = None
        self.setup_directories()
        
        # Initialize autoencoder if needed and available
        if self.detection_mode in ['autoencoder', 'ensemble']:
            if AUTOENCODER_AVAILABLE:
                self.autoencoder_detector = BombalAutoencoderDetector()
                print(f"🤖 Initialized BombalAutoencoderDetector for {detection_mode} mode")
            else:
                print(f"❌ Autoencoder mode requested but BombalAutoencoderDetector not available")
                print(f"🔄 Falling back to traditional mode")
                self.detection_mode = 'traditional'
        
        # Network behavior thresholds
        self.beaconing_threshold = 5
        self.port_scan_threshold = 10
        self.data_exfil_multiplier = 3
        self.lateral_movement_threshold = 5
        
    def setup_directories(self):
        """Create necessary directories"""
        dirs = ['models', 'results', 'logs', 'data']
        for dir_name in dirs:
            os.makedirs(f"{self.results_dir}/{dir_name}", exist_ok=True)
    
    def is_internal_ip(self, ip):
        """Check if IP is internal"""
        if pd.isna(ip) or ip == 'unknown':
            return False
        try:
            ip_str = str(ip)
            return (ip_str.startswith('192.168.') or 
                   ip_str.startswith('10.') or 
                   ip_str.startswith('172.16.') or
                   ip_str.startswith('172.17.') or
                   ip_str.startswith('172.18.') or
                   ip_str.startswith('172.19.') or
                   ip_str.startswith('172.2') or
                   ip_str.startswith('172.30.') or
                   ip_str.startswith('172.31.'))
        except:
            return False
    
    def is_suspicious_user_agent(self, user_agent):
        """Check if user agent is suspicious (scripts/tools)"""
        if pd.isna(user_agent) or user_agent == 'unknown':
            return False
        
        ua_str = str(user_agent).lower()
        suspicious_patterns = [
            'python-requests', 'curl', 'wget', 'powershell', 'bitsadmin',
            'certutil', 'sqlmap', 'nikto', 'nmap', 'masscan', 'zap',
            'burp', 'metasploit', 'cobalt', 'empire', 'beacon'
        ]
        
        return any(pattern in ua_str for pattern in suspicious_patterns)
    
    def is_suspicious_url(self, url):
        """Check if URL contains suspicious patterns"""
        if pd.isna(url) or url == 'unknown':
            return False
        
        url_str = str(url).lower()
        suspicious_patterns = [
            'cmd=', 'exec=', 'system=', '../', '..\\', 'passwd', 'shadow',
            'config', 'admin', 'login', 'debug=', 'test=', 'shell=',
            'upload=', 'file=', 'dir=', 'path=', 'eval=', 'assert='
        ]
        
        return any(pattern in url_str for pattern in suspicious_patterns)
    
    def engineer_features(self, df):
        """Create comprehensive UBA features for all 8 network use cases"""
        print("🔧 Engineering Network Log features...")
        
        df = df.copy()
        
        # Check which columns exist
        available_cols = df.columns.tolist()
        print(f"  📋 Available columns: {len(available_cols)}")
        
        # Basic temporal features
        if '@timestamp' in available_cols:
            df['hour'] = pd.to_datetime(df['@timestamp'], format='mixed').dt.hour
            df['day_of_week'] = pd.to_datetime(df['@timestamp'], format='mixed').dt.dayofweek
            df['is_business_hours'] = df['hour'].between(9, 18)
            df['is_weekend'] = df['day_of_week'].isin([5, 6])
        else:
            df['hour'] = 12
            df['day_of_week'] = 1
            df['is_business_hours'] = True
            df['is_weekend'] = False
        
        # IP categorization - only if IP columns exist
        if 'src_ip' in available_cols:
            df['src_is_internal'] = df['src_ip'].apply(self.is_internal_ip)
        else:
            df['src_is_internal'] = True
            
        if 'dest_ip' in available_cols:
            df['dest_is_internal'] = df['dest_ip'].apply(self.is_internal_ip)
        else:
            df['dest_is_internal'] = False
            
        df['is_internal_to_internal'] = df['src_is_internal'] & df['dest_is_internal']
        df['is_internal_to_external'] = df['src_is_internal'] & ~df['dest_is_internal']
        df['is_external_to_internal'] = ~df['src_is_internal'] & df['dest_is_internal']
        
        # Port categorization
        df = self._categorize_ports(df)
        
        # Protocol features
        df = self._engineer_protocol_features(df)
        
        # Use case specific features - only if required columns exist
        df = self._engineer_beaconing_features(df)          # Use case 1
        df = self._engineer_user_agent_features(df)        # Use case 2
        df = self._engineer_destination_features(df)       # Use case 3
        df = self._engineer_data_volume_features(df)       # Use case 4
        df = self._engineer_scanning_features(df)          # Use case 5
        df = self._engineer_lateral_movement_features(df)  # Use case 6
        df = self._engineer_protocol_anomaly_features(df)  # Use case 7
        df = self._engineer_url_injection_features(df)     # Use case 8
        
        print(f"✅ Feature engineering complete. Shape: {df.shape}")
        return df
    
    def _categorize_ports(self, df):
        """Categorize ports by service type"""
        print("  🚪 Categorizing ports...")
        
        if 'dest_port' not in df.columns:
            print("    ⚠️  Missing dest_port column for port categorization")
            # Add default port category columns
            df['is_web_port'] = False
            df['is_admin_port'] = False
            df['is_database_port'] = False
            df['is_file_share_port'] = False
            df['is_high_port'] = False
            df['is_uncommon_port'] = True
            return df
        
        # Define port categories
        web_ports = [80, 443, 8080, 8443, 8000, 9000]
        admin_ports = [22, 23, 3389, 5985, 5986]  # SSH, Telnet, RDP, WinRM
        database_ports = [1433, 3306, 5432, 1521, 27017]
        file_share_ports = [445, 139, 21, 2049]  # SMB, FTP, NFS
        
        df['is_web_port'] = df['dest_port'].isin(web_ports)
        df['is_admin_port'] = df['dest_port'].isin(admin_ports)
        df['is_database_port'] = df['dest_port'].isin(database_ports)
        df['is_file_share_port'] = df['dest_port'].isin(file_share_ports)
        df['is_high_port'] = df['dest_port'] > 32768
        df['is_uncommon_port'] = ~df['dest_port'].isin(web_ports + admin_ports + database_ports + file_share_ports + [53, 25, 110, 143])
        
        return df
    
    def _engineer_protocol_features(self, df):
        """Engineer protocol-based features"""
        print("  🔗 Engineering protocol features...")
        
        # Application protocol features
        if 'app_proto' in df.columns:
            df['is_http_proto'] = df['app_proto'] == 'http'
            df['is_https_proto'] = df['app_proto'] == 'https'
            df['is_dns_proto'] = df['app_proto'] == 'dns'
            df['is_ssh_proto'] = df['app_proto'] == 'ssh'
            df['is_unknown_proto'] = df['app_proto'] == 'unknown'
        else:
            df['is_http_proto'] = False
            df['is_https_proto'] = False
            df['is_dns_proto'] = False
            df['is_ssh_proto'] = False
            df['is_unknown_proto'] = True
        
        # Transport protocol
        if 'proto' in df.columns:
            df['is_tcp'] = df['proto'] == 'TCP'
            df['is_udp'] = df['proto'] == 'UDP'
            df['is_icmp'] = df['proto'] == 'ICMP'
        else:
            df['is_tcp'] = True  # Default assumption
            df['is_udp'] = False
            df['is_icmp'] = False
        
        return df
    
    def _engineer_beaconing_features(self, df):
        """Engineer beaconing detection features (Use case 1)"""
        print("  📡 Engineering beaconing features...")
        
        # Only proceed if we have the required columns
        if 'src_ip' not in df.columns or 'dest_ip' not in df.columns:
            print("    ⚠️  Missing src_ip or dest_ip columns for beaconing analysis")
            df['connection_count'] = 1
            df['is_potential_beacon'] = False
            return df
        
        # Group by source IP and destination IP for beaconing analysis
        agg_dict = {'@timestamp': 'count'}
        
        if 'flow_bytes_toserver' in df.columns:
            agg_dict['flow_bytes_toserver'] = ['mean', 'std']
        
        if 'dest_port' in df.columns:
            agg_dict['dest_port'] = lambda x: len(set(x))
        
        beaconing_stats = df.groupby(['src_ip', 'dest_ip']).agg(agg_dict).reset_index()
        
        # Flatten column names based on what we aggregated
        if 'flow_bytes_toserver' in agg_dict:
            beaconing_stats.columns = ['src_ip', 'dest_ip', 'connection_count', 'avg_bytes_sent', 'bytes_std', 'unique_ports']
            
            # Identify potential beaconing
            beaconing_stats['is_potential_beacon'] = (
                (beaconing_stats['connection_count'] >= self.beaconing_threshold) &
                (beaconing_stats['bytes_std'] < beaconing_stats['avg_bytes_sent'] * 0.2)  # Low variance in bytes
            )
        else:
            beaconing_stats.columns = ['src_ip', 'dest_ip', 'connection_count', 'unique_ports']
            beaconing_stats['is_potential_beacon'] = beaconing_stats['connection_count'] >= self.beaconing_threshold
        
        # Merge back to main dataframe
        merge_cols = ['src_ip', 'dest_ip', 'connection_count', 'is_potential_beacon']
        df = df.merge(beaconing_stats[merge_cols], on=['src_ip', 'dest_ip'], how='left')
        
        # Fill NaN values
        df['connection_count'] = df['connection_count'].fillna(1)
        df['is_potential_beacon'] = df['is_potential_beacon'].fillna(False)
        
        return df
    
    def _engineer_user_agent_features(self, df):
        """Engineer suspicious user agent features (Use case 2)"""
        print("  🕵️ Engineering user agent features...")
        
        if 'http_user_agent' in df.columns:
            df['is_suspicious_ua'] = df['http_user_agent'].apply(self.is_suspicious_user_agent)
            df['ua_length'] = df['http_user_agent'].str.len()
            df['ua_has_version'] = df['http_user_agent'].str.contains(r'\d+\.\d+', na=False)
            df['ua_is_browser'] = df['http_user_agent'].str.contains('mozilla|chrome|firefox|safari|edge', case=False, na=False)
        else:
            df['is_suspicious_ua'] = False
            df['ua_length'] = 0
            df['ua_has_version'] = False
            df['ua_is_browser'] = False
        
        # User agent baseline per source IP
        if 'http_user_agent' in df.columns and 'src_ip' in df.columns:
            ua_stats = df.groupby('src_ip')['http_user_agent'].agg(['nunique', 'count']).reset_index()
            ua_stats.columns = ['src_ip', 'unique_user_agents', 'total_http_requests']
            df = df.merge(ua_stats, on='src_ip', how='left')
            
            df['unique_user_agents'] = df['unique_user_agents'].fillna(1)
            df['total_http_requests'] = df['total_http_requests'].fillna(1)
        else:
            df['unique_user_agents'] = 1
            df['total_http_requests'] = 1
        
        return df
    
    def _engineer_destination_features(self, df):
        """Engineer unusual destination features (Use case 3)"""
        print("  🎯 Engineering destination features...")
        
        if 'src_ip' not in df.columns:
            print("    ⚠️  Missing src_ip column for destination analysis")
            df['unique_dest_ips'] = 1
            df['unique_dest_ports'] = 1
            df['internal_dest_ratio'] = 0.5
            df['is_frequent_port'] = False
            return df
        
        # Destination IP baseline per source IP
        agg_dict = {}
        
        if 'dest_ip' in df.columns:
            agg_dict['dest_ip'] = 'nunique'
        if 'dest_port' in df.columns:
            agg_dict['dest_port'] = 'nunique'
        if 'dest_is_internal' in df.columns:
            agg_dict['dest_is_internal'] = 'mean'
        
        if agg_dict:
            dest_stats = df.groupby('src_ip').agg(agg_dict).reset_index()
            
            # Build column names based on what we aggregated
            col_names = ['src_ip']
            if 'dest_ip' in agg_dict:
                col_names.append('unique_dest_ips')
            if 'dest_port' in agg_dict:
                col_names.append('unique_dest_ports')
            if 'dest_is_internal' in agg_dict:
                col_names.append('internal_dest_ratio')
            
            dest_stats.columns = col_names
            df = df.merge(dest_stats, on='src_ip', how='left')
        
        # Add missing columns with defaults
        if 'unique_dest_ips' not in df.columns:
            df['unique_dest_ips'] = 1
        if 'unique_dest_ports' not in df.columns:
            df['unique_dest_ports'] = 1
        if 'internal_dest_ratio' not in df.columns:
            df['internal_dest_ratio'] = 0.5
        
        # Port baseline per source IP
        if 'src_ip' in df.columns and 'dest_port' in df.columns:
            port_stats = df.groupby(['src_ip', 'dest_port']).size().reset_index(name='port_frequency')
            port_stats['is_frequent_port'] = port_stats['port_frequency'] > 5
            
            df = df.merge(port_stats[['src_ip', 'dest_port', 'is_frequent_port']], 
                         on=['src_ip', 'dest_port'], how='left')
        
        if 'is_frequent_port' not in df.columns:
            df['is_frequent_port'] = False
        
        # Fill NaN values
        df['unique_dest_ips'] = df['unique_dest_ips'].fillna(1)
        df['unique_dest_ports'] = df['unique_dest_ports'].fillna(1)
        df['internal_dest_ratio'] = df['internal_dest_ratio'].fillna(0.5)
        df['is_frequent_port'] = df['is_frequent_port'].fillna(False)
        
        return df
    
    def _engineer_data_volume_features(self, df):
        """Engineer data exfiltration features (Use case 4)"""
        print("  📊 Engineering data volume features...")
        
        # Calculate data volume metrics
        flow_cols = ['flow_bytes_toserver', 'flow_bytes_toclient', 'flow_pkts_toserver', 'flow_pkts_toclient']
        
        for col in flow_cols:
            if col not in df.columns:
                df[col] = 0
            else:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        # Total data transferred
        df['total_bytes'] = df['flow_bytes_toserver'] + df['flow_bytes_toclient']
        df['total_packets'] = df['flow_pkts_toserver'] + df['flow_pkts_toclient']
        df['bytes_per_packet'] = df['total_bytes'] / (df['total_packets'] + 1)  # Avoid division by zero
        
        # Data volume baseline per source IP
        volume_stats = df.groupby('src_ip').agg({
            'flow_bytes_toserver': ['mean', 'std', 'max'],
            'total_bytes': ['mean', 'std', 'max']
        }).reset_index()
        
        # Flatten column names
        volume_stats.columns = ['src_ip', 'avg_bytes_sent', 'std_bytes_sent', 'max_bytes_sent',
                               'avg_total_bytes', 'std_total_bytes', 'max_total_bytes']
        
        df = df.merge(volume_stats, on='src_ip', how='left')
        
        # Detect unusual data volumes
        df['is_high_data_volume'] = (
            df['flow_bytes_toserver'] > (df['avg_bytes_sent'] + self.data_exfil_multiplier * df['std_bytes_sent'])
        )
        
        # Fill NaN values
        for col in ['avg_bytes_sent', 'std_bytes_sent', 'max_bytes_sent', 'avg_total_bytes', 'std_total_bytes', 'max_total_bytes']:
            df[col] = df[col].fillna(df[col].median())
        
        df['is_high_data_volume'] = df['is_high_data_volume'].fillna(False)
        
        return df
    
    def _engineer_scanning_features(self, df):
        """Engineer port scanning features (Use case 5)"""
        print("  🔍 Engineering scanning features...")
        
        if '@timestamp' not in df.columns or 'src_ip' not in df.columns:
            print("    ⚠️  Missing required columns for scanning analysis")
            df['unique_ports_per_hour'] = 1
            df['unique_ips_per_hour'] = 1
            df['is_port_scanning'] = False
            df['is_ip_scanning'] = False
            df['total_unique_dest_ips'] = 1
            df['total_unique_dest_ports'] = 1
            df['total_connections'] = 1
            return df
        
        # Time window for scanning detection (1 hour)
        df['timestamp_hour'] = pd.to_datetime(df['@timestamp'], format='mixed').dt.floor('H')
        
        # Port scanning: many ports from same source
        agg_dict = {}
        if 'dest_port' in df.columns:
            agg_dict['dest_port'] = 'nunique'
        if 'dest_ip' in df.columns:
            agg_dict['dest_ip'] = 'nunique'
        
        if agg_dict:
            port_scan_stats = df.groupby(['src_ip', 'timestamp_hour']).agg(agg_dict).reset_index()
            
            # Build column names based on what we aggregated
            col_names = ['src_ip', 'timestamp_hour']
            if 'dest_port' in agg_dict:
                col_names.append('unique_ports_per_hour')
            if 'dest_ip' in agg_dict:
                col_names.append('unique_ips_per_hour')
            
            port_scan_stats.columns = col_names
            
            # Identify potential scanning
            if 'unique_ports_per_hour' in port_scan_stats.columns:
                port_scan_stats['is_port_scanning'] = port_scan_stats['unique_ports_per_hour'] >= self.port_scan_threshold
            if 'unique_ips_per_hour' in port_scan_stats.columns:
                port_scan_stats['is_ip_scanning'] = port_scan_stats['unique_ips_per_hour'] >= self.port_scan_threshold
            
            df = df.merge(port_scan_stats, on=['src_ip', 'timestamp_hour'], how='left')
        
        # Connection patterns
        conn_agg_dict = {}
        if 'dest_ip' in df.columns:
            conn_agg_dict['dest_ip'] = 'nunique'
        if 'dest_port' in df.columns:
            conn_agg_dict['dest_port'] = 'nunique'
        conn_agg_dict['@timestamp'] = 'count'
        
        conn_stats = df.groupby('src_ip').agg(conn_agg_dict).reset_index()
        
        # Build column names
        conn_col_names = ['src_ip']
        if 'dest_ip' in conn_agg_dict:
            conn_col_names.append('total_unique_dest_ips')
        if 'dest_port' in conn_agg_dict:
            conn_col_names.append('total_unique_dest_ports')
        conn_col_names.append('total_connections')
        
        conn_stats.columns = conn_col_names
        df = df.merge(conn_stats, on='src_ip', how='left')
        
        # Add missing columns with defaults
        scan_cols = ['unique_ports_per_hour', 'unique_ips_per_hour', 'is_port_scanning', 'is_ip_scanning',
                    'total_unique_dest_ips', 'total_unique_dest_ports', 'total_connections']
        
        for col in scan_cols:
            if col not in df.columns:
                if col in ['is_port_scanning', 'is_ip_scanning']:
                    df[col] = False
                else:
                    df[col] = 1
        
        # Fill NaN values
        for col in scan_cols:
            if col in ['is_port_scanning', 'is_ip_scanning']:
                df[col] = df[col].fillna(False)
            else:
                df[col] = df[col].fillna(1)
        
        return df
    
    def _engineer_lateral_movement_features(self, df):
        """Engineer lateral movement features (Use case 6)"""
        print("  🔄 Engineering lateral movement features...")
        
        if 'dest_port' not in df.columns:
            print("    ⚠️  Missing dest_port column for lateral movement analysis")
            df['is_lateral_movement_attempt'] = False
            df['internal_connections'] = 0
            df['lateral_attempts'] = 0
            df['internal_dest_count'] = 0
            df['is_excessive_internal_comms'] = False
            return df
        
        # Internal-to-internal connections with admin ports
        admin_ports = [22, 23, 3389, 5985, 5986, 445, 139]
        
        df['is_lateral_movement_attempt'] = (
            df['is_internal_to_internal'] & 
            df['dest_port'].isin(admin_ports)
        )
        
        # Count internal connections per source
        if 'src_ip' in df.columns:
            agg_dict = {
                'is_internal_to_internal': 'sum',
                'is_lateral_movement_attempt': 'sum'
            }
            
            if 'dest_ip' in df.columns:
                # This is more complex - we need to count internal destinations
                lateral_stats = df.groupby('src_ip').agg(agg_dict).reset_index()
                lateral_stats.columns = ['src_ip', 'internal_connections', 'lateral_attempts']
                
                # Calculate internal dest count separately
                internal_dest_stats = df[df['dest_is_internal'] == True].groupby('src_ip')['dest_ip'].nunique().reset_index()
                internal_dest_stats.columns = ['src_ip', 'internal_dest_count']
                
                lateral_stats = lateral_stats.merge(internal_dest_stats, on='src_ip', how='left')
            else:
                lateral_stats = df.groupby('src_ip').agg(agg_dict).reset_index()
                lateral_stats.columns = ['src_ip', 'internal_connections', 'lateral_attempts']
                lateral_stats['internal_dest_count'] = 0
            
            df = df.merge(lateral_stats, on='src_ip', how='left')
        else:
            df['internal_connections'] = 0
            df['lateral_attempts'] = 0
            df['internal_dest_count'] = 0
        
        # Unusual internal communication patterns
        df['is_excessive_internal_comms'] = df['internal_connections'] >= self.lateral_movement_threshold
        
        # Fill NaN values
        lateral_cols = ['internal_connections', 'lateral_attempts', 'internal_dest_count']
        for col in lateral_cols:
            df[col] = df[col].fillna(0)
        
        df['is_excessive_internal_comms'] = df['is_excessive_internal_comms'].fillna(False)
        
        return df
    
    def _engineer_protocol_anomaly_features(self, df):
        """Engineer suspicious protocol usage features (Use case 7)"""
        print("  🔗 Engineering protocol anomaly features...")
        
        if 'dest_port' not in df.columns:
            print("    ⚠️  Missing dest_port column for protocol anomaly analysis")
            df['is_http_on_non_web_port'] = False
            df['is_ssh_on_non_22'] = False
            df['is_web_to_internal'] = False
            df['unique_protocols'] = 1
            df['http_ratio'] = 0
            df['https_ratio'] = 0
            df['is_protocol_anomaly'] = False
            return df
        
        # HTTP on non-web ports
        df['is_http_on_non_web_port'] = (
            df['is_http_proto'] & ~df['is_web_port']
        )
        
        # Unexpected protocol/port combinations
        df['is_ssh_on_non_22'] = (df['is_ssh_proto'] & (df['dest_port'] != 22))
        df['is_web_to_internal'] = (df['is_http_proto'] & df['dest_is_internal'] & ~df['is_web_port'])
        
        # Protocol baseline per source IP
        if 'src_ip' in df.columns:
            agg_dict = {}
            if 'app_proto' in df.columns:
                agg_dict['app_proto'] = lambda x: len(set(x))
            agg_dict['is_http_proto'] = 'mean'
            agg_dict['is_https_proto'] = 'mean'
            
            proto_stats = df.groupby('src_ip').agg(agg_dict).reset_index()
            
            # Build column names
            col_names = ['src_ip']
            if 'app_proto' in agg_dict:
                col_names.extend(['unique_protocols', 'http_ratio', 'https_ratio'])
            else:
                col_names.extend(['http_ratio', 'https_ratio'])
            
            proto_stats.columns = col_names
            df = df.merge(proto_stats, on='src_ip', how='left')
        
        # Add missing columns with defaults
        if 'unique_protocols' not in df.columns:
            df['unique_protocols'] = 1
        if 'http_ratio' not in df.columns:
            df['http_ratio'] = 0
        if 'https_ratio' not in df.columns:
            df['https_ratio'] = 0
        
        # Unusual protocol usage
        df['is_protocol_anomaly'] = (
            df['is_http_on_non_web_port'] | 
            df['is_ssh_on_non_22'] | 
            df['is_web_to_internal']
        )
        
        # Fill NaN values
        proto_cols = ['unique_protocols', 'http_ratio', 'https_ratio']
        for col in proto_cols:
            if col in df.columns:
                df[col] = df[col].fillna(df[col].median() if not df[col].isna().all() else 1)
        
        return df
    
    def _engineer_url_injection_features(self, df):
        """Engineer URL injection and suspicious URL features (Use case 8)"""
        print("  🌐 Engineering URL injection features...")
        
        if 'http_url' in df.columns:
            df['is_suspicious_url'] = df['http_url'].apply(self.is_suspicious_url)
            df['url_length'] = df['http_url'].str.len()
            df['url_has_parameters'] = df['http_url'].str.contains(r'\?', na=False)
            df['url_parameter_count'] = df['http_url'].str.count('&')
            df['url_has_dots'] = df['http_url'].str.contains(r'\.\.', na=False)
            df['url_has_admin'] = df['http_url'].str.contains('admin|config|debug', case=False, na=False)
        else:
            df['is_suspicious_url'] = False
            df['url_length'] = 0
            df['url_has_parameters'] = False
            df['url_parameter_count'] = 0
            df['url_has_dots'] = False
            df['url_has_admin'] = False
        
        # HTTP method analysis
        if 'http_method' in df.columns:
            df['is_get_method'] = df['http_method'] == 'GET'
            df['is_post_method'] = df['http_method'] == 'POST'
            df['is_unusual_method'] = ~df['http_method'].isin(['GET', 'POST', 'HEAD', 'OPTIONS'])
        else:
            df['is_get_method'] = True
            df['is_post_method'] = False
            df['is_unusual_method'] = False
        
        # URL pattern analysis per source IP
        if 'http_url' in df.columns and 'src_ip' in df.columns:
            url_stats = df.groupby('src_ip').agg({
                'is_suspicious_url': 'sum',
                'http_url': 'nunique'
            }).reset_index()
            
            url_stats.columns = ['src_ip', 'suspicious_url_count', 'unique_urls']
            df = df.merge(url_stats, on='src_ip', how='left')
            
            df['suspicious_url_ratio'] = df['suspicious_url_count'] / (df['unique_urls'] + 1)
        else:
            df['suspicious_url_count'] = 0
            df['unique_urls'] = 1
            df['suspicious_url_ratio'] = 0
        
        return df
    
    def prepare_ml_features(self, df):
        """Prepare features for ML models"""
        print("🔧 Preparing ML features...")
        
        # Get available columns
        available_cols = df.columns.tolist()
        
        # Comprehensive feature set for all 8 network use cases
        potential_feature_cols = [
            # Basic network features
            'hour', 'day_of_week', 'is_business_hours', 'is_weekend',
            'src_is_internal', 'dest_is_internal', 'is_internal_to_internal',
            'is_internal_to_external', 'is_external_to_internal',
            
            # Port and protocol features
            'dest_port', 'src_port', 'is_web_port', 'is_admin_port', 'is_database_port',
            'is_file_share_port', 'is_high_port', 'is_uncommon_port',
            'is_http_proto', 'is_https_proto', 'is_dns_proto', 'is_ssh_proto',
            'is_tcp', 'is_udp', 'is_icmp',
            
            # Use case 1: Beaconing features
            'connection_count', 'is_potential_beacon',
            
            # Use case 2: User agent features
            'is_suspicious_ua', 'ua_length', 'ua_has_version', 'ua_is_browser',
            'unique_user_agents', 'total_http_requests',
            
            # Use case 3: Destination features
            'unique_dest_ips', 'unique_dest_ports', 'internal_dest_ratio', 'is_frequent_port',
            
            # Use case 4: Data volume features
            'flow_bytes_toserver', 'flow_bytes_toclient', 'total_bytes', 'total_packets',
            'bytes_per_packet', 'avg_bytes_sent', 'std_bytes_sent', 'is_high_data_volume',
            
            # Use case 5: Scanning features
            'unique_ports_per_hour', 'unique_ips_per_hour', 'is_port_scanning', 'is_ip_scanning',
            'total_unique_dest_ips', 'total_unique_dest_ports', 'total_connections',
            
            # Use case 6: Lateral movement features
            'is_lateral_movement_attempt', 'internal_connections', 'lateral_attempts',
            'is_excessive_internal_comms',
            
            # Use case 7: Protocol anomaly features
            'is_http_on_non_web_port', 'is_ssh_on_non_22', 'is_web_to_internal',
            'unique_protocols', 'http_ratio', 'https_ratio', 'is_protocol_anomaly',
            
            # Use case 8: URL injection features
            'is_suspicious_url', 'url_length', 'url_has_parameters', 'url_parameter_count',
            'url_has_dots', 'url_has_admin', 'is_get_method', 'is_post_method',
            'is_unusual_method', 'suspicious_url_count', 'suspicious_url_ratio'
        ]
        
        # Filter to only use columns that actually exist
        feature_cols = [col for col in potential_feature_cols if col in available_cols]
        
        print(f"  📊 Using {len(feature_cols)} available features out of {len(potential_feature_cols)} potential features")
        
        # Categorical features to encode
        potential_categorical_cols = [
            'src_ip', 'dest_ip', 'app_proto', 'proto', 'event_type',
            'http_user_agent', 'http_method', 'http_hostname',
            'alert_signature', 'alert_category'
        ]
        
        categorical_cols = [col for col in potential_categorical_cols if col in available_cols]
        
        # Prepare feature matrix
        X = df[feature_cols].copy()
        
        # Encode categorical variables
        for col in categorical_cols:
            try:
                if col not in self.encoders:
                    # Use frequency encoding for high cardinality features
                    if df[col].nunique() > 50:
                        freq_map = df[col].value_counts(normalize=True).to_dict()
                        self.encoders[col] = freq_map
                        encoded = df[col].map(freq_map).fillna(0)
                    else:
                        # Use label encoding for low cardinality features
                        self.encoders[col] = LabelEncoder()
                        encoded = self.encoders[col].fit_transform(df[col].astype(str))
                else:
                    # Apply existing encoding
                    if isinstance(self.encoders[col], dict):
                        encoded = df[col].map(self.encoders[col]).fillna(0)
                    else:
                        encoded = self.encoders[col].transform(df[col].astype(str))
                
                X[f'{col}_encoded'] = encoded
                print(f"  ✅ Encoded {col} ({df[col].nunique()} unique values)")
                
            except Exception as e:
                print(f"  ⚠️  Error encoding {col}: {str(e)}")
                continue
        
        # Handle any remaining NaN values
        X = X.fillna(0)
        
        # Store feature columns
        self.feature_columns = X.columns.tolist()
        
        print(f"✅ ML features prepared. Shape: {X.shape}")
        print(f"🔍 Final features: {len(self.feature_columns)}")
        
        # Show missing features for debugging
        missing_features = [col for col in potential_feature_cols if col not in available_cols]
        if missing_features:
            print(f"  📋 Missing features: {missing_features[:10]}...")
        
        return X
    
    def run_detection(self, df):
        """Main detection method - delegates to appropriate mode"""
        print(f"🚀 Running {self.detection_mode} mode detection...")
        
        if self.detection_mode == 'autoencoder':
            return self._run_autoencoder_detection(df)
        elif self.detection_mode == 'ensemble':
            return self._run_ensemble_detection(df)
        else:  # traditional
            return self._run_traditional_detection(df)
    
    def _run_autoencoder_detection(self, df):
        """Run autoencoder-only detection"""
        if not AUTOENCODER_AVAILABLE or self.autoencoder_detector is None:
            print("❌ Autoencoder not available, falling back to traditional detection")
            return self._run_traditional_detection(df)
            
        print("🤖 Running BombalAutoencoderDetector...")
        
        # Use autoencoder detector directly
        autoencoder_results = self.autoencoder_detector.run_detection(df)
        
        # Apply use case flags based on traditional features for consistency
        df_features = self.engineer_features(df.copy())
        autoencoder_results = self._add_network_use_case_flags_to_results(autoencoder_results, df_features)
        
        print("✅ Autoencoder detection complete")
        return autoencoder_results
    
    def _run_traditional_detection(self, df):
        """Run traditional ML detection"""
        print("🔧 Running traditional ML models...")
        
        # Engineer features
        df_features = self.engineer_features(df)
        
        # Prepare ML features
        X = self.prepare_ml_features(df_features)
        
        # Train models
        self.train_models(X)
        
        # Predict anomalies
        results = self.predict_anomalies(X, df_features)
        
        print("✅ Traditional ML detection complete")
        return results
    
    def _run_ensemble_detection(self, df):
        """Run ensemble detection combining both traditional and autoencoder"""
        if not AUTOENCODER_AVAILABLE or self.autoencoder_detector is None:
            print("❌ Autoencoder not available for ensemble, falling back to traditional detection")
            return self._run_traditional_detection(df)
            
        print("🎯 Running ensemble detection (Traditional + Autoencoder)...")
        
        # Run traditional detection
        traditional_results = self._run_traditional_detection(df.copy())
        
        # Run autoencoder detection
        autoencoder_results = self.autoencoder_detector.run_detection(df.copy())
        
        # Combine results
        ensemble_results = self._combine_detection_results(traditional_results, autoencoder_results, df)
        
        print("✅ Ensemble detection complete")
        return ensemble_results
    
    def _combine_detection_results(self, traditional_results, autoencoder_results, original_df):
        """Combine traditional and autoencoder results"""
        print("🔗 Combining traditional and autoencoder results...")
        
        # Start with traditional results as base
        combined_results = traditional_results.copy()
        
        # Add autoencoder anomaly flag
        combined_results['autoencoder_anomaly'] = autoencoder_results['is_anomaly']
        
        # Add reconstruction error if available
        if 'reconstruction_error' in autoencoder_results.columns:
            combined_results['reconstruction_error'] = autoencoder_results['reconstruction_error']
        
        # Create ensemble anomaly decision
        # Anomaly if either traditional ensemble OR autoencoder detects it
        combined_results['ensemble_is_anomaly'] = (
            combined_results['is_anomaly'] | combined_results['autoencoder_anomaly']
        )
        
        # Create confidence score (0-1 scale)
        traditional_confidence = combined_results['ensemble_anomaly_score'] / combined_results['ensemble_anomaly_score'].max() if combined_results['ensemble_anomaly_score'].max() > 0 else 0
        autoencoder_confidence = combined_results['autoencoder_anomaly'].astype(float)
        
        combined_results['ensemble_confidence'] = (traditional_confidence + autoencoder_confidence) / 2
        
        # Update final anomaly flag
        combined_results['is_anomaly'] = combined_results['ensemble_is_anomaly']
        
        # Update use case flags based on ensemble results
        combined_results = self._update_use_case_flags_for_ensemble(combined_results)
        
        print(f"🎯 Ensemble results: {combined_results['is_anomaly'].sum()} anomalies detected")
        return combined_results
    
    def _add_network_use_case_flags_to_results(self, results, df_features):
        """Add use case flags to autoencoder results using traditional feature engineering"""
        
        # Merge feature-engineered data to get use case indicators
        feature_indicators = df_features[[
            'is_potential_beacon', 'is_suspicious_ua', 'unique_dest_ips', 'is_frequent_port',
            'is_high_data_volume', 'is_port_scanning', 'is_ip_scanning', 
            'is_lateral_movement_attempt', 'is_excessive_internal_comms',
            'is_protocol_anomaly', 'is_suspicious_url', 'url_has_admin'
        ]].reset_index(drop=True)
        
        results_with_features = pd.concat([results.reset_index(drop=True), feature_indicators], axis=1)
        
        # Apply use case flags
        results_with_features = self._add_network_use_case_flags(results_with_features)
        
        return results_with_features
    
    def _update_use_case_flags_for_ensemble(self, results):
        """Update use case flags for ensemble results"""
        
        # Re-apply use case flags based on ensemble anomaly detection
        original_anomaly_flag = results['is_anomaly'].copy()
        
        # Temporarily set is_anomaly to ensemble result for flag calculation
        results = self._add_network_use_case_flags(results)
        
        return results
    
    def train_models(self, X):
        """Train anomaly detection models for network logs"""
        print("🤖 Training Network Log ML models...")
        
        # Scale features
        if 'scaler' not in self.scalers:
            self.scalers['scaler'] = StandardScaler()
            X_scaled = self.scalers['scaler'].fit_transform(X)
        else:
            X_scaled = self.scalers['scaler'].transform(X)
        
        # Initialize models optimized for network data
        models_config = {
            'isolation_forest': IsolationForest(
                contamination=0.08,  # Network logs often have more anomalies
                random_state=42,
                n_estimators=150
            ),
            'one_class_svm': OneClassSVM(
                kernel='rbf',
                gamma='scale',
                nu=0.08
            ),
            'gaussian_mixture': GaussianMixture(
                n_components=4,  # More components for diverse network behaviors
                random_state=42
            ),
            'hdbscan': HDBSCAN(
                min_cluster_size=30,
                min_samples=10,
                metric='euclidean'
            )
        }
        
        # Train each model
        for model_name, model in models_config.items():
            print(f"🔧 Training {model_name}...")
            try:
                if model_name == 'gaussian_mixture':
                    model.fit(X_scaled)
                    scores = model.score_samples(X_scaled)
                    threshold = np.percentile(scores, 8)  # Bottom 8% as anomalies
                    self.models[model_name] = {'model': model, 'threshold': threshold}
                elif model_name == 'hdbscan':
                    labels = model.fit_predict(X_scaled)
                    # HDBSCAN: -1 labels are outliers/anomalies
                    outlier_scores = np.zeros(len(X_scaled))
                    outlier_scores[labels == -1] = 1  # Mark outliers
                    threshold = 0.5
                    self.models[model_name] = {'model': model, 'threshold': threshold, 'labels': labels}
                else:
                    model.fit(X_scaled)
                    self.models[model_name] = {'model': model}
                
                print(f"✅ {model_name} trained successfully")
            except Exception as e:
                print(f"❌ Error training {model_name}: {str(e)}")
        
        print("🎯 All Network Log models trained!")
    
    def predict_anomalies(self, X, df):
        """Predict anomalies using trained models"""
        print("🔍 Detecting Network Log anomalies...")
        
        X_scaled = self.scalers['scaler'].transform(X)
        results = df.copy()
        
        for model_name, model_info in self.models.items():
            model = model_info['model']
            
            try:
                if model_name == 'gaussian_mixture':
                    scores = model.score_samples(X_scaled)
                    threshold = model_info['threshold']
                    predictions = (scores < threshold).astype(int)
                    results[f'{model_name}_score'] = scores
                    results[f'{model_name}_anomaly'] = predictions
                elif model_name == 'hdbscan':
                    labels = model_info.get('labels', np.zeros(len(X_scaled)))
                    predictions = (labels == -1).astype(int)
                    results[f'{model_name}_score'] = labels
                    results[f'{model_name}_anomaly'] = predictions
                else:
                    predictions = model.predict(X_scaled)
                    scores = model.decision_function(X_scaled) if hasattr(model, 'decision_function') else model.score_samples(X_scaled)
                    
                    # Convert to binary (1 = normal, -1 = anomaly)
                    anomalies = (predictions == -1).astype(int)
                    results[f'{model_name}_score'] = scores
                    results[f'{model_name}_anomaly'] = anomalies
                
                print(f"✅ {model_name}: {sum(results[f'{model_name}_anomaly'])} anomalies detected")
                
            except Exception as e:
                print(f"❌ Error in {model_name} prediction: {str(e)}")
        
        # Create ensemble score (majority voting)
        anomaly_cols = [col for col in results.columns if col.endswith('_anomaly')]
        if len(anomaly_cols) > 0:
            results['ensemble_anomaly_score'] = results[anomaly_cols].sum(axis=1)
            results['is_anomaly'] = results['ensemble_anomaly_score'] >= 2  # At least 2 models agree
        
        # Add use case specific flags
        results = self._add_network_use_case_flags(results)
        
        return results
    
    def _add_network_use_case_flags(self, results):
        """Add specific network use case flags"""
        
        # Use case flags for network anomalies
        results['uc1_beaconing'] = (
            results['is_anomaly'] & results.get('is_potential_beacon', False)
        )
        
        results['uc2_suspicious_user_agents'] = (
            results['is_anomaly'] & results.get('is_suspicious_ua', False)
        )
        
        results['uc3_unusual_destinations'] = (
            results['is_anomaly'] & 
            ((results.get('unique_dest_ips', 0) > results.get('unique_dest_ips', 0).quantile(0.95)) |
             (~results.get('is_frequent_port', True)))
        )
        
        results['uc4_data_exfiltration'] = (
            results['is_anomaly'] & results.get('is_high_data_volume', False)
        )
        
        results['uc5_port_scanning'] = (
            results['is_anomaly'] & 
            (results.get('is_port_scanning', False) | results.get('is_ip_scanning', False))
        )
        
        results['uc6_lateral_movement'] = (
            results['is_anomaly'] & 
            (results.get('is_lateral_movement_attempt', False) | results.get('is_excessive_internal_comms', False))
        )
        
        results['uc7_suspicious_protocols'] = (
            results['is_anomaly'] & results.get('is_protocol_anomaly', False)
        )
        
        results['uc8_command_injection'] = (
            results['is_anomaly'] & 
            (results.get('is_suspicious_url', False) | results.get('url_has_admin', False))
        )
        
        return results
    
    def save_models(self):
        """Save trained models"""
        models_path = f"{self.results_dir}/models/network_models.pkl"
        scalers_path = f"{self.results_dir}/models/network_scalers.pkl"
        encoders_path = f"{self.results_dir}/models/network_encoders.pkl"
        
        with open(models_path, 'wb') as f:
            pickle.dump(self.models, f)
        
        with open(scalers_path, 'wb') as f:
            pickle.dump(self.scalers, f)
            
        with open(encoders_path, 'wb') as f:
            pickle.dump(self.encoders, f)
        
        # Save feature columns
        with open(f"{self.results_dir}/models/network_feature_columns.json", 'w') as f:
            json.dump(self.feature_columns, f)
        
        print(f"💾 Network models saved to {models_path}")
    
    def save_results(self, results, filename=None):
        """Save anomaly detection results"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            mode_suffix = f"_{self.detection_mode}" if self.detection_mode != 'traditional' else ""
            filename = f"network_anomalies{mode_suffix}_{timestamp}.json"
        
        results_path = f"{self.results_dir}/results/{filename}"
        
        # Convert DataFrame to JSON-serializable format
        results_json = results.to_dict('records')
        
        # Save results
        with open(results_path, 'w') as f:
            json.dump(results_json, f, indent=2, default=str)
        
        print(f"💾 Results saved to: {results_path}")
        
        # Summary statistics with use case breakdown
        total_logs = len(results)
        total_anomalies = results['is_anomaly'].sum() if 'is_anomaly' in results.columns else 0
        
        summary = {
            "timestamp": datetime.now().isoformat(),
            "detection_mode": self.detection_mode,
            "total_logs_analyzed": int(total_logs),
            "total_anomalies_detected": int(total_anomalies),
            "anomaly_percentage": float(total_anomalies / total_logs * 100) if total_logs > 0 else 0,
            "model_scores": {},
            "use_case_breakdown": {}
        }
        
        # Add individual model statistics
        for col in results.columns:
            if col.endswith('_anomaly') and not col.startswith('uc'):
                model_name = col.replace('_anomaly', '')
                summary["model_scores"][model_name] = int(results[col].sum())
        
        # Add use case breakdown
        use_cases = {
            "uc1_beaconing": "Beaconing Detection",
            "uc2_suspicious_user_agents": "Suspicious User Agents",
            "uc3_unusual_destinations": "Unusual Destinations",
            "uc4_data_exfiltration": "Data Exfiltration",
            "uc5_port_scanning": "Port Scanning",
            "uc6_lateral_movement": "Lateral Movement",
            "uc7_suspicious_protocols": "Suspicious Protocols",
            "uc8_command_injection": "Command Injection"
        }
        
        for uc_col, uc_name in use_cases.items():
            if uc_col in results.columns:
                summary["use_case_breakdown"][uc_name] = int(results[uc_col].sum())
        
        # Save summary
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        mode_suffix = f"_{self.detection_mode}" if self.detection_mode != 'traditional' else ""
        summary_path = f"{self.results_dir}/results/network_summary{mode_suffix}_{timestamp}.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"📊 Summary: {total_anomalies}/{total_logs} anomalies ({total_anomalies/total_logs*100:.2f}%)")
        return results_path

def main():
    """Main function to run Network Log ML detection with CLI support"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Network Log ML Anomaly Detector')
    parser.add_argument('--mode', choices=['traditional', 'autoencoder', 'ensemble'], 
                       default='traditional', help='Detection mode to use')
    args = parser.parse_args()
    
    print(f"🚀 Starting Network Log ML Anomaly Detection in {args.mode} mode...")
    
    # Initialize detector with specified mode
    detector = NetworkMLDetector(detection_mode=args.mode)
    
    # Check if we have saved data first
    csv_path = "ml_results/data/network_data.csv"
    json_path = "ml_results/data/network_raw_data.json"
    
    df = None
    
    # Try to load from saved CSV first
    if os.path.exists(csv_path):
        print(f"📁 Loading data from saved CSV: {csv_path}")
        try:
            df = pd.read_csv(csv_path)
            print(f"✅ Loaded {len(df)} records from CSV")
        except Exception as e:
            print(f"⚠️  Error loading CSV: {str(e)}")
    
    # If CSV failed, try JSON
    if df is None and os.path.exists(json_path):
        print(f"📁 Loading data from saved JSON: {json_path}")
        try:
            with open(json_path, 'r') as f:
                logs = json.load(f)
            
            fetcher = NetworkDataFetcher()
            df = fetcher.convert_to_dataframe(logs)
            print(f"✅ Loaded {len(df)} records from JSON")
        except Exception as e:
            print(f"⚠️  Error loading JSON: {str(e)}")
    
    # If no saved data, fetch fresh data
    if df is None or df.empty:
        print("📥 No saved data found. Fetching fresh data from OpenSearch...")
        fetcher = NetworkDataFetcher()
        logs = fetcher.fetch_network_logs(days_back=7, size=20000)
        
        if not logs:
            print("❌ No logs available for training")
            return
        
        # Convert to DataFrame
        df = fetcher.convert_to_dataframe(logs)
        
        if df.empty:
            print("❌ DataFrame is empty")
            return
    
    print(f"🎯 Using dataset with {len(df)} records for Network Log ML training")
    
    # Run detection based on mode
    results = detector.run_detection(df)
    
    # Save models (only for traditional and ensemble modes)
    if detector.detection_mode in ['traditional', 'ensemble']:
        detector.save_models()
    
    # Save results
    results_path = detector.save_results(results)
    
    # Show sample anomalies by use case
    print(f"\n🚨 NETWORK UBA USE CASE BREAKDOWN:")
    print("="*50)
    
    use_case_columns = [col for col in results.columns if col.startswith('uc')]
    for col in use_case_columns:
        count = results[col].sum()
        if count > 0:
            uc_name = col.replace('_', ' ').title()
            print(f"  {uc_name}: {count} anomalies")
    
    print(f"\n✅ Network Log ML Detection Complete ({args.mode} mode)!")
    print(f"📁 Results saved to: {results_path}")

if __name__ == "__main__":
    main()
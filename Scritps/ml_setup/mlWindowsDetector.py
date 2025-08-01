#!/usr/bin/env python3
"""
Windows Event Log ML Anomaly Detector
Path: Scripts/ml/mlWindowsDetector.py

Comprehensive UEBA for Windows Event Logs covering:
1. Anomalous Logon Time
2. Lateral Movement Attempts  
3. Privilege Escalation
4. Unusual Process Creation
5. GeoIP Anomaly via RDP
6. Unusual Logon Times
7. Logon from Unusual Hosts
8. Pass-the-Hash Attack Detection
9. Impossible Travel
10. Brute Force Detection
"""

import os
import json
import pickle
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.mixture import GaussianMixture
from sklearn.cluster import HDBSCAN
from sklearn.preprocessing import StandardScaler, LabelEncoder
from fetchWindowsData import WindowsDataFetcher
import warnings
warnings.filterwarnings('ignore')

class WindowsMLDetector:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_columns = []
        self.results_dir = "ml_results"
        self.setup_directories()
        
        # Business rules
        self.business_hours = (9, 18)  # 9 AM - 6 PM
        self.weekend_day = 6  # Sunday (0=Monday, 6=Sunday)
        self.impossible_travel_threshold = 600  # 10 minutes in seconds
        self.brute_force_threshold = 5  # failures
        self.brute_force_window = 3  # seconds
        
    def setup_directories(self):
        """Create necessary directories"""
        dirs = ['models', 'results', 'logs', 'data']
        for dir_name in dirs:
            os.makedirs(f"{self.results_dir}/{dir_name}", exist_ok=True)
    
    def parse_coordinates(self, coord_str):
        """Parse coordinate string to get latitude and longitude"""
        if pd.isna(coord_str) or coord_str == 'unknown' or coord_str == 'nan':
            return None, None
        try:
            coord_str = str(coord_str).strip()
            if ',' in coord_str:
                parts = coord_str.split(',')
                if len(parts) == 2:
                    lat = float(parts[0].strip())
                    lon = float(parts[1].strip())
                    return lat, lon
        except:
            pass
        return None, None
    
    def calculate_distance(self, lat1, lon1, lat2, lon2):
        """Calculate distance between two coordinates (Haversine formula)"""
        if any(v is None or v == 0 for v in [lat1, lon1, lat2, lon2]):
            return 0
        
        from math import radians, cos, sin, asin, sqrt
        
        # Convert to radians
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        
        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        r = 6371  # Radius of earth in kilometers
        return c * r
    
    def engineer_features(self, df):
        """Create comprehensive UEBA features for all 10 use cases"""
        print("🔧 Engineering Windows Event Log features...")
        
        df = df.copy()
        
        # Basic temporal features
        df['hour'] = pd.to_datetime(df['@timestamp'], format='mixed').dt.hour
        df['day_of_week'] = pd.to_datetime(df['@timestamp'], format='mixed').dt.dayofweek
        df['is_business_hours'] = df['hour'].between(self.business_hours[0], self.business_hours[1])
        df['is_weekend'] = df['day_of_week'] == self.weekend_day
        df['is_night'] = df['hour'].isin([22, 23, 0, 1, 2, 3, 4, 5])
        
        # Parse coordinates
        df['src_lat'], df['src_lon'] = zip(*df['src_geo_coordinates'].apply(self.parse_coordinates))
        
        # Event categorization
        df['is_logon_event'] = df['data_win_system_eventID'] == 4624
        df['is_failed_logon'] = df['data_win_system_eventID'] == 4625
        df['is_privilege_event'] = df['data_win_system_eventID'].isin([4672, 4728, 4732])
        df['is_process_creation'] = df['data_win_system_eventID'] == 4688
        
        # Logon type categorization
        df['is_remote_interactive'] = df['data_win_eventdata_logonType'] == 10  # RDP
        df['is_network_logon'] = df['data_win_eventdata_logonType'] == 3  # Network
        df['is_interactive_logon'] = df['data_win_eventdata_logonType'] == 2  # Interactive
        
        # User behavior features
        df = self._engineer_user_features(df)
        
        # Geographic features
        df = self._engineer_geographic_features(df)
        
        # Temporal pattern features
        df = self._engineer_temporal_features(df)
        
        # Security-specific features
        df = self._engineer_security_features(df)
        
        print(f"✅ Feature engineering complete. Shape: {df.shape}")
        return df
    
    def _engineer_user_features(self, df):
        """Engineer user behavior features"""
        print("  🔧 Engineering user behavior features...")
        
        # Check which columns exist
        available_cols = df.columns.tolist()
        
        # Build aggregation dict based on available columns
        agg_dict = {}
        
        if 'src_ip' in available_cols:
            agg_dict['src_ip'] = 'nunique'
        if 'data_win_eventdata_logonType' in available_cols:
            agg_dict['data_win_eventdata_logonType'] = lambda x: len(set(x))
        if 'hour' in available_cols:
            agg_dict['hour'] = lambda x: len(set(x))
        if 'src_geo_country' in available_cols:
            agg_dict['src_geo_country'] = 'nunique'
        if 'data_win_system_eventID' in available_cols:
            agg_dict['data_win_system_eventID'] = 'count'
        
        # Only proceed if we have at least some columns to aggregate
        if agg_dict and 'data_win_eventdata_targetUserName' in available_cols:
            user_stats = df.groupby('data_win_eventdata_targetUserName').agg(agg_dict).reset_index()
            
            # Rename columns based on what was actually aggregated
            new_col_names = ['data_win_eventdata_targetUserName']
            if 'src_ip' in agg_dict:
                new_col_names.append('unique_ips_per_user')
            if 'data_win_eventdata_logonType' in agg_dict:
                new_col_names.append('unique_logon_types_per_user')
            if 'hour' in agg_dict:
                new_col_names.append('unique_hours_per_user')
            if 'src_geo_country' in agg_dict:
                new_col_names.append('unique_countries_per_user')
            if 'data_win_system_eventID' in agg_dict:
                new_col_names.append('total_events_per_user')
            
            user_stats.columns = new_col_names
            df = df.merge(user_stats, on='data_win_eventdata_targetUserName', how='left')
        else:
            # Add default columns if aggregation couldn't be done
            df['unique_ips_per_user'] = 1
            df['unique_logon_types_per_user'] = 1
            df['unique_hours_per_user'] = 1
            df['unique_countries_per_user'] = 1
            df['total_events_per_user'] = 1
        
        # Recent activity windows (last hour) - only if timestamp exists
        if '@timestamp' in available_cols:
            df['timestamp_hour'] = pd.to_datetime(df['@timestamp'], format='mixed').dt.floor('H')
            
            # Build hourly aggregation dict
            hourly_agg_dict = {}
            if 'src_ip' in available_cols:
                hourly_agg_dict['src_ip'] = 'nunique'
            if 'data_win_eventdata_logonType' in available_cols:
                hourly_agg_dict['data_win_eventdata_logonType'] = lambda x: len(set(x))
            if 'is_failed_logon' in available_cols:
                hourly_agg_dict['is_failed_logon'] = 'sum'
            if 'is_logon_event' in available_cols:
                hourly_agg_dict['is_logon_event'] = 'sum'
            
            if hourly_agg_dict and 'data_win_eventdata_targetUserName' in available_cols:
                hourly_stats = df.groupby(['data_win_eventdata_targetUserName', 'timestamp_hour']).agg(hourly_agg_dict).reset_index()
                
                # Rename columns
                hourly_col_names = ['data_win_eventdata_targetUserName', 'timestamp_hour']
                if 'src_ip' in hourly_agg_dict:
                    hourly_col_names.append('unique_ips_per_hour')
                if 'data_win_eventdata_logonType' in hourly_agg_dict:
                    hourly_col_names.append('unique_logon_types_per_hour')
                if 'is_failed_logon' in hourly_agg_dict:
                    hourly_col_names.append('failed_logons_per_hour')
                if 'is_logon_event' in hourly_agg_dict:
                    hourly_col_names.append('successful_logons_per_hour')
                
                hourly_stats.columns = hourly_col_names
                df = df.merge(hourly_stats, on=['data_win_eventdata_targetUserName', 'timestamp_hour'], how='left')
            else:
                # Add default hourly columns
                df['unique_ips_per_hour'] = 1
                df['unique_logon_types_per_hour'] = 1
                df['failed_logons_per_hour'] = 0
                df['successful_logons_per_hour'] = 1
        else:
            # Add default columns if timestamp processing failed
            df['unique_ips_per_hour'] = 1
            df['unique_logon_types_per_hour'] = 1
            df['failed_logons_per_hour'] = 0
            df['successful_logons_per_hour'] = 1
        
        return df
    
    def _engineer_geographic_features(self, df):
        """Engineer geographic and impossible travel features"""
        print("  🌍 Engineering geographic features...")
        
        # Check if geographic columns exist
        has_country = 'src_geo_country' in df.columns
        has_coordinates = 'src_geo_coordinates' in df.columns
        
        if has_country:
            # Country-based features
            df['is_domestic'] = df['src_geo_country'] == 'India'
            df['is_unknown_location'] = df['src_geo_country'] == 'unknown'
        else:
            df['is_domestic'] = True  # Default assumption
            df['is_unknown_location'] = True
        
        if has_coordinates and '@timestamp' in df.columns and 'data_win_eventdata_targetUserName' in df.columns:
            # Impossible travel detection
            # First ensure timestamp is properly converted
            df['@timestamp'] = pd.to_datetime(df['@timestamp'], format='mixed')
            df = df.sort_values(['data_win_eventdata_targetUserName', '@timestamp'])
            
            def detect_impossible_travel(user_group):
                user_group = user_group.copy()
                
                # Ensure timestamps are datetime objects
                user_group['@timestamp'] = pd.to_datetime(user_group['@timestamp'], format='mixed')
                user_group['prev_timestamp'] = user_group['@timestamp'].shift(1)
                
                user_group['prev_lat'] = user_group['src_lat'].shift(1)
                user_group['prev_lon'] = user_group['src_lon'].shift(1)
                
                # Calculate distance and time difference - only for non-null timestamps
                def safe_calculate_distance(row):
                    try:
                        return self.calculate_distance(
                            row['src_lat'], row['src_lon'], 
                            row['prev_lat'], row['prev_lon']
                        )
                    except:
                        return 0
                
                user_group['distance_km'] = user_group.apply(safe_calculate_distance, axis=1)
                
                # Calculate time difference safely
                def safe_time_diff(row):
                    try:
                        if pd.isna(row['@timestamp']) or pd.isna(row['prev_timestamp']):
                            return 0
                        return (row['@timestamp'] - row['prev_timestamp']).total_seconds()
                    except:
                        return 0
                
                user_group['time_diff_seconds'] = user_group.apply(safe_time_diff, axis=1)
                
                # Impossible travel if distance > time allows (assuming 1000 km/h max speed)
                user_group['is_impossible_travel'] = (
                    (user_group['distance_km'] > 0) & 
                    (user_group['time_diff_seconds'] > 0) &
                    (user_group['distance_km'] / (user_group['time_diff_seconds'] / 3600) > 1000)
                )
                
                # Also flag rapid location changes (< 10 minutes, > 100km)
                user_group['is_rapid_travel'] = (
                    (user_group['distance_km'] > 100) & 
                    (user_group['time_diff_seconds'] < self.impossible_travel_threshold) &
                    (user_group['time_diff_seconds'] > 0)
                )
                
                return user_group
            
            # Apply impossible travel detection per user
            try:
                df = df.groupby('data_win_eventdata_targetUserName').apply(detect_impossible_travel).reset_index(drop=True)
            except Exception as e:
                print(f"    ⚠️  Impossible travel detection failed: {str(e)}")
                # Add default columns if detection fails
                df['distance_km'] = 0
                df['time_diff_seconds'] = 0
                df['is_impossible_travel'] = False
                df['is_rapid_travel'] = False
        else:
            # Add default columns if geographic analysis can't be done
            df['distance_km'] = 0
            df['time_diff_seconds'] = 0
            df['is_impossible_travel'] = False
            df['is_rapid_travel'] = False
        
        # Fill NaN values
        geographic_cols = ['is_impossible_travel', 'is_rapid_travel', 'distance_km', 'time_diff_seconds']
        for col in geographic_cols:
            if col in df.columns:
                if col in ['is_impossible_travel', 'is_rapid_travel']:
                    df[col] = df[col].fillna(False)
                else:
                    df[col] = df[col].fillna(0)
        
        return df
    
    def _engineer_temporal_features(self, df):
        """Engineer temporal pattern features"""
        print("  ⏰ Engineering temporal features...")
        
        # Unusual time patterns
        df['is_unusual_hour'] = ~df['is_business_hours'] & ~df['is_weekend']
        df['is_midnight_access'] = df['hour'].isin([0, 1, 2, 3])
        df['is_early_morning'] = df['hour'].isin([4, 5, 6])
        df['is_late_night'] = df['hour'].isin([22, 23])
        
        # User's typical time patterns - only if we have the target user column
        if 'data_win_eventdata_targetUserName' in df.columns:
            user_time_patterns = df.groupby('data_win_eventdata_targetUserName').agg({
                'hour': lambda x: x.mode().iloc[0] if len(x.mode()) > 0 else 12,  # Most common hour
                'is_business_hours': 'mean',  # Percentage of business hours activity
                'is_weekend': 'mean'  # Percentage of weekend activity
            }).reset_index()
            
            user_time_patterns.columns = ['data_win_eventdata_targetUserName', 'typical_hour',
                                         'business_hours_ratio', 'weekend_activity_ratio']
            
            df = df.merge(user_time_patterns, on='data_win_eventdata_targetUserName', how='left')
            
            # Deviation from typical patterns
            df['hour_deviation'] = abs(df['hour'] - df['typical_hour'])
            df['is_atypical_time'] = (
                (~df['is_business_hours'] & (df['business_hours_ratio'] > 0.8)) |
                (df['is_weekend'] & (df['weekend_activity_ratio'] < 0.1))
            )
        else:
            # Add default columns if user analysis can't be done
            df['typical_hour'] = 12
            df['business_hours_ratio'] = 0.8
            df['weekend_activity_ratio'] = 0.1
            df['hour_deviation'] = abs(df['hour'] - 12)
            df['is_atypical_time'] = ~df['is_business_hours']
        
        return df
    
    def _engineer_security_features(self, df):
        """Engineer security-specific features"""
        print("  🛡️ Engineering security features...")
        
        # Check if required columns exist for brute force detection
        has_target_user = 'data_win_eventdata_targetUserName' in df.columns
        has_src_ip = 'src_ip' in df.columns
        has_timestamp = '@timestamp' in df.columns
        
        if has_target_user and has_src_ip and has_timestamp:
            # Brute force detection
            df = df.sort_values(['data_win_eventdata_targetUserName', 'src_ip', '@timestamp'])
            
            def detect_brute_force(group):
                group = group.copy()
                group['prev_timestamp'] = group['@timestamp'].shift(1)
                group['time_since_last'] = (
                    group['@timestamp'] - group['prev_timestamp']
                ).dt.total_seconds()
                
                # Count rapid failures
                group['rapid_failure'] = (
                    group['is_failed_logon'] & 
                    (group['time_since_last'] <= self.brute_force_window)
                )
                
                # Rolling count of failures in window
                group['failures_in_window'] = group['rapid_failure'].rolling(
                    window=self.brute_force_threshold, min_periods=1
                ).sum()
                
                group['is_brute_force'] = group['failures_in_window'] >= self.brute_force_threshold
                
                return group
            
            # Apply brute force detection per user-IP combination
            df = df.groupby(['data_win_eventdata_targetUserName', 'src_ip']).apply(detect_brute_force).reset_index(drop=True)
        else:
            # Add default columns if brute force detection can't be done
            df['rapid_failure'] = False
            df['failures_in_window'] = 0
            df['is_brute_force'] = False
            df['time_since_last'] = 0
        
        # Pass-the-hash indicators
        if 'data_win_eventdata_authenticationPackageName' in df.columns:
            df['is_ntlm_auth'] = df['data_win_eventdata_authenticationPackageName'].str.contains('NTLM', na=False)
        else:
            df['is_ntlm_auth'] = False
            
        df['is_network_ntlm'] = df['is_network_logon'] & df['is_ntlm_auth']
        df['is_potential_pth'] = (
            df['is_network_ntlm'] & 
            df['data_win_eventdata_logonType'].isin([3, 9])
        )
        
        # Privilege escalation indicators
        if 'data_win_eventdata_privilegeList' in df.columns:
            high_privileges = ['SeDebugPrivilege', 'SeTakeOwnershipPrivilege', 'SeBackupPrivilege', 
                              'SeRestorePrivilege', 'SeSecurityPrivilege']
            
            df['has_high_privileges'] = df['data_win_eventdata_privilegeList'].apply(
                lambda x: any(priv in str(x) for priv in high_privileges) if pd.notna(x) else False
            )
        else:
            df['has_high_privileges'] = False
        
        # Lateral movement indicators
        df['is_lateral_movement'] = (
            df['is_network_logon'] & 
            df['data_win_eventdata_targetUserName'].notna() if 'data_win_eventdata_targetUserName' in df.columns else False
        )
        
        # Unusual process creation
        if 'data_win_eventdata_processName' in df.columns:
            suspicious_processes = [
                'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
                'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
                'bitsadmin.exe', 'psexec.exe', 'mimikatz.exe', 'procdump.exe'
            ]
            
            df['is_suspicious_process'] = df['data_win_eventdata_processName'].apply(
                lambda x: any(proc in str(x).lower() for proc in suspicious_processes) if pd.notna(x) else False
            )
        else:
            df['is_suspicious_process'] = False
        
        # RDP-specific features
        df['is_rdp_logon'] = df['is_remote_interactive'] & df['is_logon_event']
        
        if 'src_ip' in df.columns:
            df['is_rdp_from_external'] = (
                df['is_rdp_logon'] & 
                ~df['src_ip'].str.startswith(('192.168.', '10.', '172.'), na=False)
            )
        else:
            df['is_rdp_from_external'] = False
        
        # Fill NaN values for security features
        security_bool_cols = ['is_brute_force', 'rapid_failure', 'is_ntlm_auth', 
                             'is_network_ntlm', 'is_potential_pth', 'has_high_privileges',
                             'is_lateral_movement', 'is_suspicious_process', 'is_rdp_logon',
                             'is_rdp_from_external']
        
        for col in security_bool_cols:
            if col in df.columns:
                df[col] = df[col].fillna(False)
        
        numeric_security_cols = ['failures_in_window', 'time_since_last']
        for col in numeric_security_cols:
            if col in df.columns:
                df[col] = df[col].fillna(0)
        
        return df
    
    def prepare_ml_features(self, df):
        """Prepare features for ML models"""
        print("🔧 Preparing ML features...")
        
        # Get available columns
        available_cols = df.columns.tolist()
        
        # Select comprehensive feature set for all 10 use cases - only use existing columns
        potential_feature_cols = [
            # Temporal features (Use cases 1, 6)
            'hour', 'day_of_week', 'is_business_hours', 'is_weekend', 'is_night',
            'is_unusual_hour', 'is_midnight_access', 'is_early_morning', 'is_late_night',
            'hour_deviation', 'is_atypical_time', 'business_hours_ratio', 'weekend_activity_ratio',
            
            # User behavior features (Use cases 2, 7)
            'unique_ips_per_user', 'unique_logon_types_per_user', 'unique_hours_per_user',
            'unique_countries_per_user', 'total_events_per_user', 'unique_ips_per_hour',
            'unique_logon_types_per_hour', 'failed_logons_per_hour', 'successful_logons_per_hour',
            
            # Geographic features (Use cases 5, 9)
            'is_domestic', 'is_unknown_location', 'is_impossible_travel', 'is_rapid_travel',
            'distance_km', 'time_diff_seconds', 'src_lat', 'src_lon',
            
            # Security features (Use cases 3, 4, 8, 10)
            'is_brute_force', 'failures_in_window', 'is_ntlm_auth', 'is_network_ntlm',
            'is_potential_pth', 'has_high_privileges', 'is_lateral_movement',
            'is_suspicious_process', 'is_rdp_logon', 'is_rdp_from_external',
            
            # Event type features
            'is_logon_event', 'is_failed_logon', 'is_privilege_event', 'is_process_creation',
            'is_remote_interactive', 'is_network_logon', 'is_interactive_logon',
            
            # Numeric fields
            'data_win_system_eventID', 'data_win_eventdata_logonType'
        ]
        
        # Filter to only use columns that actually exist
        feature_cols = [col for col in potential_feature_cols if col in available_cols]
        
        print(f"  📊 Using {len(feature_cols)} available features out of {len(potential_feature_cols)} potential features")
        
        # Categorical features to encode - only use existing columns
        potential_categorical_cols = [
            'data_win_eventdata_targetUserName', 'data_win_eventdata_subjectUserName',
            'src_geo_country', 'src_geo_city', 'data_win_eventdata_processName',
            'data_win_eventdata_authenticationPackageName', 'data_win_eventdata_logonProcessName',
            'data_win_eventdata_failureReason', 'src_ip'
        ]
        
        categorical_cols = [col for col in potential_categorical_cols if col in available_cols]
        
        # Prepare feature matrix
        X = df[feature_cols].copy()
        
        # Encode categorical variables with frequency encoding for high cardinality
        for col in categorical_cols:
            try:
                if col not in self.encoders:
                    # Use frequency encoding for high cardinality features
                    if df[col].nunique() > 100:
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
        
        # Show which key features are missing for debugging
        missing_features = [col for col in potential_feature_cols if col not in available_cols]
        if missing_features:
            print(f"  📋 Missing features: {missing_features[:10]}...")  # Show first 10
        
        return X
    
    def train_models(self, X):
        """Train comprehensive anomaly detection models"""
        print("🤖 Training Windows Event Log ML models...")
        
        # Scale features
        if 'scaler' not in self.scalers:
            self.scalers['scaler'] = StandardScaler()
            X_scaled = self.scalers['scaler'].fit_transform(X)
        else:
            X_scaled = self.scalers['scaler'].transform(X)
        
        # Initialize models with adjusted parameters for Windows events
        models_config = {
            'isolation_forest': IsolationForest(
                contamination=0.05,  # Lower contamination for Windows events
                random_state=42,
                n_estimators=150
            ),
            'one_class_svm': OneClassSVM(
                kernel='rbf',
                gamma='scale',
                nu=0.05
            ),
            'gaussian_mixture': GaussianMixture(
                n_components=5,  # More components for diverse Windows events
                random_state=42
            ),
            'hdbscan': HDBSCAN(
                min_cluster_size=50,
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
                    threshold = np.percentile(scores, 5)  # Bottom 5% as anomalies
                    self.models[model_name] = {'model': model, 'threshold': threshold}
                elif model_name == 'hdbscan':
                    labels = model.fit_predict(X_scaled)
                    # HDBSCAN: -1 labels are outliers/anomalies
                    outlier_scores = model.outlier_scores_
                    threshold = np.percentile(outlier_scores, 95)  # Top 5% as anomalies
                    self.models[model_name] = {'model': model, 'threshold': threshold, 'labels': labels}
                else:
                    model.fit(X_scaled)
                    self.models[model_name] = {'model': model}
                
                print(f"✅ {model_name} trained successfully")
            except Exception as e:
                print(f"❌ Error training {model_name}: {str(e)}")
        
        print("🎯 All Windows Event Log models trained!")
    
    def predict_anomalies(self, X, df):
        """Predict anomalies using trained models"""
        print("🔍 Detecting Windows Event Log anomalies...")
        
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
                    outlier_scores = model.outlier_scores_ if hasattr(model, 'outlier_scores_') else np.zeros(len(X_scaled))
                    threshold = model_info['threshold']
                    predictions = (outlier_scores > threshold).astype(int)
                    results[f'{model_name}_score'] = outlier_scores
                    results[f'{model_name}_anomaly'] = predictions
                else:
                    predictions = model.predict(X_scaled)
                    scores = model.decision_function(X_scaled) if hasattr(model, 'decision_function') else model.score_samples(X_scaled)
                    
                    # Convert to binary (1 = normal, -1 = anomaly for isolation forest and one-class SVM)
                    anomalies = (predictions == -1).astype(int)
                    results[f'{model_name}_score'] = scores
                    results[f'{model_name}_anomaly'] = anomalies
                
                print(f"✅ {model_name}: {sum(results[f'{model_name}_anomaly'])} anomalies detected")
                
            except Exception as e:
                print(f"❌ Error in {model_name} prediction: {str(e)}")
        
        # Create ensemble score (majority voting with at least 2 models agreeing)
        anomaly_cols = [col for col in results.columns if col.endswith('_anomaly')]
        if len(anomaly_cols) > 0:
            results['ensemble_anomaly_score'] = results[anomaly_cols].sum(axis=1)
            results['is_anomaly'] = results['ensemble_anomaly_score'] >= 2  # At least 2 models agree
        
        # Add use case specific flags for investigation
        results = self._add_use_case_flags(results)
        
        return results
    
    def _add_use_case_flags(self, results):
        """Add specific use case flags for easier investigation"""
        
        # Use case flags
        results['uc1_anomalous_logon_time'] = (
            results['is_anomaly'] & results['is_logon_event'] & results['is_atypical_time']
        )
        
        results['uc2_lateral_movement'] = (
            results['is_anomaly'] & results['is_lateral_movement'] & 
            (results['is_network_logon'] | results['is_remote_interactive'])
        )
        
        results['uc3_privilege_escalation'] = (
            results['is_anomaly'] & 
            (results['is_privilege_event'] | results['has_high_privileges'])
        )
        
        results['uc4_unusual_process'] = (
            results['is_anomaly'] & results['is_process_creation'] & results['is_suspicious_process']
        )
        
        results['uc5_geoip_rdp_anomaly'] = (
            results['is_anomaly'] & results['is_rdp_logon'] & ~results['is_domestic']
        )
        
        results['uc6_unusual_logon_times'] = (
            results['is_anomaly'] & results['is_logon_event'] & 
            (results['is_midnight_access'] | results['is_early_morning'] | results['is_late_night'])
        )
        
        results['uc7_unusual_host_logon'] = (
            results['is_anomaly'] & results['is_logon_event'] & 
            (results['unique_ips_per_user'] > results['unique_ips_per_user'].quantile(0.95))
        )
        
        results['uc8_pass_the_hash'] = (
            results['is_anomaly'] & results['is_potential_pth']
        )
        
        results['uc9_impossible_travel'] = (
            results['is_anomaly'] & (results['is_impossible_travel'] | results['is_rapid_travel'])
        )
        
        results['uc10_brute_force'] = (
            results['is_anomaly'] & results['is_brute_force']
        )
        
        return results
    
    def save_models(self):
        """Save trained models"""
        models_path = f"{self.results_dir}/models/windows_models.pkl"
        scalers_path = f"{self.results_dir}/models/windows_scalers.pkl"
        encoders_path = f"{self.results_dir}/models/windows_encoders.pkl"
        
        with open(models_path, 'wb') as f:
            pickle.dump(self.models, f)
        
        with open(scalers_path, 'wb') as f:
            pickle.dump(self.scalers, f)
            
        with open(encoders_path, 'wb') as f:
            pickle.dump(self.encoders, f)
        
        # Save feature columns
        with open(f"{self.results_dir}/models/windows_feature_columns.json", 'w') as f:
            json.dump(self.feature_columns, f)
        
        print(f"💾 Windows models saved to {models_path}")
    
    def save_results(self, results, filename=None):
        """Save anomaly detection results"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"windows_anomalies_{timestamp}.json"
        
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
            "uc1_anomalous_logon_time": "Anomalous Logon Time",
            "uc2_lateral_movement": "Lateral Movement Attempts", 
            "uc3_privilege_escalation": "Privilege Escalation",
            "uc4_unusual_process": "Unusual Process Creation",
            "uc5_geoip_rdp_anomaly": "GeoIP RDP Anomaly",
            "uc6_unusual_logon_times": "Unusual Logon Times",
            "uc7_unusual_host_logon": "Unusual Host Logons",
            "uc8_pass_the_hash": "Pass-the-Hash Attacks",
            "uc9_impossible_travel": "Impossible Travel",
            "uc10_brute_force": "Brute Force Attacks"
        }
        
        for uc_col, uc_name in use_cases.items():
            if uc_col in results.columns:
                summary["use_case_breakdown"][uc_name] = int(results[uc_col].sum())
        
        # Save summary
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_path = f"{self.results_dir}/results/windows_summary_{timestamp}.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"📊 Summary: {total_anomalies}/{total_logs} anomalies ({total_anomalies/total_logs*100:.2f}%)")
        return results_path

def main():
    """Main function to run Windows Event Log ML detection"""
    print("🚀 Starting Windows Event Log ML Anomaly Detection...")
    
    # Initialize detector
    detector = WindowsMLDetector()
    
    # Check if we have saved data first
    csv_path = "ml_results/data/windows_event_data.csv"
    json_path = "ml_results/data/windows_raw_data.json"
    
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
            
            fetcher = WindowsDataFetcher()
            df = fetcher.convert_to_dataframe(logs)
            print(f"✅ Loaded {len(df)} records from JSON")
        except Exception as e:
            print(f"⚠️  Error loading JSON: {str(e)}")
    
    # If no saved data, fetch fresh data
    if df is None or df.empty:
        print("📥 No saved data found. Fetching fresh data from OpenSearch...")
        fetcher = WindowsDataFetcher()
        logs = fetcher.fetch_windows_event_logs(days_back=7, size=20000)
        
        if not logs:
            print("❌ No logs available for training")
            return
        
        # Convert to DataFrame
        df = fetcher.convert_to_dataframe(logs)
        
        if df.empty:
            print("❌ DataFrame is empty")
            return
    
    print(f"🎯 Using dataset with {len(df)} records for Windows Event Log ML training")
    
    # Engineer features
    df_features = detector.engineer_features(df)
    
    # Prepare ML features
    X = detector.prepare_ml_features(df_features)
    
    # Train models
    detector.train_models(X)
    
    # Predict anomalies
    results = detector.predict_anomalies(X, df_features)
    
    # Save models and results
    detector.save_models()
    results_path = detector.save_results(results)
    
    # Show sample anomalies by use case
    print(f"\n🚨 USE CASE ANOMALY BREAKDOWN:")
    print("="*50)
    
    use_case_columns = [col for col in results.columns if col.startswith('uc')]
    for col in use_case_columns:
        count = results[col].sum()
        if count > 0:
            uc_name = col.replace('_', ' ').title()
            print(f"  {uc_name}: {count} anomalies")
    
    print("\n✅ Windows Event Log ML Detection Complete!")
    print(f"📁 Results saved to: {results_path}")

if __name__ == "__main__":
    main()
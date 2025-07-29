#!/usr/bin/env python3
"""
Firewall ML Anomaly Detector
Path: Scripts/ml/mlFirewallDetector.py

Detects:
1. Lateral Movement: Internal IP connecting to multiple internal machines
2. GeoIP Anomalies: Connections to/from unusual countries
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
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from fetchFirewallData import FirewallDataFetcher
import warnings
warnings.filterwarnings('ignore')

class FirewallMLDetector:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_columns = []
        self.results_dir = "ml_results"
        self.setup_directories()
        
    def setup_directories(self):
        """Create necessary directories"""
        dirs = ['models', 'results', 'logs', 'data']
        for dir_name in dirs:
            os.makedirs(f"{self.results_dir}/{dir_name}", exist_ok=True)
    
    def is_internal_ip(self, ip):
        """Check if IP is internal (192.168.x.x)"""
        if pd.isna(ip) or ip == 'unknown':
            return False
        try:
            return str(ip).startswith('192.168.')
        except:
            return False
    
    def is_rdp_related(self, port, service):
        """Check if connection is RDP/SMB/WinRM related"""
        rdp_ports = [3389, 22, 445, 5985, 5986]
        rdp_services = ['rdp', 'ssh', 'smb', 'winrm', 'wsman']
        
        port_match = False
        service_match = False
        
        try:
            port_match = int(port) in rdp_ports
        except:
            pass
            
        try:
            service_match = any(svc in str(service).lower() for svc in rdp_services)
        except:
            pass
            
        return port_match or service_match
    
    def parse_coordinates(self, coord_str):
        """Parse coordinate string to get latitude and longitude"""
        if pd.isna(coord_str) or coord_str == 'unknown' or coord_str == 'nan':
            return None, None
        try:
            # Handle different coordinate formats
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
    
    def engineer_features(self, df):
        """Create features for anomaly detection"""
        print("🔧 Engineering features...")
        
        # Basic preprocessing
        df = df.copy()
        df['src_ip_internal'] = df['src_ip'].apply(self.is_internal_ip)
        df['dest_ip_internal'] = df['dest_ip'].apply(self.is_internal_ip)
        df['is_rdp_related'] = df.apply(lambda x: self.is_rdp_related(x['dest_port'], x['data_service']), axis=1)
        
        # Parse coordinates
        df['src_lat'], df['src_lon'] = zip(*df['src_geo_coordinates'].apply(self.parse_coordinates))
        df['dest_lat'], df['dest_lon'] = zip(*df['dest_geo_coordinates'].apply(self.parse_coordinates))
        
        # Action-based features
        df['is_allow_action'] = df['action'].str.lower() == 'allow'
        df['is_deny_action'] = df['action'].str.lower() == 'deny'
        df['is_drop_action'] = df['action'].str.lower() == 'drop'
        
        # Time-based features
        df['hour'] = pd.to_datetime(df['@timestamp'], format='mixed').dt.hour
        df['day_of_week'] = pd.to_datetime(df['@timestamp'], format='mixed').dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6])
        df['is_night'] = df['hour'].isin([22, 23, 0, 1, 2, 3, 4, 5])
        
        # Lateral Movement Features (per hour windows)
        lateral_features = []
        
        # Group by source IP and hour for lateral movement detection
        df['timestamp_hour'] = pd.to_datetime(df['@timestamp'], format='mixed').dt.floor('H')
        
        # Count unique destinations per source per hour (internal only)
        internal_lateral = df[df['src_ip_internal'] & df['dest_ip_internal']].copy()
        
        if not internal_lateral.empty:
            hourly_lateral = internal_lateral.groupby(['src_ip', 'timestamp_hour']).agg({
                'dest_ip': 'nunique',
                'dest_port': lambda x: len(set(x)),
                'is_rdp_related': 'sum',
                'rule_id': 'nunique'
            }).reset_index()
            
            hourly_lateral.columns = ['src_ip', 'timestamp_hour', 'unique_dest_ips_per_hour', 
                                    'unique_ports_per_hour', 'rdp_connections_per_hour', 'unique_rules_per_hour']
            
            # Merge back to main dataframe
            df = df.merge(hourly_lateral, on=['src_ip', 'timestamp_hour'], how='left')
        else:
            df['unique_dest_ips_per_hour'] = 0
            df['unique_ports_per_hour'] = 0
            df['rdp_connections_per_hour'] = 0
            df['unique_rules_per_hour'] = 0
        
        # GeoIP Features
        # Country frequency features
        country_stats = df.groupby(['src_ip']).agg({
            'dest_geo_country': lambda x: len(set(x)),
            'src_geo_country': lambda x: x.iloc[0] if len(x) > 0 else 'unknown',
            'dest_geo_city': lambda x: len(set(x)),
            'src_geo_city': lambda x: x.iloc[0] if len(x) > 0 else 'unknown'
        }).reset_index()
        
        country_stats.columns = ['src_ip', 'unique_dest_countries', 'primary_src_country', 
                                'unique_dest_cities', 'primary_src_city']
        df = df.merge(country_stats, on='src_ip', how='left')
        
        # Application and risk features
        # Convert risk levels to numeric values first
        risk_mapping = {
            'low': 1,
            'medium': 2, 
            'high': 3,
            'critical': 4,
            'unknown': 0
        }
        
        # Convert data_apprisk to numeric
        if 'data_apprisk' in df.columns:
            df['data_apprisk_numeric'] = df['data_apprisk'].astype(str).str.lower().map(risk_mapping).fillna(0)
        else:
            df['data_apprisk_numeric'] = 0
        
        app_stats = df.groupby(['src_ip']).agg({
            'data_app': lambda x: len(set(x)) if 'data_app' in df.columns else 0,
            'data_appcat': lambda x: len(set(x)) if 'data_appcat' in df.columns else 0,
            'data_apprisk_numeric': 'mean'  # Average numeric risk score
        }).reset_index()
        
        app_stats.columns = ['src_ip', 'unique_apps', 'unique_app_categories', 'avg_app_risk']
        df = df.merge(app_stats, on='src_ip', how='left')
        
        # Direction-based features
        df['is_outgoing'] = df['data_direction'] == 'outgoing'
        df['is_incoming'] = df['data_direction'] == 'incoming'
        df['is_to_server'] = df['data_direction'] == 'to_server'
        
        # Fill NaN values
        numeric_cols = ['unique_dest_ips_per_hour', 'unique_ports_per_hour', 'rdp_connections_per_hour', 
                       'unique_rules_per_hour', 'unique_dest_countries', 'unique_dest_cities',
                       'unique_apps', 'unique_app_categories', 'avg_app_risk', 'src_lat', 'src_lon',
                       'dest_lat', 'dest_lon']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = df[col].fillna(0)
        
        print(f"✅ Feature engineering complete. Shape: {df.shape}")
        return df
    
    def prepare_ml_features(self, df):
        """Prepare features for ML models"""
        print("🔧 Preparing ML features...")
        
        # Select features for ML
        feature_cols = [
            'unique_dest_ips_per_hour', 'unique_ports_per_hour', 'rdp_connections_per_hour',
            'unique_rules_per_hour', 'unique_dest_countries', 'unique_dest_cities',
            'unique_apps', 'unique_app_categories', 'avg_app_risk', 'hour', 'day_of_week',
            'is_weekend', 'is_night', 'is_rdp_related', 'src_ip_internal', 'dest_ip_internal',
            'is_outgoing', 'is_incoming', 'is_to_server', 'dest_port', 'src_port',
            'is_allow_action', 'is_deny_action', 'is_drop_action', 'src_lat', 'src_lon',
            'dest_lat', 'dest_lon'
        ]
        
        # Categorical features to encode
        categorical_cols = ['data_service', 'dest_geo_country', 'primary_src_country',
                           'dest_geo_city', 'primary_src_city', 'data_app', 'data_appcat',
                           'data_level', 'dev_name', 'action']
        
        # Prepare feature matrix
        X = df[feature_cols].copy()
        
        # Encode categorical variables
        for col in categorical_cols:
            if col in df.columns:
                if col not in self.encoders:
                    self.encoders[col] = LabelEncoder()
                    encoded = self.encoders[col].fit_transform(df[col].astype(str))
                else:
                    encoded = self.encoders[col].transform(df[col].astype(str))
                X[f'{col}_encoded'] = encoded
        
        # Handle any remaining NaN values
        X = X.fillna(0)
        
        # Store feature columns
        self.feature_columns = X.columns.tolist()
        
        print(f"✅ ML features prepared. Shape: {X.shape}")
        print(f"🔍 Features: {self.feature_columns}")
        
        return X
    
    def train_models(self, X):
        """Train anomaly detection models"""
        print("🤖 Training ML models...")
        
        # Scale features
        if 'scaler' not in self.scalers:
            self.scalers['scaler'] = StandardScaler()
            X_scaled = self.scalers['scaler'].fit_transform(X)
        else:
            X_scaled = self.scalers['scaler'].transform(X)
        
        # Initialize models
        models_config = {
            'isolation_forest': IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            ),
            'one_class_svm': OneClassSVM(
                kernel='rbf',
                gamma='scale',
                nu=0.1
            ),
            'gaussian_mixture': GaussianMixture(
                n_components=3,
                random_state=42
            )
        }
        
        # Train each model
        for model_name, model in models_config.items():
            print(f"🔧 Training {model_name}...")
            try:
                if model_name == 'gaussian_mixture':
                    model.fit(X_scaled)
                    # For GMM, we'll use probability threshold for anomaly detection
                    scores = model.score_samples(X_scaled)
                    threshold = np.percentile(scores, 10)  # Bottom 10% as anomalies
                    self.models[model_name] = {'model': model, 'threshold': threshold}
                else:
                    model.fit(X_scaled)
                    self.models[model_name] = {'model': model}
                
                print(f"✅ {model_name} trained successfully")
            except Exception as e:
                print(f"❌ Error training {model_name}: {str(e)}")
        
        print("🎯 All models trained!")
    
    def predict_anomalies(self, X, df):
        """Predict anomalies using trained models"""
        print("🔍 Detecting anomalies...")
        
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
        
        # Create ensemble score (majority voting)
        anomaly_cols = [col for col in results.columns if col.endswith('_anomaly')]
        if len(anomaly_cols) > 0:
            results['ensemble_anomaly_score'] = results[anomaly_cols].sum(axis=1)
            results['is_anomaly'] = results['ensemble_anomaly_score'] >= 2  # At least 2 models agree
        
        return results
    
    def save_models(self):
        """Save trained models"""
        models_path = f"{self.results_dir}/models/firewall_models.pkl"
        scalers_path = f"{self.results_dir}/models/firewall_scalers.pkl"
        encoders_path = f"{self.results_dir}/models/firewall_encoders.pkl"
        
        with open(models_path, 'wb') as f:
            pickle.dump(self.models, f)
        
        with open(scalers_path, 'wb') as f:
            pickle.dump(self.scalers, f)
            
        with open(encoders_path, 'wb') as f:
            pickle.dump(self.encoders, f)
        
        # Save feature columns
        with open(f"{self.results_dir}/models/feature_columns.json", 'w') as f:
            json.dump(self.feature_columns, f)
        
        print(f"💾 Models saved to {models_path}")
    
    def load_models(self):
        """Load trained models"""
        try:
            with open(f"{self.results_dir}/models/firewall_models.pkl", 'rb') as f:
                self.models = pickle.load(f)
            
            with open(f"{self.results_dir}/models/firewall_scalers.pkl", 'rb') as f:
                self.scalers = pickle.load(f)
                
            with open(f"{self.results_dir}/models/firewall_encoders.pkl", 'rb') as f:
                self.encoders = pickle.load(f)
            
            with open(f"{self.results_dir}/models/feature_columns.json", 'r') as f:
                self.feature_columns = json.load(f)
            
            print("✅ Models loaded successfully")
            return True
        except Exception as e:
            print(f"❌ Error loading models: {str(e)}")
            return False
    
    def save_results(self, results, filename=None):
        """Save anomaly detection results"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"firewall_anomalies_{timestamp}.json"
        
        results_path = f"{self.results_dir}/results/{filename}"
        
        # Convert DataFrame to JSON-serializable format
        results_json = results.to_dict('records')
        
        # Save results
        with open(results_path, 'w') as f:
            json.dump(results_json, f, indent=2, default=str)
        
        print(f"💾 Results saved to: {results_path}")
        
        # Summary statistics
        total_logs = len(results)
        total_anomalies = results['is_anomaly'].sum() if 'is_anomaly' in results.columns else 0
        
        summary = {
            "timestamp": datetime.now().isoformat(),
            "total_logs_analyzed": int(total_logs),
            "total_anomalies_detected": int(total_anomalies),
            "anomaly_percentage": float(total_anomalies / total_logs * 100) if total_logs > 0 else 0,
            "model_scores": {}
        }
        
        # Add individual model statistics
        for col in results.columns:
            if col.endswith('_anomaly'):
                model_name = col.replace('_anomaly', '')
                summary["model_scores"][model_name] = int(results[col].sum())
        
        # Save summary
        summary_path = f"{self.results_dir}/results/summary_{timestamp}.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"📊 Summary: {total_anomalies}/{total_logs} anomalies ({total_anomalies/total_logs*100:.2f}%)")
        return results_path

def main():
    """Main function to run ML detection"""
    print("🚀 Starting Firewall ML Anomaly Detection...")
    
    # Initialize detector
    detector = FirewallMLDetector()
    
    # Check if we have saved data first
    csv_path = "ml_results/data/firewall_data.csv"
    json_path = "ml_results/data/firewall_raw_data.json"
    
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
            
            fetcher = FirewallDataFetcher()
            df = fetcher.convert_to_dataframe(logs)
            print(f"✅ Loaded {len(df)} records from JSON")
        except Exception as e:
            print(f"⚠️  Error loading JSON: {str(e)}")
    
    # If no saved data, fetch fresh data
    if df is None or df.empty:
        print("📥 No saved data found. Fetching fresh data from OpenSearch...")
        fetcher = FirewallDataFetcher()
        logs = fetcher.fetch_firewall_logs(days_back=7, size=5000)
        
        if not logs:
            print("❌ No logs available for training")
            return
        
        # Convert to DataFrame
        df = fetcher.convert_to_dataframe(logs)
        
        if df.empty:
            print("❌ DataFrame is empty")
            return
    
    print(f"🎯 Using dataset with {len(df)} records for ML training")
    
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
    
    # Show sample anomalies
    if 'is_anomaly' in results.columns:
        anomalies = results[results['is_anomaly'] == True]
        if not anomalies.empty:
            print("\n🚨 Sample Anomalies Detected:")
            print("="*80)
            cols_to_show = ['@timestamp', 'src_ip', 'dest_ip', 'dest_port', 'data_direction', 
                           'dest_geo_country', 'action', 'data_app', 'unique_dest_ips_per_hour', 
                           'ensemble_anomaly_score']
            sample_anomalies = anomalies[cols_to_show].head(10)
            print(sample_anomalies.to_string(index=False))
    
    print("\n✅ ML Detection Complete!")
    print(f"📁 Results saved to: {results_path}")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Fetch Firewall logs from OpenSearch for ML training
Path: Scripts/ml/fetchFirewallData.py
"""

import os
import json
import pandas as pd
from datetime import datetime, timedelta
from opensearchpy import OpenSearch
from dotenv import load_dotenv

# Load environment variables
load_dotenv('../.env')

class FirewallDataFetcher:
    def __init__(self):
        self.opensearch_host = os.getenv('OPENSEARCH_HOST', 'http://192.168.109.128:9200')
        self.client = OpenSearch([self.opensearch_host])
        
    def get_firewall_indexes(self, days_back=7):
        """Generate firewall index names for the last N days"""
        indexes = []
        for i in range(days_back):
            date = datetime.now() - timedelta(days=i)
            date_str = date.strftime("%d-%m-%Y")
            indexes.append(f"logs-firewall-{date_str}")
        return indexes
    
    def fetch_firewall_logs(self, days_back=7, size=10000):
        """Fetch firewall logs from OpenSearch"""
        indexes = self.get_firewall_indexes(days_back)
        print(f"🔍 Fetching from indexes: {indexes}")
        
        # Query to fetch firewall logs
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"stream_type.keyword": "Firewall"}},
                        {"range": {"@timestamp": {"gte": f"now-{days_back}d"}}}
                    ]
                }
            },
            "size": size,
            "_source": [
                "action", "data_app", "data_appcat", "data_apprisk", "data_direction", 
                "data_level", "data_msg", "data_service", "dest_geo_coordinates", 
                "dest_geo_city", "dest_geo_country", "dest_ip", "dest_port", 
                "dev_name", "rule_description", "rule_id", "src_geo_coordinates", 
                "src_geo_city", "src_geo_country", "src_ip", "src_port", 
                "timestamp", "@timestamp"
            ],
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        
        all_logs = []
        
        for index in indexes:
            try:
                print(f"📥 Fetching from {index}...")
                response = self.client.search(
                    index=index,
                    body=query
                )
                
                hits = response['hits']['hits']
                logs = [hit['_source'] for hit in hits]
                all_logs.extend(logs)
                print(f"✅ Fetched {len(logs)} logs from {index}")
                
            except Exception as e:
                print(f"⚠️  Error fetching from {index}: {str(e)}")
                continue
        
        print(f"🎯 Total logs fetched: {len(all_logs)}")
        return all_logs
    
    def save_raw_data(self, logs, filename="firewall_raw_data.json"):
        """Save raw logs to JSON file"""
        os.makedirs("ml_results/data", exist_ok=True)
        filepath = f"ml_results/data/{filename}"
        
        with open(filepath, 'w') as f:
            json.dump(logs, f, indent=2, default=str)
        
        print(f"💾 Raw data saved to: {filepath}")
        return filepath
    
    def convert_to_dataframe(self, logs):
        """Convert logs to pandas DataFrame for analysis"""
        if not logs:
            print("❌ No logs to convert")
            return pd.DataFrame()
        
        df = pd.DataFrame(logs)
        
        # Convert timestamp
        if '@timestamp' in df.columns:
            df['@timestamp'] = pd.to_datetime(df['@timestamp'])
            df['hour'] = df['@timestamp'].dt.hour
            df['date'] = df['@timestamp'].dt.date
        
        # Handle missing values
        df = df.fillna('unknown')
        
        # Data type conversions
        numeric_cols = ['dest_port', 'src_port']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        # Handle coordinate fields if they exist
        coordinate_cols = ['dest_geo_coordinates', 'src_geo_coordinates']
        for col in coordinate_cols:
            if col in df.columns:
                # Keep as string for now, can be processed later if needed
                df[col] = df[col].astype(str)
        
        # Handle coordinate fields if they exist
        coordinate_cols = ['dest_geo_coordinates', 'src_geo_coordinates']
        for col in coordinate_cols:
            if col in df.columns:
                # Keep as string for now, can be processed later if needed
                df[col] = df[col].astype(str)
        
        print(f"📊 DataFrame created with shape: {df.shape}")
        print(f"🔍 Columns: {list(df.columns)}")
        
        return df
    
    def preview_data(self, df, n=5):
        """Preview the fetched data"""
        if df.empty:
            print("❌ No data to preview")
            return
        
        print("\n" + "="*80)
        print("📋 DATA PREVIEW")
        print("="*80)
        print(f"Total records: {len(df)}")
        print(f"Date range: {df['@timestamp'].min()} to {df['@timestamp'].max()}")
        print(f"Unique source IPs: {df['src_ip'].nunique()}")
        print(f"Unique destination IPs: {df['dest_ip'].nunique()}")
        
        print(f"\n🔍 First {n} records:")
        print(df.head(n).to_string())
        
        print(f"\n📈 Data Direction counts:")
        if 'data_direction' in df.columns:
            print(df['data_direction'].value_counts())
        
        print(f"\n🌍 Top source countries:")
        if 'src_geo_country' in df.columns:
            print(df['src_geo_country'].value_counts().head())
        
        print(f"\n🎯 Top destination countries:")
        if 'dest_geo_country' in df.columns:
            print(df['dest_geo_country'].value_counts().head())
            
        print(f"\n🔧 Top actions:")
        if 'action' in df.columns:
            print(df['action'].value_counts().head())
            
        print(f"\n📱 Top applications:")
        if 'data_app' in df.columns:
            print(df['data_app'].value_counts().head())

def main():
    """Main function to test data fetching"""
    print("🚀 Starting Firewall Data Fetch...")
    
    fetcher = FirewallDataFetcher()
    
    # Fetch logs - REDUCED SIZE to avoid 10k limit error
    logs = fetcher.fetch_firewall_logs(days_back=7, size=5000)
    
    if not logs:
        print("❌ No logs fetched. Check your OpenSearch connection and indexes.")
        return
    
    # Save raw data
    fetcher.save_raw_data(logs)
    
    # Convert to DataFrame
    df = fetcher.convert_to_dataframe(logs)
    
    # Preview data
    fetcher.preview_data(df)
    
    # Save DataFrame as CSV for manual inspection
    os.makedirs("ml_results/data", exist_ok=True)
    csv_path = "ml_results/data/firewall_data.csv"
    df.to_csv(csv_path, index=False)
    print(f"💾 DataFrame saved to: {csv_path}")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Fetch Windows Event Logs from OpenSearch for ML training
Path: Scripts/ml/fetchWindowsData.py
"""

import os
import json
import pandas as pd
from datetime import datetime, timedelta
from opensearchpy import OpenSearch
from dotenv import load_dotenv

# Load environment variables
load_dotenv('../.env')

class WindowsDataFetcher:
    def __init__(self):
        self.opensearch_host = os.getenv('OPENSEARCH_HOST', 'http://192.168.109.128:9200')
        self.client = OpenSearch([self.opensearch_host])
        
    def get_windows_indexes(self, days_back=7):
        """Generate Windows Event Log index names for the last N days"""
        indexes = {
            'windows_events': [],
            'auth_logs': []
        }
        
        for i in range(days_back):
            date = datetime.now() - timedelta(days=i)
            date_str = date.strftime("%d-%m-%Y")
            indexes['windows_events'].append(f"logs-windows-event-logs-{date_str}")
            indexes['auth_logs'].append(f"logs-authentication-logs-{date_str}")
        
        return indexes
    
    def check_existing_indexes(self, index_list, index_type):
        """Check which indexes actually exist"""
        existing_indexes = []
        
        for index in index_list:
            try:
                self.client.indices.get(index=index)
                existing_indexes.append(index)
                print(f"✅ {index_type} index exists: {index}")
            except:
                print(f"⚠️  {index_type} index not found (skipping): {index}")
        
        return existing_indexes
    
    def fetch_windows_event_logs(self, days_back=7, size=10000):
        """Fetch Windows Event Logs from OpenSearch using scroll API"""
        all_logs = []
        total_fetched = 0
        
        # Get index patterns
        index_patterns = self.get_windows_indexes(days_back)
        
        # Check existing Windows Event Log indexes
        print("🔍 Checking Windows Event Log indexes...")
        existing_windows = self.check_existing_indexes(
            index_patterns['windows_events'], 'Windows Event'
        )
        
        # Check existing Authentication Log indexes  
        print("\n🔍 Checking Authentication Log indexes...")
        existing_auth = self.check_existing_indexes(
            index_patterns['auth_logs'], 'Authentication'
        )
        
        if not existing_windows and not existing_auth:
            print("❌ No Windows or Authentication indexes found!")
            return []
        
        # Query for Windows Event Logs (all event IDs)
        windows_query = {
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "data_win_system_eventID"}},
                        {"range": {"@timestamp": {"gte": f"now-{days_back}d"}}}
                    ]
                }
            },
            "_source": [
                "data_win_system_eventID", "data_win_eventdata_targetUserName", 
                "data_win_eventdata_subjectUserName", "data_win_eventdata_logonType",
                "data_win_eventdata_processName", "data_win_eventdata_privilegeList",
                "data_win_eventdata_authenticationPackageName", "data_win_eventdata_logonProcessName",
                "data_win_eventdata_failureReason", "src_ip", "src_geo_country", 
                "src_geo_city", "src_geo_coordinates", "username", "timestamp", "@timestamp"
            ],
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        
        # Query for Authentication Logs (filter by stream_type)
        auth_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"stream_type.keyword": "Authentication Logs"}},
                        {"range": {"@timestamp": {"gte": f"now-{days_back}d"}}}
                    ]
                }
            },
            "_source": [
                "data_win_system_eventID", "data_win_eventdata_targetUserName", 
                "data_win_eventdata_subjectUserName", "data_win_eventdata_logonType",
                "data_win_eventdata_processName", "data_win_eventdata_privilegeList",
                "data_win_eventdata_authenticationPackageName", "data_win_eventdata_logonProcessName",
                "data_win_eventdata_failureReason", "src_ip", "src_geo_country", 
                "src_geo_city", "src_geo_coordinates", "username", "timestamp", "@timestamp",
                "stream_type"
            ],
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        
        # Fetch from Windows Event Log indexes
        if existing_windows:
            print(f"\n📥 Fetching from {len(existing_windows)} Windows Event Log indexes...")
            windows_logs = self._fetch_from_indexes(existing_windows, windows_query, size//2)
            all_logs.extend(windows_logs)
            total_fetched += len(windows_logs)
            print(f"✅ Fetched {len(windows_logs)} Windows Event logs")
        
        # Fetch from Authentication Log indexes
        if existing_auth:
            print(f"\n📥 Fetching from {len(existing_auth)} Authentication Log indexes...")
            auth_logs = self._fetch_from_indexes(existing_auth, auth_query, size//2)
            all_logs.extend(auth_logs)
            total_fetched += len(auth_logs)
            print(f"✅ Fetched {len(auth_logs)} Authentication logs")
        
        print(f"\n🎯 Total logs collected: {total_fetched}")
        return all_logs[:size]  # Limit to requested size
    
    def _fetch_from_indexes(self, index_list, query, max_size):
        """Helper method to fetch logs from a list of indexes"""
        all_logs = []
        fetched_count = 0
        
        for index in index_list:
            if fetched_count >= max_size:
                break
                
            try:
                print(f"  📦 Fetching from {index}...")
                index_logs = []
                
                # Initialize scroll for this index
                response = self.client.search(
                    index=index,
                    body=query,
                    scroll='5m',
                    size=1000  # Process in 1k batches
                )
                
                scroll_id = response['_scroll_id']
                hits = response['hits']['hits']
                
                # Process first batch
                if hits:
                    logs = [hit['_source'] for hit in hits]
                    index_logs.extend(logs)
                    print(f"    📦 Batch 1: {len(logs)} logs")
                
                # Continue scrolling
                batch_num = 2
                while len(hits) > 0 and fetched_count + len(index_logs) < max_size:
                    try:
                        response = self.client.scroll(
                            scroll_id=scroll_id,
                            scroll='5m'
                        )
                        hits = response['hits']['hits']
                        
                        if hits:
                            logs = [hit['_source'] for hit in hits]
                            index_logs.extend(logs)
                            print(f"    📦 Batch {batch_num}: {len(logs)} logs")
                            batch_num += 1
                        
                    except Exception as scroll_error:
                        print(f"    ⚠️  Scroll error: {str(scroll_error)}")
                        break
                
                # Clear scroll
                try:
                    self.client.clear_scroll(scroll_id=scroll_id)
                except:
                    pass
                
                all_logs.extend(index_logs)
                fetched_count += len(index_logs)
                print(f"  ✅ Fetched {len(index_logs)} logs from {index}")
                
            except Exception as e:
                print(f"  ⚠️  Error fetching from {index}: {str(e)}")
                continue
        
        return all_logs
    
    def save_raw_data(self, logs, filename="windows_raw_data.json"):
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
            df['@timestamp'] = pd.to_datetime(df['@timestamp'], format='mixed')
            df['hour'] = df['@timestamp'].dt.hour
            df['day_of_week'] = df['@timestamp'].dt.dayofweek
            df['date'] = df['@timestamp'].dt.date
        
        # Handle missing values
        df = df.fillna('unknown')
        
        # Data type conversions
        numeric_cols = ['data_win_system_eventID', 'data_win_eventdata_logonType']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        # Handle coordinate fields if they exist
        coordinate_cols = ['src_geo_coordinates']
        for col in coordinate_cols:
            if col in df.columns:
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
        print("📋 WINDOWS EVENT LOG DATA PREVIEW")
        print("="*80)
        print(f"Total records: {len(df)}")
        
        if '@timestamp' in df.columns:
            print(f"Date range: {df['@timestamp'].min()} to {df['@timestamp'].max()}")
        
        # Event ID distribution
        if 'data_win_system_eventID' in df.columns:
            print(f"\n🔍 Event ID distribution:")
            event_counts = df['data_win_system_eventID'].value_counts().head(10)
            for event_id, count in event_counts.items():
                event_name = self._get_event_name(event_id)
                print(f"  {event_id} ({event_name}): {count}")
        
        # User analysis
        if 'data_win_eventdata_targetUserName' in df.columns:
            unique_users = df['data_win_eventdata_targetUserName'].nunique()
            print(f"\nUnique target users: {unique_users}")
            
            top_users = df['data_win_eventdata_targetUserName'].value_counts().head(5)
            print(f"Top target users: {top_users.to_dict()}")
        
        # Source IP analysis
        if 'src_ip' in df.columns:
            unique_ips = df['src_ip'].nunique()
            print(f"\nUnique source IPs: {unique_ips}")
            
            top_ips = df['src_ip'].value_counts().head(5)
            print(f"Top source IPs: {top_ips.to_dict()}")
        
        # Geographic analysis
        if 'src_geo_country' in df.columns:
            print(f"\n🌍 Top source countries:")
            countries = df['src_geo_country'].value_counts().head(5)
            print(countries.to_dict())
        
        # Logon type analysis
        if 'data_win_eventdata_logonType' in df.columns:
            print(f"\n🔐 Logon type distribution:")
            logon_types = df['data_win_eventdata_logonType'].value_counts()
            for logon_type, count in logon_types.items():
                logon_name = self._get_logon_type_name(logon_type)
                print(f"  {logon_type} ({logon_name}): {count}")
        
        print(f"\n🔍 First {n} records:")
        print(df.head(n).to_string())
    
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
    """Main function to test data fetching"""
    print("🚀 Starting Windows Event Log Data Fetch...")
    
    fetcher = WindowsDataFetcher()
    
    # Fetch logs from both Windows Event and Authentication indexes
    logs = fetcher.fetch_windows_event_logs(days_back=7, size=20000)
    
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
    csv_path = "ml_results/data/windows_event_data.csv"
    df.to_csv(csv_path, index=False)
    print(f"💾 DataFrame saved to: {csv_path}")

if __name__ == "__main__":
    main()
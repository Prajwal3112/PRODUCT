#!/usr/bin/env python3
"""
Fetch Network Logs from OpenSearch for ML training
Path: Scripts/ml/fetchNetworkData.py
"""

import os
import json
import pandas as pd
from datetime import datetime, timedelta
from opensearchpy import OpenSearch
from dotenv import load_dotenv

# Load environment variables
load_dotenv('../.env')

class NetworkDataFetcher:
    def __init__(self):
        self.opensearch_host = os.getenv('OPENSEARCH_HOST', 'http://192.168.109.128:9200')
        self.client = OpenSearch([self.opensearch_host])
        
    def get_network_indexes(self, days_back=7):
        """Generate Network Log index names for the last N days"""
        indexes = []
        for i in range(days_back):
            date = datetime.now() - timedelta(days=i)
            date_str = date.strftime("%d-%m-%Y")
            indexes.append(f"logs-network-logs-{date_str}")
        return indexes
    
    def check_existing_indexes(self, index_list):
        """Check which indexes actually exist"""
        existing_indexes = []
        
        for index in index_list:
            try:
                self.client.indices.get(index=index)
                existing_indexes.append(index)
                print(f"✅ Network index exists: {index}")
            except:
                print(f"⚠️  Network index not found (skipping): {index}")
        
        return existing_indexes
    
    def fetch_network_logs(self, days_back=7, size=20000):
        """Fetch Network Logs from OpenSearch using scroll API"""
        indexes = self.get_network_indexes(days_back)
        print(f"🔍 Checking Network Log indexes: {indexes}")
        
        # Check existing indexes
        existing_indexes = self.check_existing_indexes(indexes)
        
        if not existing_indexes:
            print("❌ No Network Log indexes found!")
            return []
        
        print(f"📋 Will fetch from {len(existing_indexes)} available indexes")
        
        # Query for Network Logs - comprehensive field extraction for all 8 use cases
        query = {
            "query": {
                "range": {"@timestamp": {"gte": f"now-{days_back}d"}}
            },
            "_source": [
                # Core network fields
                "src_ip", "dest_ip", "dest_port", "proto", "app_proto", "event_type",
                
                # Flow data (Use cases 1, 4)
                "flow.start", "flow.pkts_toserver", "flow.pkts_toclient", 
                "flow.bytes_toserver", "flow.bytes_toclient",
                
                # HTTP fields (Use cases 2, 8)
                "http.http_user_agent", "http.http_method", "http.url", 
                "http.hostname", "http.status",
                
                # Alert fields (Use cases 1, 6)
                "alert.signature", "alert.category", "alert.severity",
                
                # Protocol and direction
                "direction", "app_proto", "proto",
                
                # Timestamps
                "@timestamp", "timestamp", "flow.start", "flow.end",
                
                # Additional context
                "src_port", "flow.state", "flow.reason"
            ],
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        
        all_logs = []
        total_fetched = 0
        
        for index in existing_indexes:
            if total_fetched >= size:
                break
                
            try:
                print(f"📥 Fetching from {index}...")
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
                    print(f"  📦 Batch 1: {len(logs)} logs")
                
                # Continue scrolling
                batch_num = 2
                while len(hits) > 0 and total_fetched + len(index_logs) < size:
                    try:
                        response = self.client.scroll(
                            scroll_id=scroll_id,
                            scroll='5m'
                        )
                        hits = response['hits']['hits']
                        
                        if hits:
                            logs = [hit['_source'] for hit in hits]
                            index_logs.extend(logs)
                            print(f"  📦 Batch {batch_num}: {len(logs)} logs")
                            batch_num += 1
                        
                    except Exception as scroll_error:
                        print(f"  ⚠️  Scroll error: {str(scroll_error)}")
                        break
                
                # Clear scroll
                try:
                    self.client.clear_scroll(scroll_id=scroll_id)
                except:
                    pass
                
                all_logs.extend(index_logs)
                total_fetched += len(index_logs)
                print(f"  ✅ Fetched {len(index_logs)} logs from {index} (Total: {total_fetched})")
                
            except Exception as e:
                print(f"  ⚠️  Error fetching from {index}: {str(e)}")
                continue
        
        # Limit to requested size
        final_logs = all_logs[:size]
        print(f"🎯 Total logs collected: {len(final_logs)}")
        return final_logs
    
    def save_raw_data(self, logs, filename="network_raw_data.json"):
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
        numeric_cols = ['dest_port', 'src_port']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        # Handle flow data
        flow_numeric_cols = ['flow.bytes_toserver', 'flow.bytes_toclient', 
                            'flow.pkts_toserver', 'flow.pkts_toclient']
        for col in flow_numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        # Handle nested fields - flatten if needed
        self._flatten_nested_fields(df)
        
        print(f"📊 DataFrame created with shape: {df.shape}")
        print(f"🔍 Columns: {list(df.columns)}")
        
        return df
    
    def _flatten_nested_fields(self, df):
        """Flatten nested fields like flow.* and http.*"""
        # Handle flow fields
        flow_fields = {
            'flow.bytes_toserver': 'flow_bytes_toserver',
            'flow.bytes_toclient': 'flow_bytes_toclient',
            'flow.pkts_toserver': 'flow_pkts_toserver',
            'flow.pkts_toclient': 'flow_pkts_toclient',
            'flow.start': 'flow_start',
            'flow.end': 'flow_end',
            'flow.state': 'flow_state',
            'flow.reason': 'flow_reason'
        }
        
        for old_name, new_name in flow_fields.items():
            if old_name in df.columns:
                df[new_name] = df[old_name]
                df.drop(columns=[old_name], inplace=True)
        
        # Handle HTTP fields
        http_fields = {
            'http.http_user_agent': 'http_user_agent',
            'http.http_method': 'http_method',
            'http.url': 'http_url',
            'http.hostname': 'http_hostname',
            'http.status': 'http_status'
        }
        
        for old_name, new_name in http_fields.items():
            if old_name in df.columns:
                df[new_name] = df[old_name]
                df.drop(columns=[old_name], inplace=True)
        
        # Handle Alert fields
        alert_fields = {
            'alert.signature': 'alert_signature',
            'alert.category': 'alert_category',
            'alert.severity': 'alert_severity'
        }
        
        for old_name, new_name in alert_fields.items():
            if old_name in df.columns:
                df[new_name] = df[old_name]
                df.drop(columns=[old_name], inplace=True)
    
    def preview_data(self, df, n=5):
        """Preview the fetched data"""
        if df.empty:
            print("❌ No data to preview")
            return
        
        print("\n" + "="*80)
        print("📋 NETWORK LOG DATA PREVIEW")
        print("="*80)
        print(f"Total records: {len(df)}")
        
        if '@timestamp' in df.columns:
            print(f"Date range: {df['@timestamp'].min()} to {df['@timestamp'].max()}")
        
        # Protocol distribution
        if 'app_proto' in df.columns:
            print(f"\n🔍 Application Protocol distribution:")
            proto_counts = df['app_proto'].value_counts().head(10)
            for proto, count in proto_counts.items():
                print(f"  {proto}: {count}")
        
        # Event type distribution
        if 'event_type' in df.columns:
            print(f"\n📊 Event Type distribution:")
            event_counts = df['event_type'].value_counts().head(10)
            for event_type, count in event_counts.items():
                print(f"  {event_type}: {count}")
        
        # Source IP analysis
        if 'src_ip' in df.columns:
            unique_src_ips = df['src_ip'].nunique()
            print(f"\nUnique source IPs: {unique_src_ips}")
            
            top_src_ips = df['src_ip'].value_counts().head(5)
            print(f"Top source IPs: {top_src_ips.to_dict()}")
        
        # Destination analysis
        if 'dest_ip' in df.columns:
            unique_dest_ips = df['dest_ip'].nunique()
            print(f"Unique destination IPs: {unique_dest_ips}")
            
            top_dest_ips = df['dest_ip'].value_counts().head(5)
            print(f"Top destination IPs: {top_dest_ips.to_dict()}")
        
        # Port analysis
        if 'dest_port' in df.columns:
            print(f"\n🚪 Top destination ports:")
            top_ports = df['dest_port'].value_counts().head(10)
            for port, count in top_ports.items():
                port_name = self._get_port_name(port)
                print(f"  {port} ({port_name}): {count}")
        
        # Flow data analysis
        if 'flow_bytes_toserver' in df.columns:
            total_bytes_sent = df['flow_bytes_toserver'].sum()
            print(f"\n📊 Total bytes sent to servers: {total_bytes_sent:,}")
            
            avg_bytes_per_flow = df['flow_bytes_toserver'].mean()
            print(f"Average bytes per flow: {avg_bytes_per_flow:.1f}")
        
        # HTTP analysis
        if 'http_user_agent' in df.columns:
            print(f"\n🌐 Top User Agents:")
            user_agents = df['http_user_agent'].value_counts().head(5)
            for ua, count in user_agents.items():
                # Truncate long user agents
                ua_short = ua[:50] + "..." if len(ua) > 50 else ua
                print(f"  {ua_short}: {count}")
        
        # Alert analysis
        if 'alert_signature' in df.columns:
            print(f"\n🚨 Top Alert Signatures:")
            alerts = df['alert_signature'].value_counts().head(5)
            for alert, count in alerts.items():
                alert_short = alert[:60] + "..." if len(alert) > 60 else alert
                print(f"  {alert_short}: {count}")
        
        print(f"\n🔍 First {n} records:")
        print(df.head(n).to_string())
    
    def _get_port_name(self, port):
        """Get human-readable port name"""
        port_names = {
            80: "HTTP",
            443: "HTTPS",
            53: "DNS",
            22: "SSH",
            23: "Telnet",
            21: "FTP",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP",
            445: "SMB",
            139: "NetBIOS",
            135: "RPC",
            1433: "SQL Server",
            3306: "MySQL",
            5432: "PostgreSQL"
        }
        return port_names.get(int(port), "Unknown")

def main():
    """Main function to test data fetching"""
    print("🚀 Starting Network Log Data Fetch...")
    
    fetcher = NetworkDataFetcher()
    
    # Fetch logs from Network indexes
    logs = fetcher.fetch_network_logs(days_back=7, size=20000)
    
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
    csv_path = "ml_results/data/network_data.csv"
    df.to_csv(csv_path, index=False)
    print(f"💾 DataFrame saved to: {csv_path}")

if __name__ == "__main__":
    main()
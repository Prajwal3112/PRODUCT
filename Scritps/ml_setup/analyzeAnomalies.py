#!/usr/bin/env python3
"""
Firewall Anomaly Analysis Dashboard
Path: Scripts/ml/analyzeAnomalies.py

Analyzes and visualizes ML detection results
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import numpy as np
from collections import Counter
import os

class AnomalyAnalyzer:
    def __init__(self, results_file_path):
        self.results_file = results_file_path
        self.df = None
        self.anomalies = None
        self.load_data()
        
    def load_data(self):
        """Load anomaly detection results"""
        print(f"📁 Loading results from: {self.results_file}")
        
        with open(self.results_file, 'r') as f:
            data = json.load(f)
        
        self.df = pd.DataFrame(data)
        self.anomalies = self.df[self.df['is_anomaly'] == True]
        
        print(f"✅ Loaded {len(self.df)} total logs")
        print(f"🚨 Found {len(self.anomalies)} anomalies ({len(self.anomalies)/len(self.df)*100:.2f}%)")
        
    def generate_summary_report(self):
        """Generate comprehensive analysis report"""
        print("\n" + "="*80)
        print("🔍 FIREWALL ANOMALY ANALYSIS REPORT")
        print("="*80)
        
        # Basic Statistics
        print(f"\n📊 BASIC STATISTICS:")
        print(f"Total Logs Analyzed: {len(self.df):,}")
        print(f"Anomalies Detected: {len(self.anomalies):,}")
        print(f"Anomaly Rate: {len(self.anomalies)/len(self.df)*100:.2f}%")
        
        # Model Performance
        print(f"\n🤖 MODEL PERFORMANCE:")
        models = ['isolation_forest', 'one_class_svm', 'gaussian_mixture']
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
            self.analyze_anomaly_patterns()
        else:
            print("\n⚠️  No anomalies detected to analyze patterns")
    
    def analyze_anomaly_patterns(self):
        """Analyze patterns in detected anomalies"""
        print(f"\n🚨 ANOMALY PATTERN ANALYSIS:")
        
        # Time-based patterns
        print(f"\n⏰ TEMPORAL PATTERNS:")
        hour_counts = self.anomalies['hour'].value_counts().sort_index()
        print(f"Peak anomaly hours: {hour_counts.head(3).to_dict()}")
        
        weekend_anomalies = self.anomalies['is_weekend'].sum()
        print(f"Weekend anomalies: {weekend_anomalies} ({weekend_anomalies/len(self.anomalies)*100:.1f}%)")
        
        night_anomalies = self.anomalies['is_night'].sum()
        print(f"Night-time anomalies: {night_anomalies} ({night_anomalies/len(self.anomalies)*100:.1f}%)")
        
        # Network patterns
        print(f"\n🌐 NETWORK PATTERNS:")
        internal_src = self.anomalies['src_ip_internal'].sum()
        internal_dest = self.anomalies['dest_ip_internal'].sum()
        print(f"Internal source IPs: {internal_src} ({internal_src/len(self.anomalies)*100:.1f}%)")
        print(f"Internal destination IPs: {internal_dest} ({internal_dest/len(self.anomalies)*100:.1f}%)")
        
        # Top anomalous IPs
        top_src_ips = self.anomalies['src_ip'].value_counts().head(5)
        print(f"\n🎯 TOP ANOMALOUS SOURCE IPs:")
        for ip, count in top_src_ips.items():
            print(f"  {ip}: {count} anomalies")
        
        top_dest_ips = self.anomalies['dest_ip'].value_counts().head(5)
        print(f"\n🎯 TOP ANOMALOUS DESTINATION IPs:")
        for ip, count in top_dest_ips.items():
            print(f"  {ip}: {count} anomalies")
        
        # Application patterns
        print(f"\n📱 APPLICATION PATTERNS:")
        top_apps = self.anomalies['data_app'].value_counts().head(5)
        for app, count in top_apps.items():
            print(f"  {app}: {count} anomalies")
        
        # Geographic patterns
        print(f"\n🌍 GEOGRAPHIC PATTERNS:")
        src_countries = self.anomalies['src_geo_country'].value_counts().head(5)
        dest_countries = self.anomalies['dest_geo_country'].value_counts().head(5)
        
        print(f"Top source countries:")
        for country, count in src_countries.items():
            print(f"  {country}: {count}")
        
        print(f"Top destination countries:")
        for country, count in dest_countries.items():
            print(f"  {country}: {count}")
        
        # Lateral movement analysis
        self.analyze_lateral_movement()
        
        # Risk analysis
        self.analyze_risk_patterns()
    
    def analyze_lateral_movement(self):
        """Analyze lateral movement patterns"""
        print(f"\n🔄 LATERAL MOVEMENT ANALYSIS:")
        
        lateral_anomalies = self.anomalies[self.anomalies['unique_dest_ips_per_hour'] > 1]
        print(f"Potential lateral movement: {len(lateral_anomalies)} anomalies")
        
        if len(lateral_anomalies) > 0:
            max_connections = lateral_anomalies['unique_dest_ips_per_hour'].max()
            avg_connections = lateral_anomalies['unique_dest_ips_per_hour'].mean()
            print(f"Max destinations per hour: {max_connections}")
            print(f"Average destinations per hour: {avg_connections:.2f}")
            
            # RDP-related lateral movement
            rdp_lateral = lateral_anomalies[lateral_anomalies['is_rdp_related'] == True]
            print(f"RDP-related lateral movement: {len(rdp_lateral)} anomalies")
            
            # Show top lateral movement sources
            lateral_sources = lateral_anomalies.groupby('src_ip').agg({
                'unique_dest_ips_per_hour': 'max',
                'dest_ip': 'nunique'
            }).sort_values('unique_dest_ips_per_hour', ascending=False).head(5)
            
            print(f"\nTop lateral movement sources:")
            for ip, row in lateral_sources.iterrows():
                print(f"  {ip}: {row['unique_dest_ips_per_hour']} dest/hour, {row['dest_ip']} total destinations")
    
    def analyze_risk_patterns(self):
        """Analyze risk-based patterns"""
        print(f"\n⚠️  RISK ANALYSIS:")
        
        risk_dist = self.anomalies['data_apprisk'].value_counts()
        print(f"Risk level distribution:")
        for risk, count in risk_dist.items():
            print(f"  {risk}: {count} ({count/len(self.anomalies)*100:.1f}%)")
        
        high_risk = self.anomalies[self.anomalies['data_apprisk_numeric'] >= 3]
        print(f"\nHigh/Critical risk anomalies: {len(high_risk)}")
        
        avg_risk = self.anomalies['avg_app_risk'].mean()
        print(f"Average application risk score: {avg_risk:.3f}")
    
    def create_visualizations(self):
        """Create visualization plots"""
        print("\n📊 Creating visualizations...")
        
        # Set up the plotting style
        plt.style.use('default')
        sns.set_palette("husl")
        
        # Create output directory
        viz_dir = "ml_results/visualizations"
        os.makedirs(viz_dir, exist_ok=True)
        
        # 1. Model Performance Comparison
        plt.figure(figsize=(12, 8))
        
        # Model agreement distribution
        plt.subplot(2, 2, 1)
        ensemble_dist = self.df['ensemble_anomaly_score'].value_counts().sort_index()
        plt.bar(ensemble_dist.index, ensemble_dist.values)
        plt.title('Model Agreement Distribution')
        plt.xlabel('Number of Models Agreeing')
        plt.ylabel('Number of Logs')
        
        # Individual model performance
        plt.subplot(2, 2, 2)
        models = ['isolation_forest_anomaly', 'one_class_svm_anomaly', 'gaussian_mixture_anomaly']
        model_counts = [self.df[model].sum() for model in models if model in self.df.columns]
        model_names = [name.replace('_anomaly', '').replace('_', ' ').title() for name in models if f'{name}' in self.df.columns]
        
        plt.bar(model_names, model_counts)
        plt.title('Individual Model Detection Counts')
        plt.ylabel('Anomalies Detected')
        plt.xticks(rotation=45)
        
        if len(self.anomalies) > 0:
            # Hourly distribution of anomalies
            plt.subplot(2, 2, 3)
            hourly_dist = self.anomalies['hour'].value_counts().sort_index()
            plt.plot(hourly_dist.index, hourly_dist.values, marker='o')
            plt.title('Anomalies by Hour of Day')
            plt.xlabel('Hour')
            plt.ylabel('Number of Anomalies')
            plt.grid(True, alpha=0.3)
            
            # Risk level distribution
            plt.subplot(2, 2, 4)
            risk_dist = self.anomalies['data_apprisk'].value_counts()
            plt.pie(risk_dist.values, labels=risk_dist.index, autopct='%1.1f%%')
            plt.title('Anomalies by Risk Level')
        
        plt.tight_layout()
        plt.savefig(f'{viz_dir}/anomaly_overview.png', dpi=300, bbox_inches='tight')
        print(f"✅ Saved overview plot: {viz_dir}/anomaly_overview.png")
        
        # 2. Network Analysis
        if len(self.anomalies) > 0:
            plt.figure(figsize=(14, 6))
            
            # Top source IPs
            plt.subplot(1, 2, 1)
            top_src = self.anomalies['src_ip'].value_counts().head(10)
            plt.barh(range(len(top_src)), top_src.values)
            plt.yticks(range(len(top_src)), top_src.index)
            plt.title('Top 10 Anomalous Source IPs')
            plt.xlabel('Number of Anomalies')
            
            # Top destination IPs
            plt.subplot(1, 2, 2)
            top_dest = self.anomalies['dest_ip'].value_counts().head(10)
            plt.barh(range(len(top_dest)), top_dest.values)
            plt.yticks(range(len(top_dest)), top_dest.index)
            plt.title('Top 10 Anomalous Destination IPs')
            plt.xlabel('Number of Anomalies')
            
            plt.tight_layout()
            plt.savefig(f'{viz_dir}/network_analysis.png', dpi=300, bbox_inches='tight')
            print(f"✅ Saved network analysis: {viz_dir}/network_analysis.png")
        
        plt.show()
    
    def export_detailed_report(self):
        """Export detailed anomaly report"""
        report_dir = "ml_results/reports"
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{report_dir}/detailed_analysis_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write("FIREWALL ANOMALY DETECTION - DETAILED ANALYSIS REPORT\n")
            f.write("="*60 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Summary statistics
            f.write(f"SUMMARY:\n")
            f.write(f"Total Logs: {len(self.df):,}\n")
            f.write(f"Anomalies: {len(self.anomalies):,} ({len(self.anomalies)/len(self.df)*100:.2f}%)\n\n")
            
            if len(self.anomalies) > 0:
                # Top anomalous connections
                f.write("TOP ANOMALOUS CONNECTIONS:\n")
                f.write("-" * 40 + "\n")
                
                top_connections = self.anomalies.groupby(['src_ip', 'dest_ip']).size().sort_values(ascending=False).head(20)
                for (src, dest), count in top_connections.items():
                    f.write(f"{src} -> {dest}: {count} anomalies\n")
                
                f.write("\n")
                
                # Detailed anomaly samples
                f.write("SAMPLE ANOMALOUS EVENTS:\n")
                f.write("-" * 40 + "\n")
                
                sample_anomalies = self.anomalies.head(10)
                for idx, row in sample_anomalies.iterrows():
                    f.write(f"\nAnomaly {idx}:\n")
                    f.write(f"  Time: {row['@timestamp']}\n")
                    f.write(f"  Source: {row['src_ip']}:{row['src_port']}\n")
                    f.write(f"  Destination: {row['dest_ip']}:{row['dest_port']}\n")
                    f.write(f"  Application: {row['data_app']}\n")
                    f.write(f"  Action: {row['action']}\n")
                    f.write(f"  Risk Level: {row['data_apprisk']}\n")
                    f.write(f"  Ensemble Score: {row['ensemble_anomaly_score']}\n")
                    f.write(f"  Lateral Movement Indicators: {row['unique_dest_ips_per_hour']} dest/hour\n")
        
        print(f"✅ Detailed report saved: {report_file}")

def main():
    """Main analysis function"""
    print("🔍 Starting Firewall Anomaly Analysis...")
    
    # Find the latest results file
    results_dir = "ml_results/results"
    
    if not os.path.exists(results_dir):
        print("❌ Results directory not found. Run mlFirewallDetector.py first.")
        return
    
    # Get the latest firewall anomalies file
    anomaly_files = [f for f in os.listdir(results_dir) if f.startswith('firewall_anomalies_')]
    
    if not anomaly_files:
        print("❌ No anomaly results files found.")
        return
    
    # Use the latest file
    latest_file = sorted(anomaly_files)[-1]
    results_path = os.path.join(results_dir, latest_file)
    
    print(f"📁 Using results file: {latest_file}")
    
    # Initialize analyzer
    analyzer = AnomalyAnalyzer(results_path)
    
    # Generate comprehensive analysis
    analyzer.generate_summary_report()
    
    # Create visualizations
    analyzer.create_visualizations()
    
    # Export detailed report
    analyzer.export_detailed_report()
    
    print("\n✅ Analysis complete!")
    print("📊 Check ml_results/visualizations/ for plots")
    print("📄 Check ml_results/reports/ for detailed reports")

if __name__ == "__main__":
    main()
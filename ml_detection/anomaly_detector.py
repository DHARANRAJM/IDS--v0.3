#!/usr/bin/env python3
"""
Network-Based Intrusion Detection System (IDS) - ML Anomaly Detector
Optional Python-based anomaly detection using unsupervised learning
Author: [Your Name]
Date: 2024
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import seaborn as sns

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ml_detection/anomaly_detector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class IDSAnomalyDetector:
    """ML-based anomaly detector for IDS logs"""
    
    def __init__(self, config_file=None):
        self.config = self._load_config(config_file)
        self.models = {}
        self.scaler = StandardScaler()
        self.feature_columns = [
            'hour', 'day_of_week', 'source_ip_count', 'dest_port_count',
            'event_type_count', 'connection_rate', 'alert_frequency'
        ]
        
    def _load_config(self, config_file):
        """Load configuration from file"""
        default_config = {
            'log_file': '../logs/alert-log.txt',
            'analysis_window': 24,  # hours
            'min_events': 10,
            'anomaly_threshold': 0.95,
            'clustering_method': 'isolation_forest',
            'n_clusters': 3,
            'output_dir': 'ml_detection/results'
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Could not load config file: {e}")
        
        return default_config
    
    def parse_log_entry(self, line):
        """Parse a single log entry"""
        try:
            # Expected format: timestamp|event_type|source_ip|details
            parts = line.strip().split('|')
            if len(parts) >= 4:
                timestamp_str = parts[0]
                event_type = parts[1]
                source_ip = parts[2]
                details = parts[3]
                
                # Parse timestamp
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                
                return {
                    'timestamp': timestamp,
                    'event_type': event_type,
                    'source_ip': source_ip,
                    'details': details,
                    'hour': timestamp.hour,
                    'day_of_week': timestamp.weekday()
                }
        except Exception as e:
            logger.debug(f"Could not parse log entry: {line.strip()} - {e}")
        
        return None
    
    def load_log_data(self, log_file=None):
        """Load and parse IDS log data"""
        log_file = log_file or self.config['log_file']
        
        if not os.path.exists(log_file):
            logger.error(f"Log file not found: {log_file}")
            return []
        
        events = []
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    event = self.parse_log_entry(line)
                    if event:
                        events.append(event)
        except Exception as e:
            logger.error(f"Error reading log file: {e}")
        
        logger.info(f"Loaded {len(events)} events from {log_file}")
        return events
    
    def extract_features(self, events):
        """Extract features from events for ML analysis"""
        if not events:
            return pd.DataFrame()
        
        # Group events by time windows (hourly)
        hourly_data = defaultdict(lambda: {
            'events': [],
            'source_ips': set(),
            'dest_ports': set(),
            'event_types': set()
        })
        
        for event in events:
            # Round to hour
            hour_key = event['timestamp'].replace(minute=0, second=0, microsecond=0)
            hourly_data[hour_key]['events'].append(event)
            hourly_data[hour_key]['source_ips'].add(event['source_ip'])
            hourly_data[hour_key]['event_types'].add(event['event_type'])
            
            # Extract destination port if available
            if 'port' in event['details'].lower():
                try:
                    port = int(event['details'].split()[-1])
                    hourly_data[hour_key]['dest_ports'].add(port)
                except:
                    pass
        
        # Create feature matrix
        features = []
        for hour, data in hourly_data.items():
            if len(data['events']) < 2:  # Skip hours with too few events
                continue
                
            # Calculate connection rate (events per minute)
            connection_rate = len(data['events']) / 60
            
            # Calculate alert frequency
            alert_frequency = len([e for e in data['events'] if 'ALERT' in e['event_type']])
            
            feature_vector = [
                hour.hour,
                hour.weekday(),
                len(data['source_ips']),
                len(data['dest_ports']),
                len(data['event_types']),
                connection_rate,
                alert_frequency
            ]
            
            features.append(feature_vector)
        
        if not features:
            logger.warning("No features extracted from events")
            return pd.DataFrame()
        
        df = pd.DataFrame(features, columns=self.feature_columns)
        logger.info(f"Extracted features for {len(df)} time windows")
        return df
    
    def train_isolation_forest(self, features):
        """Train Isolation Forest for anomaly detection"""
        try:
            # Scale features
            scaled_features = self.scaler.fit_transform(features)
            
            # Train Isolation Forest
            iso_forest = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            # Fit the model
            iso_forest.fit(scaled_features)
            
            # Predict anomalies
            predictions = iso_forest.predict(scaled_features)
            scores = iso_forest.decision_function(scaled_features)
            
            self.models['isolation_forest'] = {
                'model': iso_forest,
                'scaler': self.scaler,
                'predictions': predictions,
                'scores': scores
            }
            
            logger.info("Isolation Forest trained successfully")
            return predictions, scores
            
        except Exception as e:
            logger.error(f"Error training Isolation Forest: {e}")
            return None, None
    
    def train_kmeans_clustering(self, features):
        """Train K-Means clustering for pattern detection"""
        try:
            # Scale features
            scaled_features = self.scaler.fit_transform(features)
            
            # Train K-Means
            kmeans = KMeans(
                n_clusters=self.config['n_clusters'],
                random_state=42
            )
            
            # Fit the model
            kmeans.fit(scaled_features)
            
            # Get cluster assignments
            cluster_labels = kmeans.labels_
            
            self.models['kmeans'] = {
                'model': kmeans,
                'scaler': self.scaler,
                'labels': cluster_labels
            }
            
            logger.info("K-Means clustering trained successfully")
            return cluster_labels
            
        except Exception as e:
            logger.error(f"Error training K-Means: {e}")
            return None
    
    def train_dbscan_clustering(self, features):
        """Train DBSCAN clustering for density-based anomaly detection"""
        try:
            # Scale features
            scaled_features = self.scaler.fit_transform(features)
            
            # Train DBSCAN
            dbscan = DBSCAN(eps=0.5, min_samples=2)
            
            # Fit the model
            dbscan.fit(scaled_features)
            
            # Get cluster assignments
            cluster_labels = dbscan.labels_
            
            self.models['dbscan'] = {
                'model': dbscan,
                'scaler': self.scaler,
                'labels': cluster_labels
            }
            
            logger.info("DBSCAN clustering trained successfully")
            return cluster_labels
            
        except Exception as e:
            logger.error(f"Error training DBSCAN: {e}")
            return None
    
    def detect_anomalies(self, features):
        """Detect anomalies using trained models"""
        anomalies = []
        
        if 'isolation_forest' in self.models:
            model_data = self.models['isolation_forest']
            predictions = model_data['predictions']
            scores = model_data['scores']
            
            # Find anomalies (predictions == -1)
            anomaly_indices = np.where(predictions == -1)[0]
            
            for idx in anomaly_indices:
                anomaly_score = scores[idx]
                if anomaly_score < -0.5:  # Threshold for anomaly
                    anomalies.append({
                        'index': idx,
                        'method': 'isolation_forest',
                        'score': anomaly_score,
                        'features': features.iloc[idx].to_dict()
                    })
        
        if 'dbscan' in self.models:
            model_data = self.models['dbscan']
            labels = model_data['labels']
            
            # Find noise points (label == -1)
            noise_indices = np.where(labels == -1)[0]
            
            for idx in noise_indices:
                anomalies.append({
                    'index': idx,
                    'method': 'dbscan',
                    'score': -1.0,
                    'features': features.iloc[idx].to_dict()
                })
        
        logger.info(f"Detected {len(anomalies)} anomalies")
        return anomalies
    
    def analyze_patterns(self, events, features):
        """Analyze patterns in the data"""
        patterns = {}
        
        # Time-based patterns
        hourly_counts = Counter(event['hour'] for event in events)
        patterns['peak_hours'] = hourly_counts.most_common(3)
        
        # Event type patterns
        event_type_counts = Counter(event['event_type'] for event in events)
        patterns['common_events'] = event_type_counts.most_common(5)
        
        # Source IP patterns
        source_ip_counts = Counter(event['source_ip'] for event in events)
        patterns['top_sources'] = source_ip_counts.most_common(5)
        
        # Feature correlation analysis
        if not features.empty:
            correlation_matrix = features.corr()
            patterns['correlations'] = correlation_matrix.to_dict()
        
        return patterns
    
    def generate_report(self, events, features, anomalies, patterns):
        """Generate analysis report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_events': len(events),
                'time_windows': len(features),
                'anomalies_detected': len(anomalies),
                'analysis_period': f"{events[0]['timestamp']} to {events[-1]['timestamp']}" if events else "N/A"
            },
            'anomalies': [
                {
                    'index': a['index'],
                    'method': a['method'],
                    'score': float(a['score']),
                    'features': a['features']
                }
                for a in anomalies
            ],
            'patterns': patterns,
            'recommendations': self._generate_recommendations(anomalies, patterns)
        }
        
        return report
    
    def _generate_recommendations(self, anomalies, patterns):
        """Generate recommendations based on analysis"""
        recommendations = []
        
        if anomalies:
            recommendations.append({
                'type': 'anomaly_detection',
                'message': f"Detected {len(anomalies)} anomalous time windows",
                'priority': 'high'
            })
        
        # Check for high event frequency
        if patterns.get('common_events'):
            most_common = patterns['common_events'][0]
            if most_common[1] > 100:
                recommendations.append({
                    'type': 'event_frequency',
                    'message': f"High frequency of {most_common[0]} events ({most_common[1]} occurrences)",
                    'priority': 'medium'
                })
        
        # Check for suspicious source IPs
        if patterns.get('top_sources'):
            top_source = patterns['top_sources'][0]
            if top_source[1] > 50:
                recommendations.append({
                    'type': 'source_analysis',
                    'message': f"Suspicious activity from {top_source[0]} ({top_source[1]} events)",
                    'priority': 'medium'
                })
        
        return recommendations
    
    def save_results(self, report, output_dir=None):
        """Save analysis results"""
        output_dir = output_dir or self.config['output_dir']
        os.makedirs(output_dir, exist_ok=True)
        
        # Save report as JSON
        report_file = os.path.join(output_dir, f"anomaly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Save visualizations
        self._create_visualizations(output_dir)
        
        logger.info(f"Results saved to {output_dir}")
        return report_file
    
    def _create_visualizations(self, output_dir):
        """Create visualization plots"""
        try:
            # Feature distribution plots
            if hasattr(self, 'features_df') and not self.features_df.empty:
                plt.figure(figsize=(15, 10))
                
                for i, col in enumerate(self.feature_columns, 1):
                    plt.subplot(2, 4, i)
                    plt.hist(self.features_df[col], bins=20, alpha=0.7)
                    plt.title(f'{col} Distribution')
                    plt.xlabel(col)
                    plt.ylabel('Frequency')
                
                plt.tight_layout()
                plt.savefig(os.path.join(output_dir, 'feature_distributions.png'))
                plt.close()
                
                # Correlation heatmap
                plt.figure(figsize=(10, 8))
                correlation_matrix = self.features_df.corr()
                sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0)
                plt.title('Feature Correlation Matrix')
                plt.tight_layout()
                plt.savefig(os.path.join(output_dir, 'correlation_heatmap.png'))
                plt.close()
                
        except Exception as e:
            logger.warning(f"Could not create visualizations: {e}")
    
    def run_analysis(self, log_file=None):
        """Run complete anomaly analysis"""
        logger.info("Starting IDS anomaly analysis...")
        
        # Load data
        events = self.load_log_data(log_file)
        if not events:
            logger.error("No events found for analysis")
            return None
        
        # Extract features
        features = self.extract_features(events)
        if features.empty:
            logger.error("No features extracted")
            return None
        
        self.features_df = features
        
        # Train models
        if self.config['clustering_method'] == 'isolation_forest':
            self.train_isolation_forest(features)
        elif self.config['clustering_method'] == 'kmeans':
            self.train_kmeans_clustering(features)
        elif self.config['clustering_method'] == 'dbscan':
            self.train_dbscan_clustering(features)
        
        # Detect anomalies
        anomalies = self.detect_anomalies(features)
        
        # Analyze patterns
        patterns = self.analyze_patterns(events, features)
        
        # Generate report
        report = self.generate_report(events, features, anomalies, patterns)
        
        # Save results
        report_file = self.save_results(report)
        
        logger.info(f"Analysis completed. Report saved to: {report_file}")
        return report

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='IDS Anomaly Detector')
    parser.add_argument('--log-file', help='Path to IDS log file')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--output-dir', help='Output directory for results')
    parser.add_argument('--method', choices=['isolation_forest', 'kmeans', 'dbscan'], 
                       default='isolation_forest', help='Clustering method')
    
    args = parser.parse_args()
    
    # Create detector
    detector = IDSAnomalyDetector(args.config)
    
    # Update config with command line arguments
    if args.log_file:
        detector.config['log_file'] = args.log_file
    if args.output_dir:
        detector.config['output_dir'] = args.output_dir
    if args.method:
        detector.config['clustering_method'] = args.method
    
    # Run analysis
    report = detector.run_analysis()
    
    if report:
        print(f"\nAnalysis completed successfully!")
        print(f"Report saved to: {report}")
        
        # Print summary
        if 'summary' in report:
            summary = report['summary']
            print(f"\nSummary:")
            print(f"  Total events: {summary['total_events']}")
            print(f"  Time windows: {summary['time_windows']}")
            print(f"  Anomalies detected: {summary['anomalies_detected']}")
            print(f"  Analysis period: {summary['analysis_period']}")
        
        # Print recommendations
        if 'recommendations' in report:
            print(f"\nRecommendations:")
            for rec in report['recommendations']:
                print(f"  [{rec['priority'].upper()}] {rec['message']}")
    else:
        print("Analysis failed. Check logs for details.")

if __name__ == "__main__":
    main()

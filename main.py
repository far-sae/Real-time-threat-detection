#!/usr/bin/env python3
"""
Main application entry point for the Real-Time Threat Detection System.
"""
import sys
import time
import threading
from loguru import logger

from config import Config
from data_collection import UnifiedCollector
from preprocessing import LogPreprocessor
from ml_detection import ThreatDetector, TrainingDataGenerator
from alerts import AlertManager
from dashboard import ThreatDashboard


class ThreatDetectionSystem:
    """Main threat detection system orchestrator"""
    
    def __init__(self):
        """Initialize all system components"""
        logger.info("Initializing Threat Detection System...")
        
        # Initialize components
        self.collector = UnifiedCollector()
        self.preprocessor = LogPreprocessor()
        self.detector = ThreatDetector()
        self.alert_manager = AlertManager()
        
        # Initialize dashboard
        self.dashboard = ThreatDashboard(self.alert_manager, self.preprocessor)
        
        self.running = False
        self.events_processed = 0
        
        logger.info("System initialized successfully")
    
    def train_initial_model(self):
        """Train initial ML model with synthetic data"""
        logger.info("Training initial ML model...")
        
        try:
            # Generate training data
            generator = TrainingDataGenerator()
            X, y = generator.generate_training_data(num_normal=2000, num_suspicious=1000)
            
            # Train model
            metrics = self.detector.train(X, y)
            
            logger.info(f"Model training complete - Accuracy: {metrics.get('accuracy', 0):.4f}")
            logger.info(f"Classification Report: {metrics.get('classification_report', {})}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return False
    
    def start_collection(self):
        """Start data collection from cloud sources"""
        logger.info("Starting data collection...")
        self.running = True
        
        # Start collectors
        collection_threads = self.collector.start_collection()
        
        # Start processing thread
        processing_thread = threading.Thread(target=self._process_events, daemon=True)
        processing_thread.start()
        
        logger.info("Data collection started")
        return collection_threads + [processing_thread]
    
    def _process_events(self):
        """Process collected events in real-time"""
        logger.info("Event processing thread started")
        
        while self.running:
            try:
                # Get events from collector
                events = self.collector.get_events(max_events=100)
                
                if events:
                    logger.info(f"Processing {len(events)} events...")
                    
                    # Normalize and preprocess
                    feature_array, normalized_df = self.preprocessor.process_batch(events)
                    
                    if len(feature_array) > 0:
                        # Detect threats
                        threat_results = self.detector.detect_threats(feature_array)
                        
                        # Generate alerts for threats
                        alerts = self.alert_manager.generate_batch_alerts(events, threat_results)
                        
                        self.events_processed += len(events)
                        
                        if alerts:
                            logger.warning(f"Generated {len(alerts)} alerts from {len(events)} events")
                        else:
                            logger.info(f"No threats detected in {len(events)} events")
                
                # Sleep before next batch
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error processing events: {e}")
                time.sleep(10)
    
    def stop_collection(self):
        """Stop data collection"""
        logger.info("Stopping data collection...")
        self.running = False
        self.collector.stop_collection()
        logger.info("Data collection stopped")
    
    def run_batch_analysis(self, minutes: int = 5):
        """
        Run one-time batch analysis on recent data
        
        Args:
            minutes: Number of minutes of data to analyze
        """
        logger.info(f"Running batch analysis on last {minutes} minutes of data...")
        
        try:
            # Collect batch of events
            events = self.collector.collect_batch(minutes=minutes)
            
            if not events:
                logger.warning("No events collected for analysis")
                return
            
            logger.info(f"Analyzing {len(events)} events...")
            
            # Process events
            feature_array, normalized_df = self.preprocessor.process_batch(events)
            
            if len(feature_array) == 0:
                logger.warning("No valid features extracted")
                return
            
            # Detect threats
            threat_results = self.detector.detect_threats(feature_array)
            
            # Generate alerts
            alerts = self.alert_manager.generate_batch_alerts(events, threat_results)
            
            # Print summary
            logger.info("="*60)
            logger.info("BATCH ANALYSIS SUMMARY")
            logger.info("="*60)
            logger.info(f"Total Events: {len(events)}")
            logger.info(f"Threats Detected: {sum(1 for r in threat_results if r['is_threat'])}")
            logger.info(f"Alerts Generated: {len(alerts)}")
            
            stats = self.alert_manager.get_alert_statistics()
            logger.info(f"Alert Breakdown: {stats.get('by_severity', {})}")
            logger.info("="*60)
            
        except Exception as e:
            logger.error(f"Error during batch analysis: {e}")
    
    def start_dashboard(self, port: int = 8050):
        """Start the web dashboard"""
        logger.info(f"Starting dashboard on port {port}...")
        self.dashboard.run(port=port, debug=Config.DEBUG)
    
    def get_status(self):
        """Get system status"""
        return {
            'running': self.running,
            'events_processed': self.events_processed,
            'queue_size': self.collector.get_queue_size(),
            'model_trained': self.detector.is_trained,
            'alert_stats': self.alert_manager.get_alert_statistics()
        }


def main():
    """Main entry point"""
    # Configure logger
    logger.remove()
    logger.add(
        sys.stdout,
        colorize=True,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>"
    )
    logger.add("logs/threat_detection_{time}.log", rotation="1 day", retention="7 days")
    
    # Create system
    system = ThreatDetectionSystem()
    
    # Check if model exists, if not train initial model
    if not system.detector.is_trained:
        logger.info("No trained model found, training initial model...")
        if not system.train_initial_model():
            logger.error("Failed to train initial model")
            return
    
    # Start system
    try:
        logger.info("="*60)
        logger.info("REAL-TIME THREAT DETECTION SYSTEM")
        logger.info("="*60)
        logger.info("Press Ctrl+C to stop")
        logger.info("="*60)
        
        # Start data collection
        collection_threads = system.start_collection()
        
        # Start dashboard in main thread
        system.start_dashboard(port=Config.FLASK_PORT)
        
    except KeyboardInterrupt:
        logger.info("\nShutdown requested...")
        system.stop_collection()
        logger.info("System stopped")
    except Exception as e:
        logger.error(f"System error: {e}")
        system.stop_collection()


if __name__ == "__main__":
    main()

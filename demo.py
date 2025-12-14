#!/usr/bin/env python3
"""
Demo script to demonstrate the system with simulated security events.
"""
import time
import random
from datetime import datetime
from loguru import logger

from preprocessing import LogPreprocessor
from ml_detection import ThreatDetector, TrainingDataGenerator
from alerts import AlertManager


def generate_demo_event(is_threat: bool = False) -> dict:
    """Generate a demo security event"""
    event = {
        'timestamp': datetime.utcnow().isoformat(),
        'source': random.choice(['aws', 'azure']),
        'event_id': f"EVT-{random.randint(1000, 9999)}",
        'log_stream': 'demo-stream',
    }
    
    if is_threat:
        # Suspicious event
        event['message'] = {
            'ip_address': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            'user_agent': 'sqlmap/1.0',
            'activity': 'Failed Login Attempt',
            'raw_message': "SELECT * FROM users WHERE id=1' OR '1'='1"
        }
        event['activity'] = 'Suspicious Activity'
        event['ip_address'] = event['message']['ip_address']
    else:
        # Normal event
        event['message'] = {
            'ip_address': f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'activity': 'Successful Login',
            'raw_message': "User logged in successfully"
        }
        event['activity'] = 'Normal Activity'
        event['ip_address'] = event['message']['ip_address']
    
    return event


def run_demo():
    """Run system demonstration"""
    logger.info("="*60)
    logger.info("THREAT DETECTION SYSTEM DEMO")
    logger.info("="*60)
    
    # Initialize components
    logger.info("Initializing components...")
    preprocessor = LogPreprocessor()
    detector = ThreatDetector()
    alert_manager = AlertManager()
    
    # Train model if needed
    if not detector.is_trained:
        logger.info("Training model with synthetic data...")
        generator = TrainingDataGenerator()
        X, y = generator.generate_training_data(num_normal=1000, num_suspicious=500)
        metrics = detector.train(X, y)
        logger.info(f"Model trained with accuracy: {metrics.get('accuracy', 0):.4f}")
    
    logger.info("\nGenerating demo security events...")
    logger.info("="*60)
    
    # Generate and process demo events
    num_events = 20
    events = []
    
    for i in range(num_events):
        # 30% chance of threat
        is_threat = random.random() < 0.3
        event = generate_demo_event(is_threat=is_threat)
        events.append(event)
        
        logger.info(f"\nEvent {i+1}/{num_events}:")
        logger.info(f"  Source: {event['source']}")
        logger.info(f"  Activity: {event['activity']}")
        logger.info(f"  IP: {event['ip_address']}")
        
        time.sleep(0.5)
    
    logger.info("\n" + "="*60)
    logger.info("Processing events through ML pipeline...")
    logger.info("="*60)
    
    # Process all events
    feature_array, normalized_df = preprocessor.process_batch(events)
    
    if len(feature_array) > 0:
        # Detect threats
        threat_results = detector.detect_threats(feature_array)
        
        # Generate alerts
        alerts = alert_manager.generate_batch_alerts(events, threat_results)
        
        # Display results
        logger.info(f"\n✓ Processed {len(events)} events")
        logger.info(f"✓ Extracted {len(feature_array)} feature vectors")
        logger.info(f"✓ Detected {sum(1 for r in threat_results if r['is_threat'])} threats")
        logger.info(f"✓ Generated {len(alerts)} alerts")
        
        # Display alerts
        if alerts:
            logger.info("\n" + "="*60)
            logger.info("GENERATED ALERTS")
            logger.info("="*60)
            
            for alert in alerts:
                logger.warning(f"\n🚨 {alert['severity'].upper()} Alert:")
                logger.warning(f"  ID: {alert['alert_id']}")
                logger.warning(f"  Confidence: {alert['confidence']*100:.1f}%")
                logger.warning(f"  Source: {alert['source']}")
                logger.warning(f"  Description: {alert['description']}")
                logger.warning(f"  Recommendations: {alert['recommendations'][0]}")
        
        # Display statistics
        stats = alert_manager.get_alert_statistics()
        logger.info("\n" + "="*60)
        logger.info("ALERT STATISTICS")
        logger.info("="*60)
        logger.info(f"Total Alerts: {stats['total_alerts']}")
        logger.info(f"Active Alerts: {stats['active_alerts']}")
        logger.info(f"By Severity: {stats['by_severity']}")
        
        # Display summary stats
        summary = preprocessor.create_summary_stats(normalized_df)
        logger.info("\n" + "="*60)
        logger.info("EVENT SUMMARY")
        logger.info("="*60)
        logger.info(f"Total Events: {summary.get('total_events', 0)}")
        logger.info(f"Failure Rate: {summary.get('failure_rate', 0)*100:.1f}%")
        logger.info(f"Avg Malicious Score: {summary.get('avg_malicious_score', 0):.3f}")
        logger.info(f"Suspicious Agents: {summary.get('suspicious_agents', 0)}")
        
    logger.info("\n" + "="*60)
    logger.info("DEMO COMPLETE")
    logger.info("="*60)
    logger.info("\nTo run the full system with real data:")
    logger.info("  1. Configure your cloud credentials in .env")
    logger.info("  2. Run: python main.py")
    logger.info("  3. Access dashboard at: http://localhost:8050")


if __name__ == "__main__":
    run_demo()

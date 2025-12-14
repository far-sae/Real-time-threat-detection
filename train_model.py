#!/usr/bin/env python3
"""
Training script to train the ML model with synthetic data.
"""
from loguru import logger
from ml_detection import ThreatDetector, TrainingDataGenerator


def train_model():
    """Train the threat detection model"""
    logger.info("Starting model training...")
    
    # Initialize generator and detector
    generator = TrainingDataGenerator()
    detector = ThreatDetector()
    
    # Generate training data
    logger.info("Generating training data...")
    X, y = generator.generate_training_data(
        num_normal=2000,
        num_suspicious=1000
    )
    
    # Train model
    logger.info("Training Random Forest model...")
    metrics = detector.train(X, y, test_size=0.2)
    
    # Display results
    logger.info("="*60)
    logger.info("TRAINING RESULTS")
    logger.info("="*60)
    logger.info(f"Accuracy: {metrics.get('accuracy', 0):.4f}")
    logger.info(f"Training Samples: {metrics.get('train_samples', 0)}")
    logger.info(f"Test Samples: {metrics.get('test_samples', 0)}")
    logger.info("\nClassification Report:")
    
    report = metrics.get('classification_report', {})
    for label, stats in report.items():
        if isinstance(stats, dict):
            logger.info(f"  {label}: precision={stats.get('precision', 0):.3f}, "
                       f"recall={stats.get('recall', 0):.3f}, "
                       f"f1-score={stats.get('f1-score', 0):.3f}")
    
    logger.info("="*60)
    logger.info("Model saved successfully!")
    
    # Display feature importance
    feature_names = generator.get_feature_names()
    importance = detector.get_feature_importance(feature_names)
    
    logger.info("\nTop 10 Most Important Features:")
    for i, (feature, score) in enumerate(list(importance.items())[:10], 1):
        logger.info(f"  {i}. {feature}: {score:.4f}")


if __name__ == "__main__":
    train_model()

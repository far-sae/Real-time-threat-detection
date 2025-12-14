"""
Machine Learning threat detection engine using Random Forest classifier.
"""
import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from typing import List, Dict, Tuple, Any
from loguru import logger
from config import Config


class ThreatDetector:
    """ML-based threat detection using Random Forest"""
    
    def __init__(self, model_path: str = None):
        """
        Initialize threat detector
        
        Args:
            model_path: Path to saved model file
        """
        self.model_path = model_path or Config.MODEL_PATH
        self.model = None
        self.is_trained = False
        self.feature_importance = None
        
        # Try to load existing model
        if os.path.exists(self.model_path):
            self.load_model()
        else:
            # Initialize new model
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            )
            logger.info("Initialized new Random Forest model")
    
    def train(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> Dict[str, Any]:
        """
        Train the Random Forest model
        
        Args:
            X: Feature array
            y: Label array (0 = normal, 1 = suspicious)
            test_size: Proportion of data for testing
            
        Returns:
            Dictionary containing training metrics
        """
        try:
            logger.info(f"Training model on {len(X)} samples with {X.shape[1]} features")
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )
            
            # Train model
            self.model.fit(X_train, y_train)
            self.is_trained = True
            
            # Calculate feature importance
            self.feature_importance = self.model.feature_importances_
            
            # Evaluate on test set
            y_pred = self.model.predict(X_test)
            
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'classification_report': classification_report(y_test, y_pred, output_dict=True),
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
                'train_samples': len(X_train),
                'test_samples': len(X_test)
            }
            
            logger.info(f"Model trained with accuracy: {metrics['accuracy']:.4f}")
            
            # Save model
            self.save_model()
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return {}
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict threat labels for input data
        
        Args:
            X: Feature array
            
        Returns:
            Array of predictions (0 = normal, 1 = suspicious)
        """
        if not self.is_trained:
            logger.warning("Model not trained, returning all normal predictions")
            return np.zeros(len(X), dtype=int)
        
        try:
            predictions = self.model.predict(X)
            logger.debug(f"Made predictions for {len(X)} samples")
            return predictions
            
        except Exception as e:
            logger.error(f"Error making predictions: {e}")
            return np.zeros(len(X), dtype=int)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Predict probability estimates for input data
        
        Args:
            X: Feature array
            
        Returns:
            Array of probability estimates for each class
        """
        if not self.is_trained:
            logger.warning("Model not trained, returning neutral probabilities")
            return np.array([[0.5, 0.5]] * len(X))
        
        try:
            probabilities = self.model.predict_proba(X)
            logger.debug(f"Generated probabilities for {len(X)} samples")
            return probabilities
            
        except Exception as e:
            logger.error(f"Error generating probabilities: {e}")
            return np.array([[0.5, 0.5]] * len(X))
    
    def detect_threats(self, X: np.ndarray, threshold: float = None) -> List[Dict[str, Any]]:
        """
        Detect threats in input data with confidence scores
        
        Args:
            X: Feature array
            threshold: Confidence threshold (default from config)
            
        Returns:
            List of threat detection results
        """
        if threshold is None:
            threshold = Config.CONFIDENCE_THRESHOLD
        
        try:
            # Get predictions and probabilities
            predictions = self.predict(X)
            probabilities = self.predict_proba(X)
            
            results = []
            for i in range(len(X)):
                threat_prob = probabilities[i][1]  # Probability of being suspicious
                
                result = {
                    'index': i,
                    'is_threat': bool(predictions[i] == 1),
                    'confidence': float(threat_prob),
                    'prediction': int(predictions[i]),
                    'exceeds_threshold': bool(threat_prob >= threshold)
                }
                
                results.append(result)
            
            threat_count = sum(1 for r in results if r['is_threat'])
            logger.info(f"Detected {threat_count}/{len(results)} threats")
            
            return results
            
        except Exception as e:
            logger.error(f"Error detecting threats: {e}")
            return []
    
    def save_model(self):
        """Save trained model to disk"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            # Save model
            joblib.dump(self.model, self.model_path)
            logger.info(f"Model saved to {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def load_model(self):
        """Load trained model from disk"""
        try:
            self.model = joblib.load(self.model_path)
            self.is_trained = True
            
            # Load feature importance if available
            if hasattr(self.model, 'feature_importances_'):
                self.feature_importance = self.model.feature_importances_
            
            logger.info(f"Model loaded from {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self.is_trained = False
    
    def get_feature_importance(self, feature_names: List[str] = None) -> Dict[str, float]:
        """
        Get feature importance scores
        
        Args:
            feature_names: List of feature names
            
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if self.feature_importance is None:
            return {}
        
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(len(self.feature_importance))]
        
        # Create dictionary of feature importance
        importance_dict = dict(zip(feature_names, self.feature_importance))
        
        # Sort by importance
        sorted_importance = dict(
            sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
        )
        
        return sorted_importance
    
    def retrain_needed(self) -> bool:
        """
        Check if model needs retraining based on age
        
        Returns:
            True if retraining is needed
        """
        if not os.path.exists(self.model_path):
            return True
        
        try:
            # Check file age
            import time
            file_age = time.time() - os.path.getmtime(self.model_path)
            
            # Retrain if older than configured interval
            return file_age > Config.RETRAIN_INTERVAL
            
        except Exception as e:
            logger.error(f"Error checking model age: {e}")
            return False

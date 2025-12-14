"""
Training data generator for creating initial training dataset.
"""
import numpy as np
from typing import Tuple
from loguru import logger


class TrainingDataGenerator:
    """Generates synthetic training data for initial model training"""
    
    def __init__(self):
        """Initialize training data generator"""
        self.num_features = 25  # Match the features from FeatureExtractor
    
    def generate_training_data(self, 
                               num_normal: int = 1000, 
                               num_suspicious: int = 500) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate synthetic training data
        
        Args:
            num_normal: Number of normal samples to generate
            num_suspicious: Number of suspicious samples to generate
            
        Returns:
            Tuple of (features, labels)
        """
        logger.info(f"Generating {num_normal} normal and {num_suspicious} suspicious samples")
        
        # Generate normal traffic patterns
        normal_samples = self._generate_normal_samples(num_normal)
        
        # Generate suspicious traffic patterns
        suspicious_samples = self._generate_suspicious_samples(num_suspicious)
        
        # Combine and create labels
        X = np.vstack([normal_samples, suspicious_samples])
        y = np.array([0] * num_normal + [1] * num_suspicious)
        
        # Shuffle
        indices = np.random.permutation(len(X))
        X = X[indices]
        y = y[indices]
        
        logger.info(f"Generated {len(X)} total samples with {X.shape[1]} features")
        return X, y
    
    def _generate_normal_samples(self, num_samples: int) -> np.ndarray:
        """Generate normal traffic samples"""
        samples = []
        
        for _ in range(num_samples):
            sample = [
                np.random.randint(8, 18),  # hour (business hours)
                np.random.randint(0, 5),   # day_of_week (weekday)
                0,  # is_weekend
                1,  # is_business_hours
                0,  # is_night
                np.random.randint(0, 100000),  # ip_address_hash
                np.random.choice([0, 1], p=[0.9, 0.1]),  # is_private_ip
                np.random.uniform(0.7, 1.0),  # ip_reputation_score
                0,  # is_suspicious_agent
                np.random.randint(50, 200),  # user_agent_length
                np.random.randint(0, 100000),  # event_id_hash
                np.random.randint(0, 100000),  # activity_hash
                np.random.randint(0, 100000),  # category_hash
                np.random.choice([0, 1], p=[0.95, 0.05]),  # is_failure
                np.random.choice([0, 1], p=[0.05, 0.95]),  # is_success
                np.random.randint(0, 100000),  # identity_hash
                1,  # has_identity
                0.0,  # sql_injection_score
                0.0,  # xss_score
                0.0,  # path_traversal_score
                0.0,  # command_injection_score
                0.0,  # code_execution_score
                0.0,  # overall_malicious_score
                np.random.randint(100, 500),  # message_length
                np.random.randint(5, 30),  # num_special_chars
                np.random.uniform(2.0, 4.0),  # entropy
            ]
            samples.append(sample)
        
        return np.array(samples)
    
    def _generate_suspicious_samples(self, num_samples: int) -> np.ndarray:
        """Generate suspicious traffic samples"""
        samples = []
        
        for _ in range(num_samples):
            sample = [
                np.random.choice([np.random.randint(0, 6), np.random.randint(22, 24)]),  # hour (off-hours)
                np.random.randint(0, 7),  # day_of_week
                np.random.choice([0, 1], p=[0.5, 0.5]),  # is_weekend
                0,  # is_business_hours
                1,  # is_night
                np.random.randint(0, 100000),  # ip_address_hash
                np.random.choice([0, 1], p=[0.3, 0.7]),  # is_private_ip (more external)
                np.random.uniform(0.1, 0.4),  # ip_reputation_score (low reputation)
                np.random.choice([0, 1], p=[0.3, 0.7]),  # is_suspicious_agent
                np.random.randint(20, 100),  # user_agent_length (shorter)
                np.random.randint(0, 100000),  # event_id_hash
                np.random.randint(0, 100000),  # activity_hash
                np.random.randint(0, 100000),  # category_hash
                np.random.choice([0, 1], p=[0.3, 0.7]),  # is_failure (more failures)
                np.random.choice([0, 1], p=[0.7, 0.3]),  # is_success
                np.random.randint(0, 100000),  # identity_hash
                np.random.choice([0, 1], p=[0.3, 0.7]),  # has_identity
                np.random.uniform(0.0, 0.8),  # sql_injection_score
                np.random.uniform(0.0, 0.7),  # xss_score
                np.random.uniform(0.0, 0.6),  # path_traversal_score
                np.random.uniform(0.0, 0.7),  # command_injection_score
                np.random.uniform(0.0, 0.6),  # code_execution_score
                np.random.uniform(0.3, 0.9),  # overall_malicious_score
                np.random.randint(200, 1000),  # message_length (longer, more complex)
                np.random.randint(50, 200),  # num_special_chars (more special chars)
                np.random.uniform(4.5, 7.0),  # entropy (higher entropy)
            ]
            samples.append(sample)
        
        return np.array(samples)
    
    def get_feature_names(self) -> list:
        """Get feature names for the generated data"""
        return [
            'hour', 'day_of_week', 'is_weekend', 'is_business_hours', 'is_night',
            'ip_address_hash', 'is_private_ip', 'ip_reputation_score',
            'is_suspicious_agent', 'user_agent_length',
            'event_id_hash', 'activity_hash', 'category_hash',
            'is_failure', 'is_success', 'identity_hash', 'has_identity',
            'sql_injection_score', 'xss_score', 'path_traversal_score',
            'command_injection_score', 'code_execution_score', 'overall_malicious_score',
            'message_length', 'num_special_chars', 'entropy'
        ]

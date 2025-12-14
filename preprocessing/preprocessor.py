"""
Log normalization and preprocessing pipeline.
"""
import pandas as pd
import numpy as np
from typing import List, Dict, Any
from loguru import logger
from preprocessing.feature_extractor import FeatureExtractor


class LogPreprocessor:
    """Normalizes and preprocesses security logs for ML analysis"""
    
    def __init__(self):
        """Initialize preprocessor"""
        self.feature_extractor = FeatureExtractor()
        self.feature_columns = None
    
    def normalize_logs(self, raw_logs: List[Dict]) -> pd.DataFrame:
        """
        Normalize raw logs into structured format
        
        Args:
            raw_logs: List of raw log dictionaries
            
        Returns:
            Normalized pandas DataFrame
        """
        if not raw_logs:
            logger.warning("No logs to normalize")
            return pd.DataFrame()
        
        try:
            # Extract features from each log
            processed_logs = []
            for log in raw_logs:
                features = self.feature_extractor.extract_features(log)
                if features:
                    processed_logs.append(features)
            
            if not processed_logs:
                logger.warning("No features extracted from logs")
                return pd.DataFrame()
            
            # Convert to DataFrame
            df = pd.DataFrame(processed_logs)
            
            logger.info(f"Normalized {len(df)} log entries with {len(df.columns)} features")
            return df
            
        except Exception as e:
            logger.error(f"Error normalizing logs: {e}")
            return pd.DataFrame()
    
    def prepare_for_ml(self, df: pd.DataFrame, training: bool = False) -> np.ndarray:
        """
        Prepare normalized logs for ML model input
        
        Args:
            df: Normalized DataFrame
            training: Whether this is for training (stores feature columns)
            
        Returns:
            NumPy array ready for ML model
        """
        if df.empty:
            return np.array([])
        
        try:
            # Select numeric features only
            numeric_features = df.select_dtypes(include=[np.number])
            
            # Remove timestamp and source columns if they exist
            exclude_cols = ['timestamp']
            numeric_features = numeric_features.drop(
                columns=[col for col in exclude_cols if col in numeric_features.columns],
                errors='ignore'
            )
            
            if training:
                # Store feature columns for consistency
                self.feature_columns = numeric_features.columns.tolist()
                logger.info(f"Stored {len(self.feature_columns)} feature columns for ML")
            else:
                # Ensure same features as training
                if self.feature_columns:
                    # Add missing columns with zeros
                    for col in self.feature_columns:
                        if col not in numeric_features.columns:
                            numeric_features[col] = 0
                    
                    # Remove extra columns
                    numeric_features = numeric_features[self.feature_columns]
            
            # Handle missing values
            numeric_features = numeric_features.fillna(0)
            
            # Handle infinite values
            numeric_features = numeric_features.replace([np.inf, -np.inf], 0)
            
            logger.info(f"Prepared {len(numeric_features)} samples with {len(numeric_features.columns)} features")
            return numeric_features.values
            
        except Exception as e:
            logger.error(f"Error preparing data for ML: {e}")
            return np.array([])
    
    def process_batch(self, raw_logs: List[Dict], training: bool = False) -> tuple:
        """
        Complete preprocessing pipeline for a batch of logs
        
        Args:
            raw_logs: List of raw log dictionaries
            training: Whether this is for training
            
        Returns:
            Tuple of (feature array, normalized DataFrame)
        """
        # Normalize logs
        normalized_df = self.normalize_logs(raw_logs)
        
        if normalized_df.empty:
            return np.array([]), normalized_df
        
        # Prepare for ML
        feature_array = self.prepare_for_ml(normalized_df, training=training)
        
        return feature_array, normalized_df
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature column names"""
        return self.feature_columns if self.feature_columns else []
    
    def create_summary_stats(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Create summary statistics from normalized logs
        
        Args:
            df: Normalized DataFrame
            
        Returns:
            Dictionary of summary statistics
        """
        if df.empty:
            return {}
        
        try:
            stats = {
                'total_events': len(df),
                'sources': df['source'].value_counts().to_dict() if 'source' in df.columns else {},
                'failure_rate': df['is_failure'].mean() if 'is_failure' in df.columns else 0,
                'avg_malicious_score': df['overall_malicious_score'].mean() 
                    if 'overall_malicious_score' in df.columns else 0,
                'suspicious_agents': df['is_suspicious_agent'].sum() 
                    if 'is_suspicious_agent' in df.columns else 0,
                'after_hours_events': df['is_night'].sum() if 'is_night' in df.columns else 0,
                'weekend_events': df['is_weekend'].sum() if 'is_weekend' in df.columns else 0,
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error creating summary stats: {e}")
            return {}

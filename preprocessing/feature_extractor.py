"""
Feature extraction and engineering for security log data.
"""
import re
import hashlib
from datetime import datetime
from typing import Dict, List, Any
from loguru import logger
import numpy as np


class FeatureExtractor:
    """Extracts features from raw security logs for ML analysis"""
    
    # Known malicious patterns
    MALICIOUS_PATTERNS = [
        r'(?i)(select|union|insert|drop|delete|update|exec|script)',  # SQL injection
        r'(?i)(<script|javascript:|onerror=|onclick=)',  # XSS
        r'(?i)(\.\.\/|\.\.\\)',  # Path traversal
        r'(?i)(cmd\.exe|/bin/bash|/bin/sh)',  # Command injection
        r'(?i)(base64_decode|eval\(|system\()',  # Code execution
    ]
    
    # Suspicious user agents
    SUSPICIOUS_AGENTS = ['bot', 'crawler', 'scanner', 'sqlmap', 'nikto', 'nmap']
    
    def __init__(self):
        """Initialize feature extractor"""
        self.ip_cache = {}
        self.user_cache = {}
    
    def extract_features(self, log_event: Dict) -> Dict[str, Any]:
        """
        Extract features from a single log event
        
        Args:
            log_event: Raw log event dictionary
            
        Returns:
            Dictionary containing extracted features
        """
        try:
            features = {}
            
            # Basic features
            features['source'] = log_event.get('source', 'unknown')
            features['timestamp'] = log_event.get('timestamp', '')
            
            # Temporal features
            features.update(self._extract_temporal_features(log_event))
            
            # Network features
            features.update(self._extract_network_features(log_event))
            
            # Event-based features
            features.update(self._extract_event_features(log_event))
            
            # Pattern-based features
            features.update(self._extract_pattern_features(log_event))
            
            # Statistical features
            features.update(self._extract_statistical_features(log_event))
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return {}
    
    def _extract_temporal_features(self, log_event: Dict) -> Dict:
        """Extract time-based features"""
        features = {}
        
        try:
            timestamp_str = log_event.get('timestamp', '')
            if timestamp_str:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                
                features['hour'] = dt.hour
                features['day_of_week'] = dt.weekday()
                features['is_weekend'] = 1 if dt.weekday() >= 5 else 0
                features['is_business_hours'] = 1 if 9 <= dt.hour <= 17 else 0
                features['is_night'] = 1 if dt.hour < 6 or dt.hour > 22 else 0
            else:
                features['hour'] = -1
                features['day_of_week'] = -1
                features['is_weekend'] = 0
                features['is_business_hours'] = 0
                features['is_night'] = 0
                
        except Exception as e:
            logger.debug(f"Error extracting temporal features: {e}")
            features = {
                'hour': -1, 'day_of_week': -1, 'is_weekend': 0,
                'is_business_hours': 0, 'is_night': 0
            }
        
        return features
    
    def _extract_network_features(self, log_event: Dict) -> Dict:
        """Extract network-related features"""
        features = {}
        
        message = log_event.get('message', {})
        raw_data = log_event.get('raw_data', {})
        
        # IP address features
        ip_address = (
            message.get('ip_address') or 
            message.get('IPAddress') or 
            raw_data.get('ip_address') or
            'unknown'
        )
        
        features['ip_address_hash'] = self._hash_value(str(ip_address))
        features['is_private_ip'] = self._is_private_ip(str(ip_address))
        features['ip_reputation_score'] = self._get_ip_reputation(str(ip_address))
        
        # User agent features
        user_agent = message.get('user_agent', '') or message.get('UserAgent', '')
        features['is_suspicious_agent'] = self._check_suspicious_agent(user_agent)
        features['user_agent_length'] = len(str(user_agent))
        
        return features
    
    def _extract_event_features(self, log_event: Dict) -> Dict:
        """Extract event-specific features"""
        features = {}
        
        message = log_event.get('message', {})
        raw_data = log_event.get('raw_data', {})
        
        # Event type and category
        event_id = str(log_event.get('event_id', '') or message.get('EventID', 'unknown'))
        activity = log_event.get('activity', '') or message.get('Activity', '')
        category = log_event.get('category', '') or message.get('Category', 'unknown')
        
        features['event_id_hash'] = self._hash_value(event_id)
        features['activity_hash'] = self._hash_value(str(activity))
        features['category_hash'] = self._hash_value(str(category))
        
        # Result/Status features
        result_type = (
            log_event.get('result_type') or 
            message.get('ResultType') or 
            message.get('Status') or
            'unknown'
        )
        features['is_failure'] = 1 if 'fail' in str(result_type).lower() else 0
        features['is_success'] = 1 if 'success' in str(result_type).lower() else 0
        
        # Identity features
        identity = log_event.get('identity', '') or message.get('Identity', '')
        features['identity_hash'] = self._hash_value(str(identity))
        features['has_identity'] = 1 if identity else 0
        
        return features
    
    def _extract_pattern_features(self, log_event: Dict) -> Dict:
        """Extract pattern-based security features"""
        features = {}
        
        # Convert entire log event to string for pattern matching
        log_str = str(log_event).lower()
        
        # Check for malicious patterns
        features['sql_injection_score'] = self._check_pattern(log_str, self.MALICIOUS_PATTERNS[0])
        features['xss_score'] = self._check_pattern(log_str, self.MALICIOUS_PATTERNS[1])
        features['path_traversal_score'] = self._check_pattern(log_str, self.MALICIOUS_PATTERNS[2])
        features['command_injection_score'] = self._check_pattern(log_str, self.MALICIOUS_PATTERNS[3])
        features['code_execution_score'] = self._check_pattern(log_str, self.MALICIOUS_PATTERNS[4])
        
        # Overall malicious score
        features['overall_malicious_score'] = sum([
            features['sql_injection_score'],
            features['xss_score'],
            features['path_traversal_score'],
            features['command_injection_score'],
            features['code_execution_score']
        ]) / 5.0
        
        return features
    
    def _extract_statistical_features(self, log_event: Dict) -> Dict:
        """Extract statistical features"""
        features = {}
        
        message = log_event.get('message', {})
        
        # Message complexity
        message_str = str(message)
        features['message_length'] = len(message_str)
        features['num_special_chars'] = sum(1 for c in message_str if not c.isalnum())
        features['entropy'] = self._calculate_entropy(message_str)
        
        # Field count
        features['num_fields'] = len(message) if isinstance(message, dict) else 0
        
        return features
    
    def _hash_value(self, value: str) -> int:
        """Hash string value to numeric representation"""
        if not value or value == 'unknown':
            return 0
        return int(hashlib.md5(value.encode()).hexdigest()[:8], 16) % 1000000
    
    def _is_private_ip(self, ip: str) -> int:
        """Check if IP address is private"""
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return 0
            
            first = int(octets[0])
            second = int(octets[1])
            
            if first == 10:
                return 1
            if first == 172 and 16 <= second <= 31:
                return 1
            if first == 192 and second == 168:
                return 1
            
            return 0
        except:
            return 0
    
    def _get_ip_reputation(self, ip: str) -> float:
        """Get IP reputation score (simplified version)"""
        # In production, integrate with threat intelligence feeds
        # For now, use simple heuristics
        
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        score = 0.5  # Neutral score
        
        # Private IPs get better score
        if self._is_private_ip(ip):
            score = 0.9
        
        self.ip_cache[ip] = score
        return score
    
    def _check_suspicious_agent(self, user_agent: str) -> int:
        """Check if user agent is suspicious"""
        user_agent_lower = str(user_agent).lower()
        for agent in self.SUSPICIOUS_AGENTS:
            if agent in user_agent_lower:
                return 1
        return 0
    
    def _check_pattern(self, text: str, pattern: str) -> float:
        """Check for pattern matches and return score"""
        try:
            matches = re.findall(pattern, text)
            return min(len(matches) / 10.0, 1.0)  # Normalize to 0-1
        except:
            return 0.0
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        try:
            # Calculate frequency of each character
            freq = {}
            for char in text:
                freq[char] = freq.get(char, 0) + 1
            
            # Calculate entropy
            entropy = 0.0
            length = len(text)
            for count in freq.values():
                p = count / length
                entropy -= p * np.log2(p)
            
            return entropy
        except:
            return 0.0

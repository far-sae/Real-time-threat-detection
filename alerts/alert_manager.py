"""
Alert generation and prioritization system for security threats.
"""
import json
import requests
from datetime import datetime
from typing import List, Dict, Any
from enum import Enum
from loguru import logger
from config import Config


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertManager:
    """Manages security alert generation and distribution"""
    
    def __init__(self):
        """Initialize alert manager"""
        self.alert_history = []
        self.alert_count = {
            'low': 0,
            'medium': 0,
            'high': 0,
            'critical': 0
        }
    
    def generate_alert(self, 
                      event_data: Dict,
                      threat_info: Dict,
                      severity: AlertSeverity = None) -> Dict[str, Any]:
        """
        Generate a security alert
        
        Args:
            event_data: Original event data
            threat_info: Threat detection information
            severity: Alert severity (auto-calculated if not provided)
            
        Returns:
            Alert dictionary
        """
        try:
            # Determine severity if not provided
            if severity is None:
                severity = self._calculate_severity(threat_info)
            
            alert = {
                'alert_id': self._generate_alert_id(),
                'timestamp': datetime.utcnow().isoformat(),
                'severity': severity.value,
                'confidence': threat_info.get('confidence', 0.0),
                'source': event_data.get('source', 'unknown'),
                'event_timestamp': event_data.get('timestamp', ''),
                'description': self._generate_description(event_data, threat_info),
                'recommendations': self._generate_recommendations(severity, threat_info),
                'event_data': event_data,
                'threat_info': threat_info,
                'status': 'open'
            }
            
            # Add to history
            self.alert_history.append(alert)
            self.alert_count[severity.value] += 1
            
            logger.warning(f"Generated {severity.value} severity alert: {alert['alert_id']}")
            
            # Distribute alert
            self._distribute_alert(alert)
            
            return alert
            
        except Exception as e:
            logger.error(f"Error generating alert: {e}")
            return {}
    
    def generate_batch_alerts(self, 
                             events: List[Dict],
                             threat_results: List[Dict]) -> List[Dict]:
        """
        Generate alerts for a batch of events
        
        Args:
            events: List of event dictionaries
            threat_results: List of threat detection results
            
        Returns:
            List of generated alerts
        """
        alerts = []
        
        for i, threat_result in enumerate(threat_results):
            if threat_result.get('is_threat') or threat_result.get('exceeds_threshold'):
                # Get corresponding event data
                event_idx = threat_result.get('index', i)
                if event_idx < len(events):
                    event_data = events[event_idx]
                    alert = self.generate_alert(event_data, threat_result)
                    if alert:
                        alerts.append(alert)
        
        logger.info(f"Generated {len(alerts)} alerts from {len(events)} events")
        return alerts
    
    def _calculate_severity(self, threat_info: Dict) -> AlertSeverity:
        """Calculate alert severity based on threat information"""
        confidence = threat_info.get('confidence', 0.0)
        
        if confidence >= Config.HIGH_SEVERITY_THRESHOLD:
            return AlertSeverity.CRITICAL if confidence >= 0.95 else AlertSeverity.HIGH
        elif confidence >= Config.MEDIUM_SEVERITY_THRESHOLD:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        import hashlib
        timestamp = datetime.utcnow().isoformat()
        unique_str = f"{timestamp}_{len(self.alert_history)}"
        return hashlib.md5(unique_str.encode()).hexdigest()[:12]
    
    def _generate_description(self, event_data: Dict, threat_info: Dict) -> str:
        """Generate human-readable alert description"""
        source = event_data.get('source', 'unknown')
        confidence = threat_info.get('confidence', 0) * 100
        
        description = f"Potential security threat detected from {source} "
        description += f"with {confidence:.1f}% confidence. "
        
        # Add context from event data
        if 'activity' in event_data:
            description += f"Activity: {event_data['activity']}. "
        
        if 'ip_address' in event_data:
            description += f"Source IP: {event_data['ip_address']}. "
        
        return description
    
    def _generate_recommendations(self, 
                                  severity: AlertSeverity,
                                  threat_info: Dict) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            recommendations.append("Immediately investigate this event")
            recommendations.append("Review all recent activities from this source")
            recommendations.append("Consider blocking the source IP address")
            recommendations.append("Check for any successful unauthorized access")
        elif severity == AlertSeverity.MEDIUM:
            recommendations.append("Review this event during next security review")
            recommendations.append("Monitor the source for additional suspicious activity")
            recommendations.append("Verify user identity if applicable")
        else:
            recommendations.append("Log for future analysis")
            recommendations.append("Monitor for pattern escalation")
        
        return recommendations
    
    def _distribute_alert(self, alert: Dict):
        """Distribute alert through configured channels"""
        severity = alert['severity']
        
        # Always log
        logger.warning(f"ALERT [{severity.upper()}]: {alert['description']}")
        
        # Send to Slack if configured and high severity
        if Config.SLACK_WEBHOOK_URL and severity in ['high', 'critical']:
            self._send_to_slack(alert)
        
        # Email notification for critical alerts
        if severity == 'critical':
            self._send_email_notification(alert)
    
    def _send_to_slack(self, alert: Dict):
        """Send alert to Slack webhook"""
        try:
            if not Config.SLACK_WEBHOOK_URL:
                return
            
            # Determine color based on severity
            color_map = {
                'low': '#36a64f',
                'medium': '#ff9900',
                'high': '#ff6600',
                'critical': '#ff0000'
            }
            
            payload = {
                'attachments': [{
                    'color': color_map.get(alert['severity'], '#808080'),
                    'title': f"🚨 Security Alert: {alert['severity'].upper()}",
                    'text': alert['description'],
                    'fields': [
                        {
                            'title': 'Alert ID',
                            'value': alert['alert_id'],
                            'short': True
                        },
                        {
                            'title': 'Confidence',
                            'value': f"{alert['confidence'] * 100:.1f}%",
                            'short': True
                        },
                        {
                            'title': 'Source',
                            'value': alert['source'],
                            'short': True
                        },
                        {
                            'title': 'Timestamp',
                            'value': alert['timestamp'],
                            'short': True
                        }
                    ],
                    'footer': 'Threat Detection System',
                    'ts': int(datetime.utcnow().timestamp())
                }]
            }
            
            response = requests.post(
                Config.SLACK_WEBHOOK_URL,
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info(f"Alert sent to Slack: {alert['alert_id']}")
            else:
                logger.error(f"Failed to send Slack alert: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
    
    def _send_email_notification(self, alert: Dict):
        """Send email notification (placeholder for actual implementation)"""
        # In production, integrate with AWS SES, SendGrid, or other email service
        logger.info(f"Email notification would be sent to {Config.ALERT_EMAIL}")
        logger.info(f"Alert: {alert['alert_id']} - {alert['description']}")
    
    def get_active_alerts(self, severity: str = None, limit: int = 100) -> List[Dict]:
        """
        Get active alerts, optionally filtered by severity
        
        Args:
            severity: Filter by severity level
            limit: Maximum number of alerts to return
            
        Returns:
            List of active alerts
        """
        alerts = [a for a in self.alert_history if a['status'] == 'open']
        
        if severity:
            alerts = [a for a in alerts if a['severity'] == severity]
        
        # Sort by timestamp, most recent first
        alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return alerts[:limit]
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        return {
            'total_alerts': len(self.alert_history),
            'active_alerts': len([a for a in self.alert_history if a['status'] == 'open']),
            'by_severity': self.alert_count.copy(),
            'recent_alerts': self.get_active_alerts(limit=10)
        }
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark alert as acknowledged"""
        for alert in self.alert_history:
            if alert['alert_id'] == alert_id:
                alert['status'] = 'acknowledged'
                alert['acknowledged_at'] = datetime.utcnow().isoformat()
                logger.info(f"Alert acknowledged: {alert_id}")
                return True
        
        return False
    
    def resolve_alert(self, alert_id: str, resolution_notes: str = "") -> bool:
        """Mark alert as resolved"""
        for alert in self.alert_history:
            if alert['alert_id'] == alert_id:
                alert['status'] = 'resolved'
                alert['resolved_at'] = datetime.utcnow().isoformat()
                alert['resolution_notes'] = resolution_notes
                logger.info(f"Alert resolved: {alert_id}")
                return True
        
        return False

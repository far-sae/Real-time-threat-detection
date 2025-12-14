"""
Azure Monitor log collector for real-time security event ingestion.
"""
from azure.identity import ClientSecretCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from datetime import datetime, timedelta
from typing import List, Dict, Generator
from loguru import logger
from config import Config


class AzureLogCollector:
    """Collects security logs from Azure Monitor in real-time"""
    
    def __init__(self):
        """Initialize Azure Monitor client"""
        try:
            # Create credential
            self.credential = ClientSecretCredential(
                tenant_id=Config.AZURE_TENANT_ID,
                client_id=Config.AZURE_CLIENT_ID,
                client_secret=Config.AZURE_CLIENT_SECRET
            )
            
            # Create logs query client
            self.client = LogsQueryClient(self.credential)
            self.workspace_id = Config.AZURE_WORKSPACE_ID
            
            logger.info(f"Azure Monitor client initialized for workspace {self.workspace_id}")
        except Exception as e:
            logger.error(f"Failed to initialize Azure client: {e}")
            raise
    
    def stream_logs(self, start_time: datetime = None, end_time: datetime = None) -> Generator[Dict, None, None]:
        """
        Stream logs from Azure Monitor in real-time
        
        Args:
            start_time: Start time for log retrieval (default: 5 minutes ago)
            end_time: End time for log retrieval (default: now)
            
        Yields:
            Dictionary containing log event data
        """
        if start_time is None:
            start_time = datetime.utcnow() - timedelta(minutes=5)
        if end_time is None:
            end_time = datetime.utcnow()
        
        try:
            # Query for security events
            query = """
            SecurityEvent
            | union SigninLogs
            | union AuditLogs
            | union AzureActivity
            | where TimeGenerated between (datetime({start}) .. datetime({end}))
            | project TimeGenerated, EventID, Activity, OperationName, 
                      ResultType, ResultDescription, IPAddress, 
                      Identity, Category, Level, ResourceId
            | order by TimeGenerated desc
            """.format(
                start=start_time.strftime('%Y-%m-%dT%H:%M:%S'),
                end=end_time.strftime('%Y-%m-%dT%H:%M:%S')
            )
            
            response = self.client.query_workspace(
                workspace_id=self.workspace_id,
                query=query,
                timespan=timedelta(hours=1)
            )
            
            if response.status == LogsQueryStatus.SUCCESS:
                for table in response.tables:
                    for row in table.rows:
                        log_entry = self._parse_log_event(table.columns, row)
                        if log_entry:
                            yield log_entry
            else:
                logger.error(f"Query failed with status: {response.status}")
                
        except Exception as e:
            logger.error(f"Error streaming logs from Azure: {e}")
    
    def _parse_log_event(self, columns: List, row: List) -> Dict:
        """
        Parse and structure an Azure Monitor log event
        
        Args:
            columns: Column definitions from the query result
            row: Row data from the query result
            
        Returns:
            Structured log entry dictionary
        """
        try:
            # Create a dictionary from columns and row data
            event_data = {}
            for i, col in enumerate(columns):
                if i < len(row):
                    event_data[col.name] = row[i]
            
            # Extract key fields
            timestamp = event_data.get('TimeGenerated')
            if isinstance(timestamp, datetime):
                timestamp = timestamp.isoformat()
            
            return {
                'timestamp': timestamp,
                'event_id': str(event_data.get('EventID', 'unknown')),
                'activity': event_data.get('Activity') or event_data.get('OperationName', 'unknown'),
                'result_type': event_data.get('ResultType', 'unknown'),
                'ip_address': event_data.get('IPAddress', 'unknown'),
                'identity': event_data.get('Identity', 'unknown'),
                'category': event_data.get('Category', 'security'),
                'level': event_data.get('Level', 'informational'),
                'source': 'azure',
                'message': event_data,
                'raw_data': event_data
            }
        except Exception as e:
            logger.warning(f"Failed to parse Azure log event: {e}")
            return None
    
    def get_recent_events(self, minutes: int = 5) -> List[Dict]:
        """
        Get recent security events from Azure Monitor
        
        Args:
            minutes: Number of minutes to look back
            
        Returns:
            List of log events
        """
        start_time = datetime.utcnow() - timedelta(minutes=minutes)
        events = list(self.stream_logs(start_time=start_time))
        logger.info(f"Retrieved {len(events)} events from Azure Monitor")
        return events
    
    def get_security_alerts(self, hours: int = 1) -> List[Dict]:
        """
        Get security alerts from Azure Security Center
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of security alerts
        """
        try:
            start_time = datetime.utcnow() - timedelta(hours=hours)
            
            query = """
            SecurityAlert
            | where TimeGenerated > ago({hours}h)
            | project TimeGenerated, AlertName, AlertSeverity, 
                      Description, RemediationSteps, Entities, 
                      CompromisedEntity, SystemAlertId
            | order by TimeGenerated desc
            """.format(hours=hours)
            
            response = self.client.query_workspace(
                workspace_id=self.workspace_id,
                query=query,
                timespan=timedelta(hours=hours)
            )
            
            alerts = []
            if response.status == LogsQueryStatus.SUCCESS:
                for table in response.tables:
                    for row in table.rows:
                        alert = self._parse_security_alert(table.columns, row)
                        if alert:
                            alerts.append(alert)
            
            logger.info(f"Retrieved {len(alerts)} security alerts from Azure")
            return alerts
            
        except Exception as e:
            logger.error(f"Error retrieving security alerts: {e}")
            return []
    
    def _parse_security_alert(self, columns: List, row: List) -> Dict:
        """Parse Azure Security Center alert"""
        try:
            event_data = {}
            for i, col in enumerate(columns):
                if i < len(row):
                    event_data[col.name] = row[i]
            
            timestamp = event_data.get('TimeGenerated')
            if isinstance(timestamp, datetime):
                timestamp = timestamp.isoformat()
            
            return {
                'timestamp': timestamp,
                'alert_name': event_data.get('AlertName', 'unknown'),
                'severity': event_data.get('AlertSeverity', 'medium'),
                'description': event_data.get('Description', ''),
                'remediation': event_data.get('RemediationSteps', ''),
                'entities': event_data.get('Entities', []),
                'compromised_entity': event_data.get('CompromisedEntity', 'unknown'),
                'alert_id': event_data.get('SystemAlertId', ''),
                'source': 'azure_security_center'
            }
        except Exception as e:
            logger.warning(f"Failed to parse security alert: {e}")
            return None

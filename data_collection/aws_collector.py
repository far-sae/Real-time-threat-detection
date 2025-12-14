"""
AWS CloudWatch log collector for real-time security event ingestion.
"""
import boto3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Generator
from loguru import logger
from config import Config


class AWSLogCollector:
    """Collects security logs from AWS CloudWatch in real-time"""
    
    def __init__(self):
        """Initialize AWS CloudWatch client"""
        try:
            self.client = boto3.client(
                'logs',
                aws_access_key_id=Config.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=Config.AWS_SECRET_ACCESS_KEY,
                region_name=Config.AWS_REGION
            )
            self.log_group_name = Config.AWS_LOG_GROUP_NAME
            logger.info(f"AWS CloudWatch client initialized for region {Config.AWS_REGION}")
        except Exception as e:
            logger.error(f"Failed to initialize AWS client: {e}")
            raise
    
    def get_log_streams(self) -> List[str]:
        """Get available log streams from the log group"""
        try:
            response = self.client.describe_log_streams(
                logGroupName=self.log_group_name,
                orderBy='LastEventTime',
                descending=True,
                limit=50
            )
            streams = [stream['logStreamName'] for stream in response.get('logStreams', [])]
            logger.debug(f"Found {len(streams)} log streams")
            return streams
        except Exception as e:
            logger.error(f"Error retrieving log streams: {e}")
            return []
    
    def stream_logs(self, start_time: datetime = None, end_time: datetime = None) -> Generator[Dict, None, None]:
        """
        Stream logs from CloudWatch in real-time
        
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
        
        start_timestamp = int(start_time.timestamp() * 1000)
        end_timestamp = int(end_time.timestamp() * 1000)
        
        try:
            # Filter log events
            kwargs = {
                'logGroupName': self.log_group_name,
                'startTime': start_timestamp,
                'endTime': end_timestamp,
                'limit': 100
            }
            
            while True:
                response = self.client.filter_log_events(**kwargs)
                
                for event in response.get('events', []):
                    log_entry = self._parse_log_event(event)
                    if log_entry:
                        yield log_entry
                
                # Check if there are more events to retrieve
                next_token = response.get('nextToken')
                if not next_token:
                    break
                
                kwargs['nextToken'] = next_token
                
        except Exception as e:
            logger.error(f"Error streaming logs from AWS: {e}")
    
    def _parse_log_event(self, event: Dict) -> Dict:
        """
        Parse and structure a CloudWatch log event
        
        Args:
            event: Raw log event from CloudWatch
            
        Returns:
            Structured log entry dictionary
        """
        try:
            message = event.get('message', '')
            
            # Try to parse JSON messages
            try:
                parsed_message = json.loads(message)
            except json.JSONDecodeError:
                parsed_message = {'raw_message': message}
            
            return {
                'timestamp': datetime.fromtimestamp(event['timestamp'] / 1000).isoformat(),
                'log_stream': event.get('logStreamName', 'unknown'),
                'message': parsed_message,
                'source': 'aws',
                'event_id': event.get('eventId'),
                'raw_data': event
            }
        except Exception as e:
            logger.warning(f"Failed to parse log event: {e}")
            return None
    
    def get_recent_events(self, minutes: int = 5) -> List[Dict]:
        """
        Get recent security events from CloudWatch
        
        Args:
            minutes: Number of minutes to look back
            
        Returns:
            List of log events
        """
        start_time = datetime.utcnow() - timedelta(minutes=minutes)
        events = list(self.stream_logs(start_time=start_time))
        logger.info(f"Retrieved {len(events)} events from AWS CloudWatch")
        return events

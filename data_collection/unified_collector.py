"""
Unified data collector that aggregates logs from AWS and Azure.
"""
import threading
import queue
from datetime import datetime
from typing import List, Dict
from loguru import logger

from data_collection.aws_collector import AWSLogCollector
from data_collection.azure_collector import AzureLogCollector


class UnifiedCollector:
    """Aggregates security logs from multiple cloud providers"""
    
    def __init__(self):
        """Initialize collectors for all cloud providers"""
        self.aws_collector = None
        self.azure_collector = None
        self.event_queue = queue.Queue(maxsize=10000)
        self.running = False
        
        # Initialize collectors
        try:
            self.aws_collector = AWSLogCollector()
            logger.info("AWS collector initialized")
        except Exception as e:
            logger.warning(f"Could not initialize AWS collector: {e}")
        
        try:
            self.azure_collector = AzureLogCollector()
            logger.info("Azure collector initialized")
        except Exception as e:
            logger.warning(f"Could not initialize Azure collector: {e}")
    
    def start_collection(self):
        """Start real-time log collection from all sources"""
        self.running = True
        
        threads = []
        
        # Start AWS collection thread
        if self.aws_collector:
            aws_thread = threading.Thread(target=self._collect_aws_logs, daemon=True)
            aws_thread.start()
            threads.append(aws_thread)
            logger.info("AWS collection thread started")
        
        # Start Azure collection thread
        if self.azure_collector:
            azure_thread = threading.Thread(target=self._collect_azure_logs, daemon=True)
            azure_thread.start()
            threads.append(azure_thread)
            logger.info("Azure collection thread started")
        
        logger.info(f"Started {len(threads)} collection threads")
        return threads
    
    def stop_collection(self):
        """Stop log collection"""
        self.running = False
        logger.info("Stopping log collection")
    
    def _collect_aws_logs(self):
        """Collect logs from AWS CloudWatch"""
        import time
        
        while self.running:
            try:
                events = self.aws_collector.get_recent_events(minutes=1)
                for event in events:
                    if not self.event_queue.full():
                        self.event_queue.put(event)
                    else:
                        logger.warning("Event queue is full, dropping event")
                
                time.sleep(10)  # Poll every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in AWS collection thread: {e}")
                time.sleep(30)  # Wait before retrying
    
    def _collect_azure_logs(self):
        """Collect logs from Azure Monitor"""
        import time
        
        while self.running:
            try:
                events = self.azure_collector.get_recent_events(minutes=1)
                for event in events:
                    if not self.event_queue.full():
                        self.event_queue.put(event)
                    else:
                        logger.warning("Event queue is full, dropping event")
                
                time.sleep(10)  # Poll every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in Azure collection thread: {e}")
                time.sleep(30)  # Wait before retrying
    
    def get_events(self, max_events: int = 100) -> List[Dict]:
        """
        Get collected events from the queue
        
        Args:
            max_events: Maximum number of events to retrieve
            
        Returns:
            List of security events
        """
        events = []
        count = 0
        
        while count < max_events and not self.event_queue.empty():
            try:
                event = self.event_queue.get_nowait()
                events.append(event)
                count += 1
            except queue.Empty:
                break
        
        return events
    
    def get_queue_size(self) -> int:
        """Get current size of the event queue"""
        return self.event_queue.qsize()
    
    def collect_batch(self, minutes: int = 5) -> List[Dict]:
        """
        Collect a batch of events from all sources
        
        Args:
            minutes: Number of minutes to look back
            
        Returns:
            Combined list of events from all sources
        """
        all_events = []
        
        # Collect from AWS
        if self.aws_collector:
            try:
                aws_events = self.aws_collector.get_recent_events(minutes=minutes)
                all_events.extend(aws_events)
                logger.info(f"Collected {len(aws_events)} events from AWS")
            except Exception as e:
                logger.error(f"Error collecting from AWS: {e}")
        
        # Collect from Azure
        if self.azure_collector:
            try:
                azure_events = self.azure_collector.get_recent_events(minutes=minutes)
                all_events.extend(azure_events)
                logger.info(f"Collected {len(azure_events)} events from Azure")
            except Exception as e:
                logger.error(f"Error collecting from Azure: {e}")
        
        logger.info(f"Total events collected: {len(all_events)}")
        return all_events

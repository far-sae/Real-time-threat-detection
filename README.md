# Real-Time Threat Detection Dashboard

A comprehensive real-time threat detection system that monitors security events across multi-cloud environments (AWS and Azure) using machine learning.

## 🎯 Features

- **Multi-Cloud Data Collection**: Real-time ingestion from AWS CloudWatch and Azure Monitor
- **Intelligent Preprocessing**: Automatic log normalization and feature extraction
- **ML-Powered Detection**: Random Forest classifier for threat identification
- **Smart Alerting**: Automated alert generation with severity-based prioritization
- **Interactive Dashboard**: Real-time visualization of threats and system metrics
- **Slack Integration**: Instant notifications for high-severity threats

## 📋 Components

1. **Data Collection**: Unified collector for AWS CloudWatch and Azure Monitor logs
2. **Preprocessing**: Feature extraction with 25+ security-relevant features
3. **ML Detection**: Random Forest model with confidence-based threat scoring
4. **Alert System**: Multi-level severity alerts with customizable thresholds
5. **Dashboard**: Interactive web interface with real-time charts and metrics

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- AWS account with CloudWatch access
- Azure account with Monitor access
- Valid credentials for both cloud providers

### Installation

1. Clone the repository:
```bash
cd real-time\ threat\ detection
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment:
```bash
cp .env.example .env
# Edit .env with your credentials
```

### Configuration

Edit the `.env` file with your credentials:

```bash
# AWS Configuration
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-east-1
AWS_LOG_GROUP_NAME=/aws/security/logs

# Azure Configuration
AZURE_TENANT_ID=your_azure_tenant_id
AZURE_CLIENT_ID=your_azure_client_id
AZURE_CLIENT_SECRET=your_azure_client_secret
AZURE_SUBSCRIPTION_ID=your_azure_subscription_id
AZURE_WORKSPACE_ID=your_log_analytics_workspace_id

# Alert Settings (Optional)
SLACK_WEBHOOK_URL=your_slack_webhook_url
ALERT_EMAIL=security-team@example.com
```

### Running the System

Start the complete system:
```bash
python main.py
```

The dashboard will be available at: http://localhost:8050

## 📊 Dashboard Features

- **Real-time Metrics**: Total alerts by severity level
- **Timeline Visualization**: Threat trends over time
- **Distribution Charts**: Severity and source breakdowns
- **Recent Alerts Table**: Latest security events
- **System Health**: Current system status and statistics

## 🔧 System Architecture

```
┌─────────────────────────────────────────────────────┐
│              Data Collection Layer                   │
│  ┌──────────────┐        ┌──────────────┐          │
│  │ AWS CloudWatch│        │Azure Monitor │          │
│  └──────────────┘        └──────────────┘          │
└─────────────────┬───────────────┬──────────────────┘
                  │               │
                  ▼               ▼
         ┌────────────────────────────────┐
         │    Unified Collector            │
         └────────────┬───────────────────┘
                      │
                      ▼
         ┌────────────────────────────────┐
         │    Preprocessing Pipeline       │
         │  • Feature Extraction           │
         │  • Normalization                │
         └────────────┬───────────────────┘
                      │
                      ▼
         ┌────────────────────────────────┐
         │    ML Threat Detector           │
         │  • Random Forest Classifier     │
         │  • Confidence Scoring           │
         └────────────┬───────────────────┘
                      │
                      ▼
         ┌────────────────────────────────┐
         │    Alert Manager                │
         │  • Severity Classification      │
         │  • Multi-channel Distribution   │
         └────────────┬───────────────────┘
                      │
                      ▼
         ┌────────────────────────────────┐
         │    Interactive Dashboard        │
         │  • Real-time Visualization      │
         │  • Metrics & Analytics          │
         └────────────────────────────────┘
```

## 🧠 Machine Learning Features

The system extracts 25+ features from security logs:

### Temporal Features
- Hour of day, day of week
- Business hours detection
- Weekend/night activity flags

### Network Features
- IP address analysis
- Private/public IP classification
- IP reputation scoring
- User agent analysis

### Event Features
- Event type classification
- Success/failure patterns
- Identity verification

### Security Patterns
- SQL injection detection
- XSS attempt detection
- Path traversal detection
- Command injection detection
- Code execution detection

### Statistical Features
- Message entropy
- Complexity analysis
- Field count analysis

## 📈 Alert Severity Levels

- **CRITICAL** (95%+ confidence): Immediate investigation required
- **HIGH** (85%+ confidence): Priority review needed
- **MEDIUM** (65%+ confidence): Review during next security check
- **LOW** (<65% confidence): Log for analysis

## 🔔 Notification Channels

- **Slack**: High and critical alerts
- **Email**: Critical alerts only
- **Dashboard**: All alerts with real-time updates
- **Logs**: Complete audit trail

## 🛠️ Advanced Usage

### Batch Analysis

Run analysis on historical data:
```python
from main import ThreatDetectionSystem

system = ThreatDetectionSystem()
system.run_batch_analysis(minutes=60)
```

### Custom Model Training

Train with your own data:
```python
from ml_detection import ThreatDetector
import numpy as np

detector = ThreatDetector()
X = np.array([...])  # Your features
y = np.array([...])  # Your labels (0=normal, 1=threat)

metrics = detector.train(X, y)
```

### Programmatic Access

```python
# Get system status
status = system.get_status()

# Get alert statistics
stats = system.alert_manager.get_alert_statistics()

# Acknowledge an alert
system.alert_manager.acknowledge_alert(alert_id)
```

## 📁 Project Structure

```
real-time-threat-detection/
├── main.py                      # Main application entry point
├── config.py                    # Configuration management
├── requirements.txt             # Python dependencies
├── .env.example                 # Example environment variables
├── data_collection/             # Data ingestion modules
│   ├── aws_collector.py         # AWS CloudWatch collector
│   ├── azure_collector.py       # Azure Monitor collector
│   └── unified_collector.py     # Multi-cloud aggregator
├── preprocessing/               # Data preprocessing
│   ├── feature_extractor.py     # Feature engineering
│   └── preprocessor.py          # Log normalization
├── ml_detection/                # Machine learning
│   ├── threat_detector.py       # Random Forest model
│   └── training_data.py         # Training data generator
├── alerts/                      # Alert management
│   └── alert_manager.py         # Alert generation & distribution
├── dashboard/                   # Web dashboard
│   └── threat_dashboard.py      # Interactive UI
├── models/                      # Trained ML models (auto-generated)
└── logs/                        # Application logs (auto-generated)
```

## 🔒 Security Considerations

- Store credentials securely using environment variables
- Never commit `.env` file to version control
- Use IAM roles with minimal required permissions
- Enable encryption for data in transit
- Regularly rotate access credentials
- Monitor the monitoring system itself

## 🐛 Troubleshooting

### No events being collected
- Verify cloud credentials are correct
- Check log group/workspace names
- Ensure IAM/RBAC permissions are set
- Review firewall and network settings

### Model not detecting threats
- Retrain with production data
- Adjust confidence thresholds in config
- Review feature extraction logic
- Check for feature drift

### Dashboard not loading
- Verify port 8050 is not in use
- Check Flask configuration
- Review browser console for errors

## 📝 License

This project is licensed under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Support

For issues and questions, please open an issue in the repository.

## 🔄 Future Enhancements

- [ ] Additional cloud provider support (GCP, etc.)
- [ ] Deep learning models (LSTM, Transformer)
- [ ] Automated response actions
- [ ] Threat intelligence feed integration
- [ ] Advanced visualization options
- [ ] Mobile app for alerts
- [ ] Custom rule engine
- [ ] Integration with SIEM systems

"""
Real-time threat detection dashboard using Dash and Plotly.
"""
import dash
from dash import dcc, html, Input, Output
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
import plotly.express as px
from datetime import datetime, timedelta
import pandas as pd
from typing import List, Dict
from loguru import logger


class ThreatDashboard:
    """Interactive dashboard for visualizing security threats"""
    
    def __init__(self, alert_manager, preprocessor):
        """
        Initialize dashboard
        
        Args:
            alert_manager: AlertManager instance
            preprocessor: LogPreprocessor instance
        """
        self.alert_manager = alert_manager
        self.preprocessor = preprocessor
        
        # Initialize Dash app
        self.app = dash.Dash(
            __name__,
            external_stylesheets=[dbc.themes.DARKLY],
            suppress_callback_exceptions=True
        )
        
        # Setup layout
        self._setup_layout()
        
        # Setup callbacks
        self._setup_callbacks()
        
        logger.info("Dashboard initialized")
    
    def _setup_layout(self):
        """Setup dashboard layout"""
        self.app.layout = dbc.Container([
            # Header
            dbc.Row([
                dbc.Col([
                    html.H1("🛡️ Real-Time Threat Detection Dashboard", 
                           className="text-center mb-4 mt-4"),
                    html.Hr()
                ])
            ]),
            
            # Status Cards
            dbc.Row([
                dbc.Col([
                    self._create_status_card("Total Alerts", "total-alerts", "danger")
                ], width=3),
                dbc.Col([
                    self._create_status_card("Critical", "critical-count", "danger")
                ], width=2),
                dbc.Col([
                    self._create_status_card("High", "high-count", "warning")
                ], width=2),
                dbc.Col([
                    self._create_status_card("Medium", "medium-count", "info")
                ], width=2),
                dbc.Col([
                    self._create_status_card("Low", "low-count", "success")
                ], width=3),
            ], className="mb-4"),
            
            # Charts Row 1
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Threats Over Time"),
                        dbc.CardBody([
                            dcc.Graph(id="threats-timeline")
                        ])
                    ])
                ], width=8),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Threat Distribution"),
                        dbc.CardBody([
                            dcc.Graph(id="threat-distribution")
                        ])
                    ])
                ], width=4),
            ], className="mb-4"),
            
            # Charts Row 2
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Threats by Source"),
                        dbc.CardBody([
                            dcc.Graph(id="threats-by-source")
                        ])
                    ])
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Confidence Distribution"),
                        dbc.CardBody([
                            dcc.Graph(id="confidence-histogram")
                        ])
                    ])
                ], width=6),
            ], className="mb-4"),
            
            # Recent Alerts Table
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Recent Alerts"),
                        dbc.CardBody([
                            html.Div(id="recent-alerts-table")
                        ])
                    ])
                ])
            ], className="mb-4"),
            
            # System Health
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("System Health"),
                        dbc.CardBody([
                            html.Div(id="system-health")
                        ])
                    ])
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Processing Statistics"),
                        dbc.CardBody([
                            html.Div(id="processing-stats")
                        ])
                    ])
                ], width=6),
            ], className="mb-4"),
            
            # Auto-refresh interval
            dcc.Interval(
                id='interval-component',
                interval=5000,  # Update every 5 seconds
                n_intervals=0
            )
        ], fluid=True)
    
    def _create_status_card(self, title: str, id: str, color: str):
        """Create a status card component"""
        return dbc.Card([
            dbc.CardBody([
                html.H6(title, className="card-subtitle mb-2"),
                html.H2("0", id=id, className=f"text-{color}")
            ])
        ], color="dark", outline=True)
    
    def _setup_callbacks(self):
        """Setup dashboard callbacks"""
        
        @self.app.callback(
            [
                Output("total-alerts", "children"),
                Output("critical-count", "children"),
                Output("high-count", "children"),
                Output("medium-count", "children"),
                Output("low-count", "children"),
                Output("threats-timeline", "figure"),
                Output("threat-distribution", "figure"),
                Output("threats-by-source", "figure"),
                Output("confidence-histogram", "figure"),
                Output("recent-alerts-table", "children"),
                Output("system-health", "children"),
                Output("processing-stats", "children"),
            ],
            [Input("interval-component", "n_intervals")]
        )
        def update_dashboard(n):
            """Update all dashboard components"""
            try:
                # Get alert statistics
                stats = self.alert_manager.get_alert_statistics()
                
                # Update counts
                total = stats.get('total_alerts', 0)
                by_severity = stats.get('by_severity', {})
                
                critical = by_severity.get('critical', 0)
                high = by_severity.get('high', 0)
                medium = by_severity.get('medium', 0)
                low = by_severity.get('low', 0)
                
                # Create timeline chart
                timeline_fig = self._create_timeline_chart()
                
                # Create distribution pie chart
                distribution_fig = self._create_distribution_chart(by_severity)
                
                # Create source bar chart
                source_fig = self._create_source_chart()
                
                # Create confidence histogram
                confidence_fig = self._create_confidence_histogram()
                
                # Create recent alerts table
                alerts_table = self._create_alerts_table()
                
                # Create system health display
                health_display = self._create_health_display()
                
                # Create processing stats
                stats_display = self._create_stats_display()
                
                return (
                    str(total), str(critical), str(high), str(medium), str(low),
                    timeline_fig, distribution_fig, source_fig, confidence_fig,
                    alerts_table, health_display, stats_display
                )
                
            except Exception as e:
                logger.error(f"Error updating dashboard: {e}")
                return "0", "0", "0", "0", "0", {}, {}, {}, {}, html.Div(), html.Div(), html.Div()
    
    def _create_timeline_chart(self):
        """Create threats over time chart"""
        try:
            alerts = self.alert_manager.get_active_alerts(limit=1000)
            
            if not alerts:
                return self._empty_figure("No data available")
            
            # Convert to DataFrame
            df = pd.DataFrame(alerts)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values('timestamp')
            
            # Group by hour and severity
            df['hour'] = df['timestamp'].dt.floor('H')
            grouped = df.groupby(['hour', 'severity']).size().reset_index(name='count')
            
            fig = px.line(
                grouped, x='hour', y='count', color='severity',
                color_discrete_map={
                    'low': '#28a745',
                    'medium': '#17a2b8',
                    'high': '#ffc107',
                    'critical': '#dc3545'
                }
            )
            
            fig.update_layout(
                template='plotly_dark',
                xaxis_title='Time',
                yaxis_title='Number of Threats',
                hovermode='x unified'
            )
            
            return fig
            
        except Exception as e:
            logger.error(f"Error creating timeline chart: {e}")
            return self._empty_figure("Error loading data")
    
    def _create_distribution_chart(self, by_severity: Dict):
        """Create severity distribution pie chart"""
        try:
            if not by_severity or sum(by_severity.values()) == 0:
                return self._empty_figure("No threats detected")
            
            labels = list(by_severity.keys())
            values = list(by_severity.values())
            
            colors = {
                'low': '#28a745',
                'medium': '#17a2b8',
                'high': '#ffc107',
                'critical': '#dc3545'
            }
            
            fig = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                marker=dict(colors=[colors.get(l, '#808080') for l in labels]),
                hole=.3
            )])
            
            fig.update_layout(template='plotly_dark')
            
            return fig
            
        except Exception as e:
            logger.error(f"Error creating distribution chart: {e}")
            return self._empty_figure("Error loading data")
    
    def _create_source_chart(self):
        """Create threats by source bar chart"""
        try:
            alerts = self.alert_manager.get_active_alerts(limit=1000)
            
            if not alerts:
                return self._empty_figure("No data available")
            
            df = pd.DataFrame(alerts)
            source_counts = df['source'].value_counts().head(10)
            
            fig = go.Figure(data=[
                go.Bar(x=source_counts.index, y=source_counts.values,
                      marker_color='#17a2b8')
            ])
            
            fig.update_layout(
                template='plotly_dark',
                xaxis_title='Source',
                yaxis_title='Number of Threats'
            )
            
            return fig
            
        except Exception as e:
            logger.error(f"Error creating source chart: {e}")
            return self._empty_figure("Error loading data")
    
    def _create_confidence_histogram(self):
        """Create confidence distribution histogram"""
        try:
            alerts = self.alert_manager.get_active_alerts(limit=1000)
            
            if not alerts:
                return self._empty_figure("No data available")
            
            df = pd.DataFrame(alerts)
            
            fig = go.Figure(data=[
                go.Histogram(x=df['confidence'], nbinsx=20,
                           marker_color='#ffc107')
            ])
            
            fig.update_layout(
                template='plotly_dark',
                xaxis_title='Confidence Score',
                yaxis_title='Frequency'
            )
            
            return fig
            
        except Exception as e:
            logger.error(f"Error creating confidence histogram: {e}")
            return self._empty_figure("Error loading data")
    
    def _create_alerts_table(self):
        """Create recent alerts table"""
        try:
            alerts = self.alert_manager.get_active_alerts(limit=10)
            
            if not alerts:
                return html.P("No recent alerts", className="text-muted")
            
            table_header = [
                html.Thead(html.Tr([
                    html.Th("Time"),
                    html.Th("Severity"),
                    html.Th("Source"),
                    html.Th("Confidence"),
                    html.Th("Description")
                ]))
            ]
            
            rows = []
            for alert in alerts:
                severity_badge = {
                    'low': 'success',
                    'medium': 'info',
                    'high': 'warning',
                    'critical': 'danger'
                }
                
                timestamp = datetime.fromisoformat(alert['timestamp']).strftime('%H:%M:%S')
                
                row = html.Tr([
                    html.Td(timestamp),
                    html.Td(dbc.Badge(alert['severity'].upper(), 
                                     color=severity_badge.get(alert['severity'], 'secondary'))),
                    html.Td(alert['source']),
                    html.Td(f"{alert['confidence']*100:.1f}%"),
                    html.Td(alert['description'][:100] + "..." if len(alert['description']) > 100 
                           else alert['description'])
                ])
                rows.append(row)
            
            table_body = [html.Tbody(rows)]
            
            return dbc.Table(table_header + table_body, 
                           bordered=True, dark=True, hover=True, 
                           responsive=True, striped=True)
            
        except Exception as e:
            logger.error(f"Error creating alerts table: {e}")
            return html.P("Error loading alerts", className="text-danger")
    
    def _create_health_display(self):
        """Create system health display"""
        try:
            stats = self.alert_manager.get_alert_statistics()
            active = stats.get('active_alerts', 0)
            
            status = "🟢 Operational" if active < 10 else "🟡 Elevated" if active < 50 else "🔴 Critical"
            
            return html.Div([
                html.H5(status),
                html.P(f"Active Alerts: {active}"),
                html.P(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            ])
            
        except Exception as e:
            logger.error(f"Error creating health display: {e}")
            return html.P("Error loading health status", className="text-danger")
    
    def _create_stats_display(self):
        """Create processing statistics display"""
        try:
            stats = self.alert_manager.get_alert_statistics()
            
            return html.Div([
                html.P(f"Total Events Processed: {stats.get('total_alerts', 0)}"),
                html.P(f"Detection Rate: {self._calculate_detection_rate():.2f}%"),
                html.P(f"Average Confidence: {self._calculate_avg_confidence():.2f}")
            ])
            
        except Exception as e:
            logger.error(f"Error creating stats display: {e}")
            return html.P("Error loading statistics", className="text-danger")
    
    def _calculate_detection_rate(self):
        """Calculate threat detection rate"""
        try:
            stats = self.alert_manager.get_alert_statistics()
            total = stats.get('total_alerts', 0)
            if total == 0:
                return 0.0
            
            threats = sum(stats.get('by_severity', {}).values())
            return (threats / total) * 100
        except:
            return 0.0
    
    def _calculate_avg_confidence(self):
        """Calculate average confidence score"""
        try:
            alerts = self.alert_manager.get_active_alerts(limit=1000)
            if not alerts:
                return 0.0
            
            confidences = [a['confidence'] for a in alerts]
            return sum(confidences) / len(confidences)
        except:
            return 0.0
    
    def _empty_figure(self, message: str):
        """Create empty figure with message"""
        fig = go.Figure()
        fig.update_layout(
            template='plotly_dark',
            xaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
            yaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
            annotations=[{
                'text': message,
                'xref': 'paper',
                'yref': 'paper',
                'showarrow': False,
                'font': {'size': 14}
            }]
        )
        return fig
    
    def run(self, host: str = '0.0.0.0', port: int = 8050, debug: bool = False):
        """Run the dashboard server"""
        logger.info(f"Starting dashboard on {host}:{port}")
        self.app.run_server(host=host, port=port, debug=debug)

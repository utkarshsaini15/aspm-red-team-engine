"""
Live Chart Simulation Module
Provides real-time data streaming and visualization for security scan metrics
"""
import asyncio
import json
import random
import time
from datetime import datetime, timezone
from typing import Dict, List, AsyncGenerator
from dataclasses import dataclass, asdict
from fastapi import WebSocket, WebSocketDisconnect
import numpy as np


@dataclass
class ChartDataPoint:
    """Single data point for the live chart"""
    timestamp: float
    value: float
    label: str
    category: str = "default"


@dataclass
class ChartMetrics:
    """Metrics for the live chart simulation"""
    vulnerability_score: float
    scan_progress: float
    response_time: float
    success_rate: float
    anomaly_count: int


class LiveChartSimulator:
    """Generates realistic security scan data for live visualization"""
    
    def __init__(self):
        self.start_time = time.time()
        self.scan_phase = "initialization"
        self.phases = ["initialization", "scanning", "analysis", "reporting", "completed"]
        self.current_phase_index = 0
        self.phase_progress = 0.0
        
        # Base metrics with some randomness
        self.base_vulnerability = random.uniform(20, 40)
        self.base_response_time = random.uniform(100, 300)
        self.base_success_rate = random.uniform(85, 95)
        
    def get_current_metrics(self) -> ChartMetrics:
        """Generate current metrics based on scan phase"""
        elapsed = time.time() - self.start_time
        
        # Update phase progress
        self.phase_progress += random.uniform(0.01, 0.05)
        if self.phase_progress >= 1.0:
            self.phase_progress = 0.0
            self.current_phase_index = min(self.current_phase_index + 1, len(self.phases) - 1)
            self.scan_phase = self.phases[self.current_phase_index]
        
        # Generate metrics based on phase
        phase_multiplier = {
            "initialization": 0.1,
            "scanning": 0.6,
            "analysis": 0.8,
            "reporting": 0.95,
            "completed": 1.0
        }.get(self.scan_phase, 0.5)
        
        # Add realistic variations
        vulnerability_score = self.base_vulnerability + random.uniform(-5, 15) * phase_multiplier
        vulnerability_score = max(0, min(100, vulnerability_score))
        
        scan_progress = (self.current_phase_index + self.phase_progress) / len(self.phases) * 100
        
        response_time = self.base_response_time + random.uniform(-50, 100) * phase_multiplier
        response_time = max(50, response_time)
        
        success_rate = self.base_success_rate + random.uniform(-5, 5) * phase_multiplier
        success_rate = max(70, min(100, success_rate))
        
        anomaly_count = int(random.uniform(0, 5) * phase_multiplier)
        
        return ChartMetrics(
            vulnerability_score=vulnerability_score,
            scan_progress=scan_progress,
            response_time=response_time,
            success_rate=success_rate,
            anomaly_count=anomaly_count
        )
    
    def get_time_series_data(self, metric_name: str, points: int = 20) -> List[ChartDataPoint]:
        """Generate historical time series data for a metric"""
        current_time = time.time()
        data = []
        
        for i in range(points):
            timestamp = current_time - (points - i) * 2  # 2-second intervals
            # Generate realistic historical data
            if metric_name == "vulnerability_score":
                value = self.base_vulnerability + random.uniform(-10, 20)
            elif metric_name == "response_time":
                value = self.base_response_time + random.uniform(-100, 200)
            elif metric_name == "success_rate":
                value = self.base_success_rate + random.uniform(-10, 10)
            else:
                value = random.uniform(0, 100)
            
            data.append(ChartDataPoint(
                timestamp=timestamp,
                value=value,
                label=datetime.fromtimestamp(timestamp).strftime("%H:%M:%S"),
                category=metric_name
            ))
        
        return data


class WebSocketManager:
    """Manages WebSocket connections for real-time chart updates"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.simulator = LiveChartSimulator()
        self.is_running = False
    
    async def connect(self, websocket: WebSocket):
        """Accept and store WebSocket connection"""
        await websocket.accept()
        self.active_connections.append(websocket)
        
        # Start broadcasting if this is the first connection
        if not self.is_running and len(self.active_connections) == 1:
            self.is_running = True
            asyncio.create_task(self.broadcast_updates())
    
    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        
        # Stop broadcasting if no connections
        if not self.active_connections:
            self.is_running = False
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to specific WebSocket"""
        await websocket.send_text(message)
    
    async def broadcast(self, message: str):
        """Broadcast message to all connected WebSockets"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                disconnected.append(connection)
        
        # Remove disconnected connections
        for conn in disconnected:
            self.disconnect(conn)
    
    async def broadcast_updates(self):
        """Continuously broadcast chart updates"""
        while self.is_running and self.active_connections:
            try:
                # Get current metrics
                metrics = self.simulator.get_current_metrics()
                
                # Create update message
                update_data = {
                    "type": "metrics_update",
                    "timestamp": time.time(),
                    "data": asdict(metrics),
                    "phase": self.simulator.scan_phase,
                    "phase_progress": self.simulator.phase_progress
                }
                
                await self.broadcast(json.dumps(update_data))
                await asyncio.sleep(1)  # Update every second
                
            except Exception as e:
                print(f"Error broadcasting updates: {e}")
                break


# Global WebSocket manager instance
websocket_manager = WebSocketManager()


async def get_chart_data(metric: str = "vulnerability_score", points: int = 20) -> Dict:
    """Get chart data for a specific metric"""
    simulator = LiveChartSimulator()
    data = simulator.get_time_series_data(metric, points)
    
    return {
        "metric": metric,
        "data": [asdict(point) for point in data],
        "current_phase": simulator.scan_phase,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


async def get_all_metrics() -> Dict:
    """Get all current metrics"""
    simulator = LiveChartSimulator()
    metrics = simulator.get_current_metrics()
    
    return {
        "metrics": asdict(metrics),
        "phase": simulator.scan_phase,
        "phase_progress": simulator.phase_progress,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

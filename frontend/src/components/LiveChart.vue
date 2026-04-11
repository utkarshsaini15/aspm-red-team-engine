<template>
  <div class="live-chart-container">
    <div class="chart-header">
      <h2>Live Security Scan Metrics</h2>
      <div class="status-indicators">
        <div class="indicator" :class="{ active: isConnected }">
          <span class="dot"></span>
          {{ isConnected ? 'Connected' : 'Disconnected' }}
        </div>
        <div class="phase-indicator">
          Phase: {{ currentPhase }}
        </div>
      </div>
    </div>

    <div class="metrics-grid">
      <div class="metric-card">
        <h3>Vulnerability Score</h3>
        <div class="metric-value" :class="getSeverityClass(metrics.vulnerability_score)">
          {{ metrics.vulnerability_score.toFixed(1) }}%
        </div>
        <canvas ref="vulnerabilityChart"></canvas>
      </div>

      <div class="metric-card">
        <h3>Scan Progress</h3>
        <div class="metric-value">
          {{ metrics.scan_progress.toFixed(1) }}%
        </div>
        <div class="progress-bar">
          <div class="progress-fill" :style="{ width: metrics.scan_progress + '%' }"></div>
        </div>
      </div>

      <div class="metric-card">
        <h3>Response Time</h3>
        <div class="metric-value" :class="getResponseTimeClass(metrics.response_time)">
          {{ metrics.response_time.toFixed(0) }}ms
        </div>
        <canvas ref="responseChart"></canvas>
      </div>

      <div class="metric-card">
        <h3>Success Rate</h3>
        <div class="metric-value" :class="getSuccessRateClass(metrics.success_rate)">
          {{ metrics.success_rate.toFixed(1) }}%
        </div>
        <canvas ref="successChart"></canvas>
      </div>

      <div class="metric-card">
        <h3>Anomaly Count</h3>
        <div class="metric-value" :class="getAnomalyClass(metrics.anomaly_count)">
          {{ metrics.anomaly_count }}
        </div>
        <canvas ref="anomalyChart"></canvas>
      </div>

      <div class="metric-card">
        <h3>Phase Progress</h3>
        <div class="phase-steps">
          <div 
            v-for="(phase, index) in phases" 
            :key="phase"
            class="phase-step"
            :class="{ 
              active: index === currentPhaseIndex,
              completed: index < currentPhaseIndex 
            }"
          >
            {{ phase }}
          </div>
        </div>
      </div>
    </div>

    <div class="controls">
      <button @click="toggleConnection" :class="{ active: isConnected }">
        {{ isConnected ? 'Stop' : 'Start' }} Live Updates
      </button>
      <button @click="clearCharts">Clear Charts</button>
      <button @click="exportData">Export Data</button>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, onUnmounted } from 'vue'
import Chart from 'chart.js/auto'

export default {
  name: 'LiveChart',
  setup() {
    const isConnected = ref(false)
    const websocket = ref(null)
    const currentPhase = ref('initialization')
    const currentPhaseIndex = ref(0)
    const phaseProgress = ref(0)
    
    const metrics = ref({
      vulnerability_score: 0,
      scan_progress: 0,
      response_time: 0,
      success_rate: 100,
      anomaly_count: 0
    })

    const phases = [
      'initialization',
      'scanning', 
      'analysis',
      'reporting',
      'completed'
    ]

    const charts = ref({
      vulnerability: null,
      response: null,
      success: null,
      anomaly: null
    })

    const chartData = ref({
      vulnerability: [],
      response: [],
      success: [],
      anomaly: []
    })

    // Chart refs
    const vulnerabilityChart = ref(null)
    const responseChart = ref(null)
    const successChart = ref(null)
    const anomalyChart = ref(null)

    const initCharts = () => {
      const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            display: true,
            title: { display: false }
          },
          y: {
            display: true,
            beginAtZero: true
          }
        },
        plugins: {
          legend: { display: false }
        },
        animation: {
          duration: 0
        }
      }

      // Vulnerability Chart
      if (vulnerabilityChart.value) {
        charts.value.vulnerability = new Chart(vulnerabilityChart.value, {
          type: 'line',
          data: {
            labels: [],
            datasets: [{
              data: [],
              borderColor: '#ef4444',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              tension: 0.4
            }]
          },
          options: {
            ...chartOptions,
            scales: {
              ...chartOptions.scales,
              y: { ...chartOptions.scales.y, max: 100 }
            }
          }
        })
      }

      // Response Time Chart
      if (responseChart.value) {
        charts.value.response = new Chart(responseChart.value, {
          type: 'line',
          data: {
            labels: [],
            datasets: [{
              data: [],
              borderColor: '#3b82f6',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              tension: 0.4
            }]
          },
          options: {
            ...chartOptions,
            scales: {
              ...chartOptions.scales,
              y: { ...chartOptions.scales.y, max: 500 }
            }
          }
        })
      }

      // Success Rate Chart
      if (successChart.value) {
        charts.value.success = new Chart(successChart.value, {
          type: 'line',
          data: {
            labels: [],
            datasets: [{
              data: [],
              borderColor: '#10b981',
              backgroundColor: 'rgba(16, 185, 129, 0.1)',
              tension: 0.4
            }]
          },
          options: {
            ...chartOptions,
            scales: {
              ...chartOptions.scales,
              y: { ...chartOptions.scales.y, max: 100 }
            }
          }
        })
      }

      // Anomaly Chart
      if (anomalyChart.value) {
        charts.value.anomaly = new Chart(anomalyChart.value, {
          type: 'bar',
          data: {
            labels: [],
            datasets: [{
              data: [],
              borderColor: '#f59e0b',
              backgroundColor: 'rgba(245, 158, 11, 0.5)'
            }]
          },
          options: {
            ...chartOptions,
            scales: {
              ...chartOptions.scales,
              y: { ...chartOptions.scales.y, max: 10 }
            }
          }
        })
      }
    }

    const updateChart = (chartType, value, timestamp) => {
      const chart = charts.value[chartType]
      if (!chart) return

      const data = chartData.value[chartType]
      data.push(value)
      
      // Keep only last 20 data points
      if (data.length > 20) {
        data.shift()
      }

      chart.data.labels = data.map((_, i) => {
        const time = new Date(Date.now() - (data.length - i - 1) * 1000)
        return time.toLocaleTimeString()
      })
      chart.data.datasets[0].data = data
      chart.update('none')
    }

    const connectWebSocket = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsUrl = `${protocol}//${window.location.host}/ws/live-chart`
      
      websocket.value = new WebSocket(wsUrl)
      
      websocket.value.onopen = () => {
        isConnected.value = true
        console.log('WebSocket connected')
      }
      
      websocket.value.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          
          if (data.type === 'metrics_update') {
            metrics.value = data.data
            currentPhase.value = data.phase
            phaseProgress.value = data.phase_progress
            currentPhaseIndex.value = phases.indexOf(data.phase)
            
            const timestamp = new Date().toLocaleTimeString()
            updateChart('vulnerability', data.data.vulnerability_score, timestamp)
            updateChart('response', data.data.response_time, timestamp)
            updateChart('success', data.data.success_rate, timestamp)
            updateChart('anomaly', data.data.anomaly_count, timestamp)
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error)
        }
      }
      
      websocket.value.onclose = () => {
        isConnected.value = false
        console.log('WebSocket disconnected')
      }
      
      websocket.value.onerror = (error) => {
        console.error('WebSocket error:', error)
        isConnected.value = false
      }
    }

    const disconnectWebSocket = () => {
      if (websocket.value) {
        websocket.value.close()
        websocket.value = null
      }
      isConnected.value = false
    }

    const toggleConnection = () => {
      if (isConnected.value) {
        disconnectWebSocket()
      } else {
        connectWebSocket()
      }
    }

    const clearCharts = () => {
      Object.values(charts.value).forEach(chart => {
        if (chart) {
          chart.data.labels = []
          chart.data.datasets[0].data = []
          chart.update()
        }
      })
      
      Object.keys(chartData.value).forEach(key => {
        chartData.value[key] = []
      })
    }

    const exportData = () => {
      const exportObj = {
        metrics: metrics.value,
        currentPhase: currentPhase.value,
        phaseProgress: phaseProgress.value,
        chartData: chartData.value,
        timestamp: new Date().toISOString()
      }
      
      const dataStr = JSON.stringify(exportObj, null, 2)
      const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr)
      
      const exportFileDefaultName = `live-chart-data-${Date.now()}.json`
      
      const linkElement = document.createElement('a')
      linkElement.setAttribute('href', dataUri)
      linkElement.setAttribute('download', exportFileDefaultName)
      linkElement.click()
    }

    // Helper classes for styling
    const getSeverityClass = (score) => {
      if (score < 30) return 'low'
      if (score < 70) return 'medium'
      return 'high'
    }

    const getResponseTimeClass = (time) => {
      if (time < 200) return 'good'
      if (time < 400) return 'okay'
      return 'slow'
    }

    const getSuccessRateClass = (rate) => {
      if (rate > 90) return 'excellent'
      if (rate > 80) return 'good'
      return 'poor'
    }

    const getAnomalyClass = (count) => {
      if (count === 0) return 'none'
      if (count < 3) return 'few'
      return 'many'
    }

    onMounted(() => {
      initCharts()
      // Auto-connect on mount
      connectWebSocket()
    })

    onUnmounted(() => {
      disconnectWebSocket()
      Object.values(charts.value).forEach(chart => {
        if (chart) chart.destroy()
      })
    })

    return {
      isConnected,
      currentPhase,
      currentPhaseIndex,
      phaseProgress,
      metrics,
      phases,
      vulnerabilityChart,
      responseChart,
      successChart,
      anomalyChart,
      toggleConnection,
      clearCharts,
      exportData,
      getSeverityClass,
      getResponseTimeClass,
      getSuccessRateClass,
      getAnomalyClass
    }
  }
}
</script>

<style scoped>
.live-chart-container {
  padding: 20px;
  background: #f8fafc;
  border-radius: 12px;
  min-height: 100vh;
}

.chart-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.chart-header h2 {
  font-size: 24px;
  font-weight: 600;
  color: #1e293b;
  margin: 0;
}

.status-indicators {
  display: flex;
  gap: 16px;
  align-items: center;
}

.indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: white;
  border-radius: 20px;
  font-size: 14px;
  color: #64748b;
  border: 1px solid #e2e8f0;
}

.indicator.active {
  color: #10b981;
  border-color: #10b981;
}

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #64748b;
}

.indicator.active .dot {
  background: #10b981;
  animation: pulse 2s infinite;
}

.phase-indicator {
  padding: 8px 12px;
  background: #3b82f6;
  color: white;
  border-radius: 20px;
  font-size: 14px;
  font-weight: 500;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
  margin-bottom: 24px;
}

.metric-card {
  background: white;
  padding: 20px;
  border-radius: 12px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  border: 1px solid #e2e8f0;
}

.metric-card h3 {
  font-size: 16px;
  font-weight: 600;
  color: #475569;
  margin: 0 0 12px 0;
}

.metric-value {
  font-size: 32px;
  font-weight: 700;
  margin-bottom: 16px;
  color: #1e293b;
}

.metric-value.low { color: #10b981; }
.metric-value.medium { color: #f59e0b; }
.metric-value.high { color: #ef4444; }

.metric-value.good { color: #10b981; }
.metric-value.okay { color: #f59e0b; }
.metric-value.slow { color: #ef4444; }

.metric-value.excellent { color: #10b981; }
.metric-value.good { color: #3b82f6; }
.metric-value.poor { color: #ef4444; }

.metric-value.none { color: #10b981; }
.metric-value.few { color: #f59e0b; }
.metric-value.many { color: #ef4444; }

.progress-bar {
  width: 100%;
  height: 8px;
  background: #e2e8f0;
  border-radius: 4px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #3b82f6, #10b981);
  transition: width 0.3s ease;
}

.phase-steps {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.phase-step {
  padding: 8px 12px;
  background: #f1f5f9;
  border-radius: 8px;
  font-size: 14px;
  color: #64748b;
  border-left: 3px solid transparent;
  transition: all 0.3s ease;
}

.phase-step.active {
  background: #dbeafe;
  color: #1e40af;
  border-left-color: #3b82f6;
  font-weight: 500;
}

.phase-step.completed {
  background: #dcfce7;
  color: #166534;
  border-left-color: #10b981;
}

canvas {
  max-height: 150px;
}

.controls {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.controls button {
  padding: 12px 24px;
  border: none;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
}

.controls button:first-child {
  background: #3b82f6;
  color: white;
}

.controls button:first-child:hover {
  background: #2563eb;
}

.controls button:first-child.active {
  background: #ef4444;
}

.controls button:first-child.active:hover {
  background: #dc2626;
}

.controls button:not(:first-child) {
  background: white;
  color: #475569;
  border: 1px solid #e2e8f0;
}

.controls button:not(:first-child):hover {
  background: #f8fafc;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

@media (max-width: 768px) {
  .chart-header {
    flex-direction: column;
    gap: 16px;
    align-items: flex-start;
  }
  
  .metrics-grid {
    grid-template-columns: 1fr;
  }
  
  .controls {
    flex-direction: column;
  }
  
  .controls button {
    width: 100%;
  }
}
</style>

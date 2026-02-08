import { useState, useEffect } from 'react'
import './App.css'
import Dashboard from './components/Dashboard'
import ThreatFeed from './components/ThreatFeed'
import Statistics from './components/Statistics'
import ForensicReports from './components/ForensicReports'
import NetworkMap from './components/NetworkMap'
import Modal from './components/Modal'
import AlertPanel from './components/AlertPanel'
import SystemControl from './components/SystemControl'
import ConfigEditor from './components/ConfigEditor'
import EvidenceBrowser from './components/EvidenceBrowser'

const API_URL = 'http://10.97.239.162:8000/api'

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [threats, setThreats] = useState([])
  const [stats, setStats] = useState({
    threatsDetected: 0,
    evidencePreserved: 0,
    systemsMonitored: 1,
    activeAlerts: 0
  })
  const [networkData, setNetworkData] = useState(null)
  const [systemInfo, setSystemInfo] = useState(null)
  const [isOnline, setIsOnline] = useState(false)

  // Modal State
  const [modalOpen, setModalOpen] = useState(false)
  const [modalTitle, setModalTitle] = useState('')
  const [modalContent, setModalContent] = useState(null)

  // Fetch dashboard data
  const fetchDashboardData = async () => {
    try {
      const response = await fetch(`${API_URL}/dashboard`)
      const data = await response.json()

      setStats({
        threatsDetected: data.stats.threats_detected,
        evidencePreserved: data.stats.evidence_preserved,
        systemsMonitored: data.stats.systems_monitored,
        activeAlerts: data.stats.active_alerts
      })

      setThreats(data.threats || [])
      setNetworkData(data.network)
      setIsOnline(true)
    } catch (error) {
      console.log('Backend offline...')
      setIsOnline(false)
    }
  }

  // Fetch system info
  const fetchSystemInfo = async () => {
    try {
      const response = await fetch(`${API_URL}/system`)
      const data = await response.json()
      setSystemInfo(data)
    } catch (error) {
      console.log('System info unavailable')
    }
  }

  // Initial fetch
  useEffect(() => {
    fetchDashboardData()
    fetchSystemInfo()
  }, [])

  // Real-time updates every 2s
  useEffect(() => {
    const interval = setInterval(fetchDashboardData, 2000)
    return () => clearInterval(interval)
  }, [])

  // HANDLER FOR "INVESTIGATE" BUTTON
  const handleInvestigate = (threat) => {
    if (!threat) return;

    setModalTitle(`🔍 Investigation: ${threat.id || 'Unknown Threat'}`);
    setModalContent(
      <div className="investigation-modal">
        <div className="investigation-header">
          <span className={`badge ${threat.severity || 'medium'}`}>
            {threat.severity ? threat.severity.toUpperCase() : 'UNKNOWN'}
          </span>
          <span className="timestamp">{threat.timestamp}</span>
        </div>

        <div className="section">
          <h4>Threat Type</h4>
          <p>{threat.title || threat.type}</p>
        </div>

        <div className="section">
          <h4>Description</h4>
          <p>{threat.description}</p>
        </div>

        <div className="section">
          <h4>Source Context</h4>
          <pre className="code-block">
            Source: {threat.source || 'N/A'}
            Incident ID: {threat.id}
          </pre>
        </div>

        <div className="actions">
          <button className="btn-primary" onClick={() => setActiveTab('reports')}>View Full Report</button>
          <button className="btn-secondary" onClick={() => setModalOpen(false)}>Close Case</button>
        </div>

        <style jsx>{`
            .investigation-header { display: flex; justify-content: space-between; margin-bottom: 20px; }
            .badge { padding: 4px 12px; border-radius: 4px; font-weight: bold; background: #333; }
            .badge.critical { background: rgba(248, 81, 73, 0.2); color: #f85149; }
            .section { margin-bottom: 15px; }
            h4 { color: #8b949e; margin-bottom: 5px; font-size: 0.85em; text-transform: uppercase; }
            p { color: #c9d1d9; }
            .code-block { background: #0d1117; padding: 10px; border-radius: 6px; color: #58a6ff; }
            .actions { display: flex; gap: 10px; margin-top: 20px; }
            .btn-primary { background: #238636; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; }
            .btn-secondary { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; padding: 8px 16px; border-radius: 6px; cursor: pointer; }
         `}</style>
      </div>
    );
    setModalOpen(true);
  };

  return (
    <div className="app-container">
      {/* SIDEBAR NAVIGATION */}
      <nav className="sidebar">
        <div className="sidebar-header">
          <div className="logo-icon">🛡️</div>
          <div className="logo-text">
            <span>SHADOW</span>NET
            <span className="version">v3.0</span>
          </div>
        </div>

        <div className="nav-menu">
          <button
            className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <span className="icon">📊</span> Live Operations
          </button>

          <button
            className={`nav-item ${activeTab === 'control' ? 'active' : ''}`}
            onClick={() => setActiveTab('control')}
          >
            <span className="icon">⚙️</span> Active Defense
          </button>

          <button
            className={`nav-item ${activeTab === 'reports' ? 'active' : ''}`}
            onClick={() => setActiveTab('reports')}
          >
            <span className="icon">📁</span> Case Files
          </button>

          <button
            className={`nav-item ${activeTab === 'evidence' ? 'active' : ''}`}
            onClick={() => setActiveTab('evidence')}
          >
            <span className="icon">📦</span> Evidence Locker
          </button>

          <button
            className={`nav-item ${activeTab === 'network' ? 'active' : ''}`}
            onClick={() => setActiveTab('network')}
          >
            <span className="icon">🌐</span> Network Intel
          </button>

          <div style={{ marginTop: 'auto' }}></div>

          <button
            className={`nav-item ${activeTab === 'config' ? 'active' : ''}`}
            onClick={() => setActiveTab('config')}
          >
            <span className="icon">🔧</span> Configuration
          </button>
        </div>

        <div className="system-status">
          <div className="status-header">SYSTEM INTEGRITY</div>
          <div className="status-row">
            <span>Status</span>
            <span className={isOnline ? "online" : "offline"}>
              {isOnline ? "ACTIVE" : "OFFLINE"}
            </span>
          </div>
          <div className="status-row">
            <span>Host</span>
            <span>{systemInfo?.hostname || 'Unknown'}</span>
          </div>
          <div className="status-row">
            <span>Mode</span>
            <span>{systemInfo?.is_admin ? "ADMIN" : "USER"}</span>
          </div>
        </div>
      </nav>

      {/* MAIN CONTENT */}
      <main className="main-content">
        <header className="top-bar">
          <div className="breadcrumb">
            SYSTEM // {activeTab.toUpperCase()}
          </div>
          <div className="alert-ticker">
            {stats.activeAlerts > 0 ? (
              <span className="high-severity">🚨 {stats.activeAlerts} Active Threats Detected</span>
            ) : (
              <span className="normal">✅ All Systems Nominal</span>
            )}
          </div>
        </header>

        <div className="content-area">
          {activeTab === 'dashboard' && (
            <div className="dashboard-grid">
              <Statistics stats={stats} />
              <div className="split-view">
                <ThreatFeed threats={threats} onInvestigate={handleInvestigate} />
                <AlertPanel stats={stats} />
              </div>
            </div>
          )}

          {activeTab === 'reports' && (
            <ForensicReports apiUrl={API_URL} />
          )}

          {activeTab === 'network' && (
            <div className="network-view">
              <NetworkMap data={networkData} />
            </div>
          )}

          {activeTab === 'control' && (
            <SystemControl apiUrl={API_URL} />
          )}

          {activeTab === 'config' && (
            <ConfigEditor apiUrl={API_URL} />
          )}

          {activeTab === 'evidence' && (
            <EvidenceBrowser apiUrl={API_URL} />
          )}
        </div>
      </main>

      {modalOpen && (
        <Modal
          title={modalTitle}
          content={modalContent}
          onClose={() => setModalOpen(false)}
        />
      )}
    </div>
  )
}

export default App

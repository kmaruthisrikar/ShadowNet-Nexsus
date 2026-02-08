import React from 'react'

function AlertPanel({ stats, onAction }) {
    // Use real stats from API
    const alertCount = stats?.activeAlerts || 0
    const threatCount = stats?.threatsDetected || 0

    return (
        <div className="card">
            <div className="card-header">
                <h2 className="card-title">🔔 System Status</h2>
            </div>

            <div className="alert-list">
                {alertCount > 0 ? (
                    <div className="alert-item high">
                        <div className="alert-icon">🚨</div>
                        <div className="alert-content">
                            <div className="alert-title">{alertCount} Active Alerts</div>
                            <div className="alert-time">Monitoring in progress</div>
                        </div>
                        <button className="btn btn-primary" onClick={() => onAction('alerts')}>View</button>
                    </div>
                ) : (
                    <div className="alert-item info">
                        <div className="alert-icon">✅</div>
                        <div className="alert-content">
                            <div className="alert-title">System Healthy</div>
                            <div className="alert-time">No active alerts</div>
                        </div>
                    </div>
                )}

                {threatCount > 0 && (
                    <div className="alert-item medium">
                        <div className="alert-icon">⚠️</div>
                        <div className="alert-content">
                            <div className="alert-title">{threatCount} Threats Detected</div>
                            <div className="alert-time">Total since start</div>
                        </div>
                        <button className="btn btn-primary" onClick={() => onAction('threats')}>Investigate</button>
                    </div>
                )}

                <div className="alert-item info">
                    <div className="alert-icon">🛡️</div>
                    <div className="alert-content">
                        <div className="alert-title">Protection Active</div>
                        <div className="alert-time">All modules running</div>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default AlertPanel

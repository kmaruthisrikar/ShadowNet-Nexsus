import React from 'react';

const Statistics = ({ stats }) => {
    return (
        <div className="stats-container">
            <div className="stat-card">
                <div className="stat-header">
                    <span>🚨 Threats Detected</span>
                </div>
                <div className="stat-value">{stats.threatsDetected}</div>
            </div>

            <div className="stat-card">
                <div className="stat-header">
                    <span>💾 Evidence Preserved</span>
                </div>
                <div className="stat-value">{stats.evidencePreserved}</div>
            </div>

            <div className="stat-card">
                <div className="stat-header">
                    <span>🖥️ Systems Active</span>
                </div>
                <div className="stat-value">{stats.systemsMonitored}</div>
            </div>

            <div className="stat-card">
                <div className="stat-header">
                    <span>🔔 Active Alerts</span>
                </div>
                <div className="stat-value">{stats.activeAlerts}</div>
            </div>
        </div>
    );
};

export default Statistics;

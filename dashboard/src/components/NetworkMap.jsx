import React from 'react'

function NetworkMap({ networkData }) {
    // Use real network data from API
    const activeConnections = networkData?.active_connections || 0
    const blockedIPs = networkData?.blocked || 0
    const suspicious = networkData?.suspicious || 0

    return (
        <div className="card">
            <div className="card-header">
                <h2 className="card-title">🌐 Network Activity</h2>
            </div>

            <div className="network-stats">
                <div className="network-stat">
                    <div className="stat-icon">📊</div>
                    <div className="stat-info">
                        <div className="stat-number">{activeConnections}</div>
                        <div className="stat-text">Active Connections</div>
                    </div>
                </div>

                <div className="network-stat">
                    <div className="stat-icon">🚫</div>
                    <div className="stat-info">
                        <div className="stat-number">{blockedIPs}</div>
                        <div className="stat-text">Blocked IPs</div>
                    </div>
                </div>

                <div className="network-stat">
                    <div className="stat-icon">⚠️</div>
                    <div className="stat-info">
                        <div className="stat-number">{suspicious}</div>
                        <div className="stat-text">Suspicious</div>
                    </div>
                </div>
            </div>

            <div className="network-activity">
                {activeConnections > 0 ? (
                    <>
                        <div className="activity-item">
                            <span className="activity-dot green"></span>
                            <span>{activeConnections} active network connections</span>
                        </div>
                        {suspicious > 0 && (
                            <div className="activity-item">
                                <span className="activity-dot red"></span>
                                <span>{suspicious} suspicious connections detected</span>
                            </div>
                        )}
                        {blockedIPs > 0 && (
                            <div className="activity-item">
                                <span className="activity-dot yellow"></span>
                                <span>{blockedIPs} IPs blocked by firewall</span>
                            </div>
                        )}
                    </>
                ) : (
                    <div className="activity-item">
                        <span className="activity-dot green"></span>
                        <span>Network monitoring active - no threats detected</span>
                    </div>
                )}
            </div>
        </div>
    )
}

export default NetworkMap

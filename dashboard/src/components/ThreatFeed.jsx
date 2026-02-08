import React from 'react';

const ThreatFeed = ({ threats, onInvestigate }) => {
    const realThreats = threats || [];

    return (
        <div className="threat-feed-container">
            <div className="feed-header">
                <span>🚨 Live Threat Feed</span>
                <span className="severity-badge critical">{realThreats.length}</span>
            </div>

            <div className="threat-list">
                {realThreats.length > 0 ? (
                    realThreats.map((threat, index) => (
                        <div key={threat.id || index} className="threat-item">
                            <div className="threat-main">
                                <span className="threat-title">{threat.title || threat.type}</span>
                                <span className={`severity-badge ${threat.severity || 'medium'}`}>
                                    {(threat.severity || 'medium').toUpperCase()}
                                </span>
                            </div>

                            <span className="threat-desc">
                                {threat.description || 'No detailed description available.'}
                            </span>

                            <div className="threat-meta">
                                <span>⏱️ {new Date(threat.timestamp).toLocaleTimeString()}</span>
                                <span>💻 {threat.source || 'Unknown Host'}</span>

                                <button
                                    className="action-btn"
                                    onClick={() => onInvestigate && onInvestigate(threat)}
                                >
                                    INVESTIGATE
                                </button>
                            </div>
                        </div>
                    ))
                ) : (
                    <div style={{ padding: '40px', textAlign: 'center', color: '#8b949e' }}>
                        <div style={{ fontSize: '2em', marginBottom: '10px' }}>✅</div>
                        <div>No Active Threats Detected</div>
                        <div style={{ fontSize: '0.8em', marginTop: '5px' }}>System is secure</div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ThreatFeed;

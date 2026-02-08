import React, { useState } from 'react';

const SystemControl = ({ apiUrl }) => {
    const [output, setOutput] = useState('');
    const [loading, setLoading] = useState(false);

    const runAction = async (actionType) => {
        setLoading(true);
        setOutput(`[SYS] Initiating ${actionType}...`);

        try {
            const response = await fetch(`${apiUrl}/test/execute`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: actionType })
            });

            const data = await response.json();

            if (data.success) {
                setOutput(prev => prev + `\n[SUCCESS] Command executed successfully.\n[INFO] Monitor the Dashboard for detection alerts.`);
            } else {
                setOutput(prev => prev + `\n[ERROR] ${data.error}`);
            }
        } catch (error) {
            setOutput(prev => prev + `\n[FATAL] Connection failed: ${error.message}`);
        }

        setLoading(false);
    };

    const clearLogs = () => {
        setOutput("[SYS] Clearing local console logs...\n[SYS] Ready.");
    };

    return (
        <div className="control-panel">
            <div className="control-grid">

                {/* ATTACK SIMULATION CARD */}
                <div className="control-card danger">
                    <div className="card-header">
                        <h3>⚔️ Attack Simulations</h3>
                        <span className="badge">LIVE FIRE</span>
                    </div>
                    <p>Execute real-world attack patterns on the host to validate detection logic.</p>
                    <div className="button-group">
                        <button className="btn-danger" onClick={() => runAction('ransomware_sim')} disabled={loading}>
                            Run Ransomware Sim
                        </button>
                        <button className="btn-warning" onClick={() => runAction('obfuscation_sim')} disabled={loading}>
                            Run Obfuscation Test
                        </button>
                        <button className="btn-warning" onClick={() => runAction('network_sim')} disabled={loading}>
                            Run C2 Network Beacon
                        </button>
                    </div>
                </div>

                {/* SYSTEM MAINTENANCE CARD */}
                <div className="control-card">
                    <div className="card-header">
                        <h3>🛠️ System Maintenance</h3>
                        <span className="badge info">OPS</span>
                    </div>
                    <p>Manage system state, evidence storage, and logging.</p>
                    <div className="button-group">
                        <button className="btn-primary" onClick={clearLogs}>Clear Console</button>
                        <button className="btn-secondary" disabled>Purge Old Evidence</button>
                        <button className="btn-secondary" disabled>Restart Services</button>
                    </div>
                </div>

            </div>

            {/* CONSOLE OUTPUT */}
            <div className="console-output">
                <div className="console-header">SYSTEM OUTPUT //</div>
                <pre>{output || "[SYS] Ready for commands..."}</pre>
                {loading && <div className="loading-line"></div>}
            </div>

            <style jsx>{`
        .control-panel {
          display: flex;
          flex-direction: column;
          gap: 20px;
          height: 100%;
        }

        .control-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 20px;
        }

        .control-card {
          background: #161b22;
          border: 1px solid #30363d;
          border-radius: 8px;
          padding: 20px;
          display: flex;
          flex-direction: column;
          gap: 15px;
        }
        
        .control-card.danger {
          border-left: 3px solid #f85149;
        }

        .card-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .card-header h3 {
          margin: 0;
          color: #e6edf3;
          font-size: 1.1em;
        }

        .badge {
          background: #30363d;
          padding: 2px 8px;
          border-radius: 12px;
          font-size: 0.7em;
          font-weight: 600;
          color: #8b949e;
        }
        
        .badge.info { color: #58a6ff; background: rgba(88, 166, 255, 0.1); }

        p {
          color: #8b949e;
          font-size: 0.9em;
          line-height: 1.5;
          margin: 0;
        }

        .button-group {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          margin-top: auto;
        }

        button {
          padding: 8px 16px;
          border-radius: 6px;
          border: 1px solid transparent;
          cursor: pointer;
          font-weight: 500;
          font-size: 0.9em;
          transition: all 0.2s;
        }

        .btn-danger {
          background: rgba(248, 81, 73, 0.1);
          color: #f85149;
          border-color: rgba(248, 81, 73, 0.4);
        }
        .btn-danger:hover {
          background: #f85149;
          color: white;
        }

        .btn-warning {
          background: rgba(210, 153, 34, 0.1);
          color: #d29922;
          border-color: rgba(210, 153, 34, 0.4);
        }
        .btn-warning:hover {
          background: #d29922;
          color: white;
        }

        .btn-primary {
          background: #238636;
          color: white;
        }
        .btn-primary:hover {
          background: #2ea043;
        }
        
        .btn-secondary {
            background: #21262d;
            color: #c9d1d9;
            border-color: #30363d;
        }

        .console-output {
          flex: 1;
          background: #010409;
          border: 1px solid #30363d;
          border-radius: 8px;
          padding: 15px;
          font-family: 'Consolas', monospace;
          overflow: hidden;
          display: flex;
          flex-direction: column;
        }
        
        .console-header {
            color: #58a6ff;
            font-size: 0.8em;
            margin-bottom: 10px;
            opacity: 0.7;
        }

        pre {
          color: #3fb950;
          margin: 0;
          white-space: pre-wrap;
          font-size: 0.9em;
        }
        
        .loading-line {
            height: 2px;
            background: #58a6ff;
            width: 100%;
            margin-top: 10px;
            animation: lineScan 2s infinite linear;
        }
        
        @keyframes lineScan {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
      `}</style>
        </div>
    );
};

export default SystemControl;

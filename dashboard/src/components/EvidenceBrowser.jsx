import React, { useState, useEffect } from 'react';

const EvidenceBrowser = ({ apiUrl }) => {
    const [artifacts, setArtifacts] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchArtifacts();
    }, []);

    const fetchArtifacts = async () => {
        try {
            const res = await fetch(`${apiUrl}/artifacts`);
            const data = await res.json();
            setArtifacts(data.artifacts || []);
            setLoading(false);
        } catch (e) {
            console.error(e);
            setLoading(false);
        }
    };

    return (
        <div className="evidence-browser">
            <div className="browser-header">
                <h3>📦 Evidence Locker (Artifacts & Malware Samples)</h3>
                <button className="refresh-btn" onClick={fetchArtifacts}>🔄 Refresh</button>
            </div>

            <div className="table-container">
                <table className="evidence-table">
                    <thead>
                        <tr>
                            <th>Filename</th>
                            <th>Incident ID</th>
                            <th>Size</th>
                            <th>Date Preserved</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {loading ? (
                            <tr><td colSpan="5" style={{ textAlign: 'center', padding: '20px' }}>Loading Evidence Vault...</td></tr>
                        ) : artifacts.length === 0 ? (
                            <tr><td colSpan="5" style={{ textAlign: 'center', padding: '20px', color: '#8b949e' }}>Evidence Vault is Empty.</td></tr>
                        ) : (
                            artifacts.map((file, i) => (
                                <tr key={i}>
                                    <td className="file-col">
                                        <span className="file-icon">📄</span>
                                        {file.filename}
                                    </td>
                                    <td className="incident-col">{file.incident_id}</td>
                                    <td>{(file.size_bytes / 1024).toFixed(2)} KB</td>
                                    <td>{new Date(file.created).toLocaleString()}</td>
                                    <td>
                                        <button className="btn-small" disabled>🔒 Locked</button>
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>

            <style jsx>{`
        .evidence-browser {
          height: 100%;
          background: #0d1117;
          border: 1px solid #30363d;
          border-radius: 6px;
          display: flex;
          flex-direction: column;
        }

        .browser-header {
          padding: 15px 20px;
          border-bottom: 1px solid #30363d;
          display: flex;
          justify-content: space-between;
          align-items: center;
          background: #161b22;
        }

        .browser-header h3 {
          margin: 0;
          color: #c9d1d9;
          font-size: 1rem;
        }

        .refresh-btn {
          background: transparent;
          border: 1px solid #30363d;
          color: #c9d1d9;
          padding: 4px 12px;
          border-radius: 6px;
          cursor: pointer;
        }

        .table-container {
          flex: 1;
          overflow-y: auto;
        }

        .evidence-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 0.9rem;
        }

        .evidence-table th {
          text-align: left;
          padding: 12px 20px;
          background: #161b22;
          color: #8b949e;
          font-weight: 600;
          border-bottom: 1px solid #30363d;
        }

        .evidence-table td {
          padding: 12px 20px;
          border-bottom: 1px solid #21262d;
          color: #c9d1d9;
        }

        .evidence-table tr:hover td {
          background: #161b22;
        }

        .file-col {
          display: flex;
          align-items: center;
          gap: 8px;
          font-family: 'Consolas', monospace;
          color: #58a6ff !important;
        }

        .incident-col {
          font-family: 'Consolas', monospace;
          color: #e3b341;
        }

        .btn-small {
          background: #21262d;
          border: 1px solid #30363d;
          color: #8b949e;
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 0.75rem;
          cursor: not-allowed;
        }
      `}</style>
        </div>
    );
};

export default EvidenceBrowser;

import React, { useState, useEffect } from 'react';

const ForensicReports = ({ apiUrl }) => {
    const [reports, setReports] = useState([]);
    const [selectedReport, setSelectedReport] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchReports();
    }, []);

    const fetchReports = async () => {
        try {
            const response = await fetch(`${apiUrl}/reports`);
            const data = await response.json();
            setReports(data.reports || []);
            setLoading(false);
        } catch (error) {
            console.error('Error fetching reports:', error);
            setLoading(false);
        }
    };

    const viewReport = async (filename) => {
        try {
            const response = await fetch(`${apiUrl}/view-report?filename=${filename}`);
            const data = await response.json();
            setSelectedReport(data);
        } catch (error) {
            console.error('Error viewing report:', error);
        }
    };

    return (
        <div className="reports-container">
            <div className="reports-sidebar">
                <h3>📂 Case Files</h3>
                <div className="report-list">
                    {loading ? (
                        <div className="loading-spinner"></div>
                    ) : reports.length === 0 ? (
                        <div className="no-data">No forensic reports generated yet.</div>
                    ) : (
                        reports.map((report) => (
                            <div
                                key={report.filename}
                                className={`report-item ${selectedReport?.filename === report.filename ? 'active' : ''}`}
                                onClick={() => viewReport(report.filename)}
                            >
                                <div className="report-icon">📄</div>
                                <div className="report-info">
                                    <div className="report-name">{report.filename}</div>
                                    <div className="report-date">{new Date(report.created).toLocaleString()}</div>
                                </div>
                            </div>
                        ))
                    )}
                </div>
            </div>

            <div className="report-viewer">
                {selectedReport ? (
                    <div className="viewer-content">
                        <div className="viewer-header">
                            <h2>{selectedReport.filename}</h2>
                            <button className="download-btn" onClick={() => window.print()}>🖨️ Print / PDF</button>
                        </div>
                        <div className="markdown-body">
                            <pre>{selectedReport.content}</pre>
                        </div>
                    </div>
                ) : (
                    <div className="viewer-placeholder">
                        <div className="placeholder-icon">📑</div>
                        <h3>Select a Forensic Report</h3>
                        <p>View detailed analysis, evidence chains, and AI verdicts.</p>
                    </div>
                )}
            </div>

            <style jsx>{`
        .reports-container {
          display: flex;
          height: calc(100vh - 100px);
          background: #0f1115;
          border: 1px solid #2a2f3a;
          border-radius: 8px;
          overflow: hidden;
        }
        
        .reports-sidebar {
          width: 300px;
          background: #161b22;
          border-right: 1px solid #2a2f3a;
          display: flex;
          flex-direction: column;
        }
        
        .reports-sidebar h3 {
          padding: 15px;
          margin: 0;
          color: #a0a8b7;
          border-bottom: 1px solid #2a2f3a;
          font-size: 0.9em;
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        
        .report-list {
          flex: 1;
          overflow-y: auto;
        }
        
        .report-item {
          display: flex;
          padding: 15px;
          border-bottom: 1px solid #222831;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .report-item:hover {
          background: #1c2128;
        }
        
        .report-item.active {
          background: #1f293a;
          border-left: 3px solid #00f0ff;
        }
        
        .report-icon {
          font-size: 1.5em;
          margin-right: 10px;
          opacity: 0.7;
        }
        
        .report-name {
          color: #e6edf3;
          font-weight: 500;
          font-size: 0.9em;
          margin-bottom: 4px;
        }
        
        .report-date {
          color: #8b949e;
          font-size: 0.75em;
        }
        
        .report-viewer {
          flex: 1;
          overflow-y: auto;
          background: #0d1117;
          padding: 30px;
        }
        
        .viewer-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
          padding-bottom: 20px;
          border-bottom: 1px solid #30363d;
        }
        
        .download-btn {
          background: #238636;
          color: white;
          border: none;
          padding: 8px 16px;
          border-radius: 6px;
          cursor: pointer;
          font-weight: 500;
        }
        
        .markdown-body pre {
          background: #161b22;
          padding: 20px;
          border-radius: 6px;
          color: #c9d1d9;
          white-space: pre-wrap;
          font-family: 'Consolas', 'Monaco', monospace;
          line-height: 1.5;
        }
        
        .viewer-placeholder {
          height: 100%;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          color: #484f58;
        }
        
        .placeholder-icon {
          font-size: 4em;
          margin-bottom: 20px;
          opacity: 0.3;
        }
      `}</style>
        </div>
    );
};

export default ForensicReports;

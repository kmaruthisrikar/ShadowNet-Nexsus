import React, { useState, useEffect } from 'react';

const ConfigEditor = ({ apiUrl }) => {
    const [configContent, setConfigContent] = useState('');
    const [status, setStatus] = useState('');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchConfig();
    }, []);

    const fetchConfig = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${apiUrl}/config`);
            const data = await res.json();
            if (data.content) {
                setConfigContent(data.content);
                setStatus('');
            } else {
                setStatus('Failed to load config.');
            }
        } catch (e) {
            setStatus('Error connecting to backend.');
        }
        setLoading(false);
    };

    const saveConfig = async () => {
        setStatus('Saving...');
        try {
            const res = await fetch(`${apiUrl}/config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: configContent })
            });
            const data = await res.json();
            if (data.success) {
                setStatus('✅ Configuration saved successfully. Restart backend to apply changes.');
            } else {
                setStatus(`❌ Error: ${data.error}`);
            }
        } catch (e) {
            setStatus(`❌ Network Error: ${e.message}`);
        }
    };

    return (
        <div className="config-editor-container">
            <div className="editor-header">
                <h3>⚙️ Global Configuration (config.yaml)</h3>
                <div className="actions">
                    <span className="status-msg">{status}</span>
                    <button className="btn-primary" onClick={saveConfig} disabled={loading}>
                        💾 Save Changes
                    </button>
                </div>
            </div>

            <div className="editor-area">
                <textarea
                    value={configContent}
                    onChange={(e) => setConfigContent(e.target.value)}
                    spellCheck="false"
                />
            </div>

            <style jsx>{`
        .config-editor-container {
          display: flex;
          flex-direction: column;
          height: 100%;
          background: #0d1117;
          border: 1px solid #30363d;
          border-radius: 6px;
          overflow: hidden;
        }

        .editor-header {
          padding: 15px 20px;
          background: #161b22;
          border-bottom: 1px solid #30363d;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .editor-header h3 {
          margin: 0;
          color: #c9d1d9;
          font-size: 1rem;
        }

        .actions {
          display: flex;
          align-items: center;
          gap: 15px;
        }
        
        .status-msg {
          font-size: 0.85rem;
          color: #8b949e;
        }

        .btn-primary {
          background: #238636;
          color: white;
          border: 1px solid rgba(240, 246, 252, 0.1);
          padding: 6px 16px;
          border-radius: 6px;
          cursor: pointer;
          font-weight: 600;
        }
        
        .btn-primary:hover {
          background: #2ea043;
        }

        .editor-area {
          flex: 1;
          display: flex;
        }

        textarea {
          flex: 1;
          background: #0d1117;
          color: #c9d1d9;
          padding: 20px;
          font-family: 'Consolas', 'Monaco', monospace;
          font-size: 14px;
          line-height: 1.5;
          border: none;
          resize: none;
          outline: none;
        }
      `}</style>
        </div>
    );
};

export default ConfigEditor;

import React from 'react';

const Footer = () => {
  return (
    <footer style={{
      position: 'fixed',
      bottom: 0,
      left: 0,
      right: 0,
      height: '60px',
      backgroundColor: '#1a1a1a',
      borderTop: '1px solid #333',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '0 20px',
      fontSize: '13px',
      color: '#888',
      zIndex: 1000
    }}>
      <div>
        © 2025 SIEM Dashboard. Real-time log monitoring and security analysis.
      </div>
      <div style={{ display: 'flex', gap: '20px' }}>
        <span>Kafka Connected</span>
        <span>OpenSearch Active</span>
        <span>Graylog Synced</span>
      </div>
    </footer>
  );
};

export default Footer;
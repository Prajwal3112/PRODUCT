import React from 'react';
import { Menu, X, Activity, Shield, Settings } from 'lucide-react';

const Header = ({ toggleSidebar, isSidebarOpen }) => {
  return (
    <header style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      height: '60px',
      backgroundColor: '#1a1a1a',
      borderBottom: '1px solid #333',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 20px',
      zIndex: 1000,
      boxShadow: '0 2px 10px rgba(0,0,0,0.1)'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
        <button
          onClick={toggleSidebar}
          style={{
            background: 'none',
            border: 'none',
            color: '#fff',
            cursor: 'pointer',
            padding: '8px',
            borderRadius: '4px',
            display: 'flex',
            alignItems: 'center',
            transition: 'background-color 0.2s'
          }}
          onMouseOver={(e) => e.target.style.backgroundColor = '#333'}
          onMouseOut={(e) => e.target.style.backgroundColor = 'transparent'}
        >
          {isSidebarOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Shield size={24} color="#00ff88" />
          <h1 style={{ 
            margin: 0, 
            color: '#fff', 
            fontSize: '20px', 
            fontWeight: '600',
            letterSpacing: '0.5px'
          }}>
            SIEM Dashboard
          </h1>
        </div>
      </div>
      
      <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
        <div style={{
          padding: '8px 12px',
          backgroundColor: '#00ff88',
          color: '#000',
          borderRadius: '20px',
          fontSize: '12px',
          fontWeight: '600',
          display: 'flex',
          alignItems: 'center',
          gap: '5px'
        }}>
          <Activity size={14} />
          ACTIVE
        </div>
        <button style={{
          background: 'none',
          border: '1px solid #555',
          color: '#fff',
          padding: '8px 15px',
          borderRadius: '6px',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          transition: 'all 0.2s'
        }}
        onMouseOver={(e) => {
          e.target.style.backgroundColor = '#333';
          e.target.style.borderColor = '#777';
        }}
        onMouseOut={(e) => {
          e.target.style.backgroundColor = 'transparent';
          e.target.style.borderColor = '#555';
        }}>
          <Settings size={16} />
          Settings
        </button>
      </div>
    </header>
  );
};

export default Header;
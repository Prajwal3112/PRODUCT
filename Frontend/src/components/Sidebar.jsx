import React, { useState } from 'react';
import { BarChart3, Database, Shield, Activity, Settings, LogOut } from 'lucide-react';

const Sidebar = ({ isOpen }) => {
  const [activeItem, setActiveItem] = useState('dashboard');

  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
    { id: 'logs', label: 'Log Analysis', icon: Database },
    { id: 'security', label: 'Security Events', icon: Shield },
    { id: 'monitoring', label: 'System Monitor', icon: Activity },
    { id: 'settings', label: 'Configuration', icon: Settings },
  ];

  return (
    <aside style={{
      position: 'fixed',
      top: '60px',
      left: isOpen ? '0' : '-250px',
      width: '250px',
      height: 'calc(100vh - 60px - 60px)', // Subtract header + footer height
      backgroundColor: '#1e1e1e',
      borderRight: '1px solid #333',
      transition: 'left 0.3s ease',
      zIndex: 999,
      overflowY: 'auto',
      display: 'flex',
      flexDirection: 'column'
    }}>
      <nav style={{ padding: '20px 0', flex: 1 }}>
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeItem === item.id;
          
          return (
            <button
              key={item.id}
              onClick={() => setActiveItem(item.id)}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '12px 20px',
                background: isActive ? '#00ff8820' : 'none',
                border: 'none',
                borderLeft: isActive ? '3px solid #00ff88' : '3px solid transparent',
                color: isActive ? '#00ff88' : '#ccc',
                cursor: 'pointer',
                fontSize: '14px',
                transition: 'all 0.2s',
                textAlign: 'left'
              }}
              onMouseOver={(e) => {
                if (!isActive) {
                  e.target.style.backgroundColor = '#2a2a2a';
                  e.target.style.color = '#fff';
                }
              }}
              onMouseOut={(e) => {
                if (!isActive) {
                  e.target.style.backgroundColor = 'transparent';
                  e.target.style.color = '#ccc';
                }
              }}
            >
              <Icon size={18} />
              {item.label}
            </button>
          );
        })}
      </nav>
      
      <div style={{
        padding: '20px',
        borderTop: '1px solid #333'
      }}>
        <button style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          padding: '12px',
          background: 'none',
          border: '1px solid #555',
          borderRadius: '6px',
          color: '#ccc',
          cursor: 'pointer',
          fontSize: '14px',
          transition: 'all 0.2s'
        }}
        onMouseOver={(e) => {
          e.target.style.backgroundColor = '#ff4444';
          e.target.style.borderColor = '#ff4444';
          e.target.style.color = '#fff';
        }}
        onMouseOut={(e) => {
          e.target.style.backgroundColor = 'transparent';
          e.target.style.borderColor = '#555';
          e.target.style.color = '#ccc';
        }}>
          <LogOut size={18} />
          Logout
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
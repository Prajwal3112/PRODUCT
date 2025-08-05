import React, { useState } from 'react';
import Header from '../components/Header';
import Sidebar from '../components/Sidebar';
import Footer from '../components/Footer';
import LogViewer from '../components/LogViewer';

const Dashboard = () => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  const toggleSidebar = () => {
    setIsSidebarOpen(!isSidebarOpen);
  };

  return (
    <div style={{
      height: '100vh',
      backgroundColor: '#0f0f0f',
      color: '#fff',
      fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
      overflow: 'hidden'
    }}>
      <Header toggleSidebar={toggleSidebar} isSidebarOpen={isSidebarOpen} />
      <Sidebar isOpen={isSidebarOpen} />
      
      {/* Main Content Area */}
      <main style={{
        position: 'fixed',
        top: '60px',
        left: isSidebarOpen ? '250px' : '0',
        right: '0',
        bottom: '60px', // Account for fixed footer
        padding: '30px',
        transition: 'left 0.3s ease',
        overflowY: 'auto',
        backgroundColor: '#0f0f0f'
      }}>
        {/* Main content area: LogViewer component */}
        <LogViewer />
      </main>
      
      <Footer />
      
      {/* Responsive overlay for mobile */}
      {isSidebarOpen && (
        <div 
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0,0,0,0.5)',
            zIndex: 998,
            display: window.innerWidth <= 768 ? 'block' : 'none'
          }}
          onClick={toggleSidebar}
        />
      )}
      
      <style>{`
        @media (max-width: 768px) {
          .sidebar {
            box-shadow: 2px 0 10px rgba(0,0,0,0.3);
          }
        }
        
        /* Scrollbar styling */
        ::-webkit-scrollbar {
          width: 6px;
        }
        
        ::-webkit-scrollbar-track {
          background: #2a2a2a;
        }
        
        ::-webkit-scrollbar-thumb {
          background: #555;
          border-radius: 3px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
          background: #777;
        }
      `}</style>
    </div>
  );
};

export default Dashboard;
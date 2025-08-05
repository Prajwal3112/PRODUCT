import React from 'react';
import { X, Filter } from 'lucide-react';

const ActiveFilters = ({ filters, onRemoveFilter, onClearAll }) => {
  if (!filters || filters.length === 0) {
    return null;
  }

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      gap: '10px',
      padding: '12px',
      background: '#0a0a0a',
      border: '1px solid #333',
      borderRadius: '6px',
      marginBottom: '15px'
    }}>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          color: '#00ff88',
          fontSize: '13px',
          fontWeight: '600'
        }}>
          <Filter size={14} />
          ACTIVE FILTERS ({filters.length})
        </div>
        
        <button
          onClick={onClearAll}
          style={{
            background: 'none',
            border: '1px solid #555',
            color: '#ff6b6b',
            padding: '4px 8px',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '11px',
            transition: 'all 0.2s'
          }}
          onMouseOver={(e) => {
            e.target.style.backgroundColor = '#ff6b6b20';
            e.target.style.borderColor = '#ff6b6b';
          }}
          onMouseOut={(e) => {
            e.target.style.backgroundColor = 'transparent';
            e.target.style.borderColor = '#555';
          }}
        >
          Clear All
        </button>
      </div>
      
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '8px'
      }}>
        {filters.map((filter, index) => (
          <div
            key={index}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              background: '#1a1a1a',
              border: '1px solid #00ff88',
              borderRadius: '15px',
              padding: '4px 10px',
              fontSize: '12px',
              color: '#00ff88'
            }}
          >
            <span style={{ 
              fontFamily: 'Monaco, Consolas, "Courier New", monospace'
            }}>
              {filter}
            </span>
            <button
              onClick={() => onRemoveFilter(index)}
              style={{
                background: 'none',
                border: 'none',
                color: '#00ff88',
                cursor: 'pointer',
                padding: '0',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transition: 'color 0.2s'
              }}
              onMouseOver={(e) => e.target.style.color = '#ff6b6b'}
              onMouseOut={(e) => e.target.style.color = '#00ff88'}
            >
              <X size={12} />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ActiveFilters;
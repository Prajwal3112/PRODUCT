import React from 'react';
import { Plus, Filter } from 'lucide-react';

const FieldFilter = ({ fieldName, fieldValue, onAddFilter, disabled = false }) => {
  // Skip certain fields that don't make sense to filter on
  const skipFields = ['indexed_at', '_index', 'message'];
  
  // Skip empty or null values
  if (!fieldValue || fieldValue === '' || skipFields.includes(fieldName)) {
    return (
      <span style={{ color: '#fff', wordBreak: 'break-word' }}>
        {typeof fieldValue === 'object' ? JSON.stringify(fieldValue) : String(fieldValue)}
      </span>
    );
  }

  const handleAddFilter = (e) => {
    e.stopPropagation();
    
    // Format the field name and value for DQL
    let dqlField = fieldName;
    let dqlValue = String(fieldValue);
    
    // Handle special cases for field names
    if (fieldName === '@timestamp') {
      dqlField = '@timestamp';
    } else if (fieldName.includes('.')) {
      // For nested fields, use as-is
      dqlField = fieldName;
    }
    
    // Handle different value types
    if (typeof fieldValue === 'string' && (fieldValue.includes(' ') || fieldValue.includes('-'))) {
      dqlValue = `"${fieldValue}"`;
    }
    
    const filterQuery = `${dqlField}: ${dqlValue}`;
    onAddFilter(filterQuery);
  };

  const isClickable = !disabled && fieldValue && String(fieldValue).trim() !== '';

  return (
    <div style={{ 
      display: 'flex', 
      alignItems: 'center', 
      gap: '6px',
      position: 'relative',
      group: 'field-filter'
    }}>
      <span style={{ 
        color: '#fff', 
        wordBreak: 'break-word',
        flex: 1
      }}>
        {typeof fieldValue === 'object' ? JSON.stringify(fieldValue) : String(fieldValue)}
      </span>
      
      {isClickable && (
        <button
          onClick={handleAddFilter}
          title={`Add filter: ${fieldName}: ${fieldValue}`}
          style={{
            background: 'none',
            border: '1px solid #555',
            color: '#00ff88',
            padding: '4px',
            borderRadius: '3px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            opacity: 0.7,
            transition: 'all 0.2s',
            minWidth: '24px',
            height: '24px'
          }}
          onMouseOver={(e) => {
            e.target.style.opacity = '1';
            e.target.style.backgroundColor = '#00ff8820';
            e.target.style.borderColor = '#00ff88';
          }}
          onMouseOut={(e) => {
            e.target.style.opacity = '0.7';
            e.target.style.backgroundColor = 'transparent';
            e.target.style.borderColor = '#555';
          }}
        >
          <Plus size={12} />
        </button>
      )}
    </div>
  );
};

export default FieldFilter;
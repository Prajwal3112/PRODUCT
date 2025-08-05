import React, { useState, useRef, useEffect } from 'react';
import { Search, X, Clock, BookOpen } from 'lucide-react';

const SearchBar = ({ onSearch, loading = false, placeholder = "Search logs using DQL syntax..." }) => {
  const [query, setQuery] = useState('');
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [recentQueries, setRecentQueries] = useState([]);
  const inputRef = useRef(null);

  // Common DQL field suggestions based on your log structure
  const fieldSuggestions = [
    { field: 'agent_name', example: 'agent_name: "Kaplesh"', description: 'Filter by agent name' },
    { field: 'rule_id', example: 'rule_id: 60642', description: 'Filter by rule ID' },
    { field: '_id', example: '_id: "oc3geJgBuR2PlYEUBuA1"', description: 'Filter by document ID' },
    { field: 'source_ip', example: 'source_ip: "192.168.1.100"', description: 'Filter by source IP' },
    { field: 'destination_ip', example: 'destination_ip: "10.0.0.1"', description: 'Filter by destination IP' },
    { field: 'severity', example: 'severity: "high"', description: 'Filter by severity level' },
    { field: 'event_type', example: 'event_type: "login"', description: 'Filter by event type' },
    { field: 'user_name', example: 'user_name: "admin"', description: 'Filter by username' },
    { field: 'rule_description', example: 'rule_description: "brute force"', description: 'Search in rule description' },
    { field: 'message', example: 'message: "failed login"', description: 'Search in message content' }
  ];

  // DQL operators
  const operators = [
    { op: 'AND', example: 'rule_id: 60642 AND severity: "high"', description: 'Both conditions must match' },
    { op: 'OR', example: 'severity: "high" OR severity: "critical"', description: 'Either condition can match' },
    { op: 'NOT', example: 'NOT severity: "low"', description: 'Exclude matching documents' },
    { op: '>', example: 'timestamp > "2025-01-01"', description: 'Greater than' },
    { op: '<', example: 'rule_id < 70000', description: 'Less than' },
    { op: '*', example: 'agent_name: Kap*', description: 'Wildcard matching' }
  ];

  // Load recent queries from localStorage on component mount
  useEffect(() => {
    const saved = localStorage.getItem('siem_recent_queries');
    if (saved) {
      try {
        setRecentQueries(JSON.parse(saved));
      } catch (e) {
        console.error('Failed to parse recent queries:', e);
      }
    }
  }, []);

  // Save query to recent queries
  const saveToRecent = (searchQuery) => {
    if (!searchQuery.trim()) return;
    
    const updated = [searchQuery, ...recentQueries.filter(q => q !== searchQuery)].slice(0, 10);
    setRecentQueries(updated);
    localStorage.setItem('siem_recent_queries', JSON.stringify(updated));
  };

  const handleSearch = () => {
    if (query.trim()) {
      saveToRecent(query.trim());
      onSearch(query.trim());
      setShowSuggestions(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleSearch();
    } else if (e.key === 'Escape') {
      setShowSuggestions(false);
    }
  };

  const insertSuggestion = (suggestion) => {
    setQuery(suggestion);
    inputRef.current?.focus();
    setShowSuggestions(false);
  };

  const clearQuery = () => {
    setQuery('');
    onSearch('');
    inputRef.current?.focus();
  };

  const clearRecentQueries = () => {
    setRecentQueries([]);
    localStorage.removeItem('siem_recent_queries');
  };

  return (
    <div style={{ position: 'relative', width: '100%' }}>
      {/* Search Input */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        background: '#0f0f0f',
        border: '1px solid #555',
        borderRadius: '6px',
        padding: '8px 12px',
        gap: '8px',
        transition: 'border-color 0.2s',
        borderColor: showSuggestions ? '#00ff88' : '#555'
      }}>
        <Search size={16} color="#888" />
        <input
          ref={inputRef}
          type="text"
          placeholder={placeholder}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyPress={handleKeyPress}
          onFocus={() => setShowSuggestions(true)}
          onBlur={() => setTimeout(() => setShowSuggestions(false), 200)}
          style={{
            background: 'transparent',
            border: 'none',
            color: '#fff',
            fontSize: '14px',
            flex: 1,
            outline: 'none',
            fontFamily: 'Monaco, Consolas, "Courier New", monospace'
          }}
        />
        {query && (
          <button
            onClick={clearQuery}
            style={{
              background: 'none',
              border: 'none',
              color: '#888',
              cursor: 'pointer',
              padding: '2px',
              borderRadius: '2px',
              display: 'flex',
              alignItems: 'center'
            }}
          >
            <X size={14} />
          </button>
        )}
        <button
          onClick={handleSearch}
          disabled={loading || !query.trim()}
          style={{
            background: loading || !query.trim() ? '#333' : '#00ff88',
            border: 'none',
            color: loading || !query.trim() ? '#666' : '#000',
            padding: '6px 12px',
            borderRadius: '4px',
            cursor: loading || !query.trim() ? 'not-allowed' : 'pointer',
            fontSize: '13px',
            fontWeight: '600',
            transition: 'all 0.2s'
          }}
        >
          {loading ? 'Searching...' : 'Search'}
        </button>
      </div>

      {/* Suggestions Dropdown */}
      {showSuggestions && (
        <div style={{
          position: 'absolute',
          top: '100%',
          left: 0,
          right: 0,
          background: '#1a1a1a',
          border: '1px solid #333',
          borderRadius: '6px',
          marginTop: '4px',
          maxHeight: '400px',
          overflowY: 'auto',
          zIndex: 1000,
          boxShadow: '0 4px 20px rgba(0,0,0,0.3)'
        }}>
          {/* Recent Queries */}
          {recentQueries.length > 0 && (
            <div style={{ padding: '12px 0' }}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '0 12px 8px',
                borderBottom: '1px solid #333'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Clock size={14} color="#888" />
                  <span style={{ color: '#888', fontSize: '12px', fontWeight: '600' }}>
                    RECENT QUERIES
                  </span>
                </div>
                <button
                  onClick={clearRecentQueries}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#888',
                    cursor: 'pointer',
                    fontSize: '11px',
                    padding: '2px 4px'
                  }}
                >
                  Clear
                </button>
              </div>
              {recentQueries.slice(0, 5).map((recentQuery, index) => (
                <button
                  key={index}
                  onClick={() => insertSuggestion(recentQuery)}
                  style={{
                    width: '100%',
                    display: 'block',
                    textAlign: 'left',
                    background: 'none',
                    border: 'none',
                    color: '#ccc',
                    padding: '8px 12px',
                    cursor: 'pointer',
                    fontSize: '13px',
                    fontFamily: 'Monaco, Consolas, "Courier New", monospace',
                    transition: 'background-color 0.2s'
                  }}
                  onMouseOver={(e) => e.target.style.backgroundColor = '#2a2a2a'}
                  onMouseOut={(e) => e.target.style.backgroundColor = 'transparent'}
                >
                  <span style={{ color: '#00ff88' }}>↻</span> {recentQuery}
                </button>
              ))}
            </div>
          )}

          {/* Field Suggestions */}
          <div style={{ padding: '12px 0' }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '0 12px 8px',
              borderBottom: '1px solid #333'
            }}>
              <BookOpen size={14} color="#888" />
              <span style={{ color: '#888', fontSize: '12px', fontWeight: '600' }}>
                FIELD SUGGESTIONS
              </span>
            </div>
            {fieldSuggestions.slice(0, 8).map((suggestion, index) => (
              <button
                key={index}
                onClick={() => insertSuggestion(suggestion.example)}
                style={{
                  width: '100%',
                  display: 'block',
                  textAlign: 'left',
                  background: 'none',
                  border: 'none',
                  color: '#ccc',
                  padding: '8px 12px',
                  cursor: 'pointer',
                  fontSize: '13px',
                  transition: 'background-color 0.2s'
                }}
                onMouseOver={(e) => e.target.style.backgroundColor = '#2a2a2a'}
                onMouseOut={(e) => e.target.style.backgroundColor = 'transparent'}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <span style={{ 
                    fontFamily: 'Monaco, Consolas, "Courier New", monospace',
                    color: '#00ff88'
                  }}>
                    {suggestion.example}
                  </span>
                  <span style={{ color: '#888', fontSize: '11px' }}>
                    {suggestion.description}
                  </span>
                </div>
              </button>
            ))}
          </div>

          {/* Operator Suggestions */}
          <div style={{ padding: '12px 0' }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '0 12px 8px',
              borderBottom: '1px solid #333'
            }}>
              <span style={{ color: '#888', fontSize: '12px', fontWeight: '600' }}>
                DQL OPERATORS
              </span>
            </div>
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
              gap: '4px',
              padding: '0 12px'
            }}>
              {operators.map((op, index) => (
                <div
                  key={index}
                  style={{
                    padding: '6px 8px',
                    background: '#2a2a2a',
                    borderRadius: '4px',
                    fontSize: '11px'
                  }}
                >
                  <div style={{ 
                    color: '#00ff88', 
                    fontFamily: 'Monaco, Consolas, "Courier New", monospace',
                    marginBottom: '2px'
                  }}>
                    {op.example}
                  </div>
                  <div style={{ color: '#888' }}>
                    {op.description}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SearchBar;
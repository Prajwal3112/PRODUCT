import React, { useState, useEffect } from 'react';
import { RefreshCw, Calendar, Filter, Eye, ChevronUp, X } from 'lucide-react';
import SearchBar from './SearchBar';
import FieldFilter from './FieldFilter';
import ActiveFilters from './ActiveFilters';

const LogViewer = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilters, setActiveFilters] = useState([]);
  const [selectedStream, setSelectedStream] = useState('all');
  const [timeRange, setTimeRange] = useState('1h');
  const [expandedLog, setExpandedLog] = useState(null);
  const [viewMode, setViewMode] = useState('table');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalLogs, setTotalLogs] = useState(0);

  const streamTypes = [
    'all', 
    'authentication-logs', 
    'fim', 
    'firewall', 
    'malware-detection', 
    'network-logs', 
    'syslog-logs', 
    'vulnerability', 
    'windows-event-logs'
  ];
  const timeRanges = [
    { value: '15m', label: 'Last 15 minutes' },
    { value: '1h', label: 'Last hour' },
    { value: '4h', label: 'Last 4 hours' },
    { value: '24h', label: 'Last 24 hours' },
    { value: '7d', label: 'Last 7 days' }
  ];

  const fetchLogs = async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Combine search query with active filters
      const combinedQuery = [searchQuery, ...activeFilters]
        .filter(q => q && q.trim())
        .join(' AND ');

      const params = new URLSearchParams({
        stream: selectedStream,
        time: timeRange,
        dql: combinedQuery,
        page: currentPage,
        size: 50
      });

      const response = await fetch(`${import.meta.env.VITE_BACKEND_URL}/api/logs?${params}`);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      setLogs(data.logs || []);
      setTotalLogs(data.total || 0);
    } catch (err) {
      setError(`Failed to fetch logs: ${err.message}`);
      console.error('Log fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchLogs(); }, [selectedStream, timeRange, currentPage]);

  const handleSearch = (query) => { 
    setSearchQuery(query);
    setCurrentPage(1); 
  };

  const handleAddFilter = (filterQuery) => {
    // Check if filter already exists
    if (!activeFilters.includes(filterQuery)) {
      setActiveFilters([...activeFilters, filterQuery]);
      setCurrentPage(1);
    }
  };

  const handleRemoveFilter = (index) => {
    const newFilters = activeFilters.filter((_, i) => i !== index);
    setActiveFilters(newFilters);
    setCurrentPage(1);
  };

  const handleClearAllFilters = () => {
    setActiveFilters([]);
    setCurrentPage(1);
  };
  
  const handleRefresh = () => fetchLogs();

  // Add activeFilters to dependency array
  useEffect(() => { 
    fetchLogs(); 
  }, [selectedStream, timeRange, currentPage, searchQuery, activeFilters]);

  const formatTimestamp = (timestamp) => new Date(timestamp).toLocaleString();
  const getStreamColor = (stream) => stream ? '#00ff88' === '#00ff88' : '#888';
  const totalPages = Math.ceil(totalLogs / 50);

  const renderLogDetails = (log) => (
    <div style={{ background: '#0a0a0a', padding: '15px', borderRadius: '6px', fontSize: '13px' }}>
      {viewMode === 'json' ? (
        <pre style={{ color: '#00ff88', fontSize: '12px', overflow: 'auto', maxHeight: '400px' }}>
          {JSON.stringify(log, null, 2)}
        </pre>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
          {Object.entries(log).map(([key, value]) => (
            <div key={key} style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
              <span style={{ color: '#888', fontSize: '11px', textTransform: 'uppercase' }}>
                {key.replace(/_/g, ' ')}
              </span>
              <FieldFilter 
                fieldName={key}
                fieldValue={value}
                onAddFilter={handleAddFilter}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  );

  return (
    <div style={{
      padding: '20px',
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      gap: '20px'
    }}>
      {/* Header Controls */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '15px'
      }}>
        <h2 style={{ margin: 0, color: '#fff', fontSize: '24px' }}>
          Log Viewer
        </h2>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ color: '#888', fontSize: '14px' }}>
            {totalLogs.toLocaleString()} total logs
          </span>
          <button
            onClick={handleRefresh}
            disabled={loading}
            style={{
              background: '#00ff88',
              border: 'none',
              color: '#000',
              padding: '8px 12px',
              borderRadius: '6px',
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '5px',
              fontSize: '13px',
              fontWeight: '600'
            }}
          >
            <RefreshCw size={14} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div style={{
        display: 'flex',
        gap: '15px',
        flexWrap: 'wrap',
        alignItems: 'center',
        padding: '15px',
        background: '#1a1a1a',
        borderRadius: '8px',
        border: '1px solid #333'
      }}>
        {/* DQL Search Bar */}
        <div style={{ flex: '1', minWidth: '300px' }}>
          <SearchBar 
            onSearch={handleSearch}
            loading={loading}
            placeholder="Search using DQL: agent_name: Kaplesh, rule_id: 60642, _id: oc3geJgBuR2PlYEUBuA1"
          />
        </div>

        {/* Stream Filter */}

        {/* Stream Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Filter size={16} color="#888" />
          <select
            value={selectedStream}
            onChange={(e) => setSelectedStream(e.target.value)}
            style={{
              background: '#0f0f0f',
              border: '1px solid #555',
              color: '#fff',
              padding: '8px 12px',
              borderRadius: '6px',
              fontSize: '14px'
            }}
          >
            {streamTypes.map(stream => (
              <option key={stream} value={stream}>
                {stream === 'all' ? 'All Streams' : stream.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
              </option>
            ))}
          </select>
        </div>

        {/* Time Range */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Calendar size={16} color="#888" />
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            style={{
              background: '#0f0f0f',
              border: '1px solid #555',
              color: '#fff',
              padding: '8px 12px',
              borderRadius: '6px',
              fontSize: '14px'
            }}
          >
            {timeRanges.map(range => (
              <option key={range.value} value={range.value}>
                {range.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Active Filters */}
      <ActiveFilters 
        filters={activeFilters}
        onRemoveFilter={handleRemoveFilter}
        onClearAll={handleClearAllFilters}
      />

      {/* Error Message */}
      {error && (
        <div style={{
          background: '#ff443320',
          border: '1px solid #ff4433',
          color: '#ff6b6b',
          padding: '12px',
          borderRadius: '6px',
          fontSize: '14px'
        }}>
          {error}
        </div>
      )}

      {/* Log Table */}
      <div style={{
        flex: 1,
        background: '#1a1a1a',
        borderRadius: '8px',
        border: '1px solid #333',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column'
      }}>
        {/* Table Header */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '200px 120px 1fr 150px 80px',
          gap: '15px',
          padding: '15px',
          background: '#2a2a2a',
          borderBottom: '1px solid #333',
          fontSize: '13px',
          fontWeight: '600',
          color: '#aaa'
        }}>
          <div>TIMESTAMP</div>
          <div>ID</div>
          <div>RULE DESCRIPTION</div>
          <div>STREAM TYPE</div>
          <div>ACTION</div>
        </div>

        {/* Table Body */}
        <div style={{
          flex: 1,
          overflow: 'auto'
        }}>
          {loading ? (
            <div style={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              height: '200px',
              color: '#888'
            }}>
              <RefreshCw size={20} style={{ animation: 'spin 1s linear infinite', marginRight: '10px' }} />
              Loading logs...
            </div>
          ) : logs.length === 0 ? (
            <div style={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              height: '200px',
              color: '#888',
              fontSize: '16px'
            }}>
              No logs found
            </div>
          ) : (
            logs.map((log) => (
              <div key={log._id}>
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: '200px 120px 1fr 150px 80px',
                  gap: '15px',
                  padding: '15px',
                  borderBottom: '1px solid #2a2a2a',
                  fontSize: '13px',
                  color: '#ccc',
                  cursor: 'pointer',
                  transition: 'background-color 0.2s'
                }}
                onMouseOver={(e) => e.currentTarget.style.backgroundColor = '#222'}
                onMouseOut={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                >
                  <div style={{ fontSize: '12px' }}>
                    {formatTimestamp(log['@timestamp'])}
                  </div>
                  <div style={{ 
                    fontSize: '11px', 
                    fontFamily: 'monospace',
                    color: '#888',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis'
                  }}>
                    {log._id.substring(0, 12)}...
                  </div>
                  <div>
                    {log.rule_description || log.message || 'No description'}
                  </div>
                  <div>
                    <span style={{
                      background: getStreamColor(log.stream) + '20',
                      color: getStreamColor(log.stream),
                      padding: '4px 8px',
                      borderRadius: '12px',
                      fontSize: '11px',
                      fontWeight: '600'
                    }}>
                      {(log.stream || log.stream_type || 'unknown').replace(/-/g, ' ').toUpperCase()}
                    </span>
                  </div>
                  <div>
                    <button
                      onClick={() => setExpandedLog(expandedLog === log._id ? null : log._id)}
                      style={{
                        background: 'none',
                        border: '1px solid #555',
                        color: '#00ff88',
                        padding: '6px',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center'
                      }}
                    >
                      {expandedLog === log._id ? <ChevronUp size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </div>

                {/* Expanded Log Details */}
                {expandedLog === log._id && (
                  <div style={{
                    padding: '20px',
                    background: '#111',
                    borderBottom: '1px solid #333'
                  }}>
                    <div style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: '15px'
                    }}>
                      <h4 style={{ margin: 0, color: '#fff' }}>Log Details</h4>
                      <div style={{ display: 'flex', gap: '10px' }}>
                        <button
                          onClick={() => setViewMode('table')}
                          style={{
                            background: viewMode === 'table' ? '#00ff88' : '#333',
                            border: 'none',
                            color: viewMode === 'table' ? '#000' : '#fff',
                            padding: '6px 12px',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontSize: '12px'
                          }}
                        >
                          Table
                        </button>
                        <button
                          onClick={() => setViewMode('json')}
                          style={{
                            background: viewMode === 'json' ? '#00ff88' : '#333',
                            border: 'none',
                            color: viewMode === 'json' ? '#000' : '#fff',
                            padding: '6px 12px',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontSize: '12px'
                          }}
                        >
                          JSON
                        </button>
                        <button
                          onClick={() => setExpandedLog(null)}
                          style={{
                            background: '#ff4433',
                            border: 'none',
                            color: '#fff',
                            padding: '6px',
                            borderRadius: '4px',
                            cursor: 'pointer'
                          }}
                        >
                          <X size={14} />
                        </button>
                      </div>
                    </div>
                    {renderLogDetails(log)}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          gap: '15px',
          padding: '15px',
          background: '#1a1a1a',
          borderRadius: '8px',
          border: '1px solid #333'
        }}>
          <button
            onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
            disabled={currentPage === 1}
            style={{
              background: currentPage === 1 ? '#333' : '#555',
              border: 'none',
              color: currentPage === 1 ? '#666' : '#fff',
              padding: '8px 12px',
              borderRadius: '6px',
              cursor: currentPage === 1 ? 'not-allowed' : 'pointer'
            }}
          >
            Previous
          </button>
          
          <span style={{ color: '#888', fontSize: '14px' }}>
            Page {currentPage} of {totalPages}
          </span>
          
          <button
            onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
            disabled={currentPage === totalPages}
            style={{
              background: currentPage === totalPages ? '#333' : '#555',
              border: 'none',
              color: currentPage === totalPages ? '#666' : '#fff',
              padding: '8px 12px',
              borderRadius: '6px',
              cursor: currentPage === totalPages ? 'not-allowed' : 'pointer'
            }}
          >
            Next
          </button>
        </div>
      )}

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

export default LogViewer;
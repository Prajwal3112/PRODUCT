import React, { useEffect, useState } from 'react';
import axios from 'axios';

export default function Logs() {
  const [logs, setLogs] = useState([]);
  const [from, setFrom] = useState(0);
  const size = 100;
  const [loading, setLoading] = useState(false);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`/api/logs?from=${from}&size=${size}`);
      setLogs(prev => [...prev, ...res.data.logs]);
      setFrom(prev => prev + size);
    } catch (err) {
      console.error('❌ Error fetching logs', err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleScroll = (e) => {
    const bottom =
      e.target.scrollHeight - e.target.scrollTop === e.target.clientHeight;
    if (bottom && !loading) fetchLogs();
  };

  return (
    <div onScroll={handleScroll} className="h-full overflow-y-auto space-y-2">
      {logs.map((log, idx) => (
        <div key={idx} className="p-2 bg-white/10 backdrop-blur-sm rounded-md text-sm font-mono whitespace-pre-wrap">
          {JSON.stringify(log, null, 2)}
        </div>
      ))}
      {loading && <p className="text-purple-300 text-sm">Loading more logs...</p>}
    </div>
  );
}

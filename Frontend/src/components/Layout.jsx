import React from 'react';

export default function Layout({ children }) {
  return (
    <div className="flex h-screen text-white bg-gradient-to-br from-purple-900 via-black to-gray-900">
      {/* Sidebar */}
      <aside className="w-64 bg-black/30 backdrop-blur-md p-4 border-r border-purple-700">
        <h1 className="text-xl font-bold mb-4">🔍 CyberSentinel</h1>
        <ul className="space-y-2 text-sm">
          <li className="hover:text-purple-300 cursor-pointer">📄 Logs</li>
          <li className="hover:text-purple-300 cursor-pointer">📊 Dashboards</li>
          <li className="hover:text-purple-300 cursor-pointer">🛠 Settings</li>
        </ul>
      </aside>

      {/* Main */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="bg-black/40 p-4 border-b border-purple-700">
          <h2 className="text-lg font-semibold">Live Log Viewer</h2>
        </header>
        <main className="flex-1 overflow-y-auto p-4">{children}</main>
        <footer className="bg-black/30 p-2 text-sm text-center border-t border-purple-700">
          © 2025 CyberSentinel Logs Viewer
        </footer>
      </div>
    </div>
  );
}

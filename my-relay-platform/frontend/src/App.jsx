/**
 * Relay Platform - React Frontend
 * ================================
 * Modern dashboard for managing disposable email relays.
 */

import React, { useState, useEffect, useCallback } from 'react';

// API Configuration - Auto-detect based on environment
const API_BASE = window.location.hostname === 'localhost' 
  ? 'http://localhost:8080'
  : `${window.location.protocol}//${window.location.host}`;

// ============== API Service ==============
const api = {
  token: localStorage.getItem('token'),
  
  setToken(token) {
    this.token = token;
    if (token) {
      localStorage.setItem('token', token);
    } else {
      localStorage.removeItem('token');
    }
  },
  
  async request(endpoint, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...(this.token && { 'Authorization': `Bearer ${this.token}` }),
      ...options.headers,
    };
    
    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });
    
    if (response.status === 401) {
      this.setToken(null);
      window.location.reload();
    }
    
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || 'Request failed');
    }
    return data;
  },
  
  // Auth
  login: (username, password) => api.request('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username, password }),
  }),
  
  register: (data) => api.request('/auth/register', {
    method: 'POST',
    body: JSON.stringify(data),
  }),
  
  getMe: () => api.request('/auth/me'),
  
  // Instances
  getInstances: () => api.request('/instances'),
  createInstance: (data) => api.request('/instances', {
    method: 'POST',
    body: JSON.stringify(data),
  }),
  deleteInstance: (id) => api.request(`/instances/${id}`, { method: 'DELETE' }),
  getInstanceHealth: (id) => api.request(`/instances/${id}/health`),
  
  // Emails
  sendEmail: (data) => api.request('/emails/send', {
    method: 'POST',
    body: JSON.stringify(data),
  }),
  getEmails: () => api.request('/emails'),
  
  // Regions
  getRegions: () => api.request('/regions'),
};

// ============== Components ==============

// Login/Register Form
function AuthForm({ onLogin }) {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    
    try {
      if (isLogin) {
        const data = await api.login(username, password);
        api.setToken(data.access_token);
        onLogin();
      } else {
        await api.register({ username, email, password });
        // Auto-login after register
        const data = await api.login(username, password);
        api.setToken(data.access_token);
        onLogin();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900">
      <div className="bg-gray-800 p-8 rounded-lg shadow-xl w-full max-w-md">
        <h1 className="text-2xl font-bold text-white mb-6 text-center">
          📧 Relay Platform
        </h1>
        
        <div className="flex mb-6">
          <button
            onClick={() => setIsLogin(true)}
            className={`flex-1 py-2 ${isLogin ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400'} rounded-l`}
          >
            Login
          </button>
          <button
            onClick={() => setIsLogin(false)}
            className={`flex-1 py-2 ${!isLogin ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400'} rounded-r`}
          >
            Register
          </button>
        </div>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full p-3 bg-gray-700 text-white rounded focus:ring-2 focus:ring-blue-500 outline-none"
            required
          />
          
          {!isLogin && (
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full p-3 bg-gray-700 text-white rounded focus:ring-2 focus:ring-blue-500 outline-none"
              required
            />
          )}
          
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full p-3 bg-gray-700 text-white rounded focus:ring-2 focus:ring-blue-500 outline-none"
            required
          />
          
          {error && (
            <div className="text-red-400 text-sm">{error}</div>
          )}
          
          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white rounded font-medium disabled:opacity-50"
          >
            {loading ? 'Loading...' : (isLogin ? 'Login' : 'Register')}
          </button>
        </form>
        
        <p className="text-gray-500 text-sm text-center mt-4">
          Default admin: admin / admin123
        </p>
      </div>
    </div>
  );
}

// Instance Card
function InstanceCard({ instance, onRefresh, onSelect, isSelected }) {
  const [loading, setLoading] = useState(false);
  
  const statusColors = {
    pending: 'bg-yellow-500',
    launching: 'bg-yellow-500',
    initializing: 'bg-blue-500', 
    ready: 'bg-green-500',
    sending: 'bg-purple-500',
    terminating: 'bg-orange-500',
    terminated: 'bg-gray-600',
    error: 'bg-red-600',
  };
  
  const handleTerminate = async () => {
    if (!window.confirm('Are you sure you want to terminate this instance?')) return;
    setLoading(true);
    try {
      await api.deleteInstance(instance.id);
      onRefresh();
    } catch (err) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  };
  
  const handleHealthCheck = async () => {
    setLoading(true);
    try {
      const health = await api.getInstanceHealth(instance.id);
      alert(`Health: ${health.status}\n${JSON.stringify(health, null, 2)}`);
    } catch (err) {
      alert(`Health check failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div 
      className={`bg-gray-800 rounded-lg p-4 border-2 transition-all cursor-pointer relative overflow-hidden
        ${isSelected ? 'border-blue-500' : 'border-transparent hover:border-gray-600'}
        ${instance.status === 'error' ? 'border-red-500/50' : ''}`}
      onClick={() => instance.status === 'ready' && onSelect(instance)}
    >
      <div className="flex justify-between items-start mb-3">
        <div>
          <h3 className="text-white font-medium flex items-center gap-2">
            {instance.status === 'error' && <span>⚠️</span>}
            {instance.name || `Instance #${instance.id}`}
          </h3>
          <p className="text-gray-400 text-sm">{instance.region}</p>
        </div>
        <span className={`px-2 py-1 rounded text-xs text-white font-bold uppercase tracking-wider ${statusColors[instance.status] || 'bg-gray-500'}`}>
          {instance.status}
        </span>
      </div>
      
      <div className="space-y-1 text-sm">
        <div className="flex justify-between">
          <span className="text-gray-400">IP:</span>
          <span className="text-white font-mono">{instance.public_ip || '—'}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-gray-400">Emails Sent:</span>
          <span className="text-white">{instance.emails_sent}</span>
        </div>
        {instance.instance_id && (
          <div className="flex justify-between">
            <span className="text-gray-400">AWS ID:</span>
            <span className="text-white font-mono text-xs">{instance.instance_id.slice(0, 15)}...</span>
          </div>
        )}
      </div>
      
      {/* ERROR DISPLAY BLOCK */}
      {instance.status === 'error' ? (
        <div className="mt-3 p-2 bg-red-900/30 border border-red-500/50 rounded text-red-200 text-xs font-mono break-all">
          <span className="font-bold block mb-1 text-red-100">❌ Error Details:</span>
          {instance.status_message}
        </div>
      ) : (
        instance.status_message && (
          <p className="text-gray-500 text-xs mt-2 italic truncate">
            {['launching', 'initializing'].includes(instance.status) && <span className="animate-pulse">⏳ </span>}
            {instance.status_message}
          </p>
        )
      )}
      
      <div className="flex gap-2 mt-4">
        {instance.status === 'ready' && (
          <button
            onClick={(e) => { e.stopPropagation(); handleHealthCheck(); }}
            disabled={loading}
            className="flex-1 py-1 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded disabled:opacity-50"
          >
            Health
          </button>
        )}
        {!['terminated', 'terminating'].includes(instance.status) && (
          <button
            onClick={(e) => { e.stopPropagation(); handleTerminate(); }}
            disabled={loading}
            className="flex-1 py-1 bg-red-600 hover:bg-red-700 text-white text-sm rounded disabled:opacity-50"
          >
            {instance.status === 'error' ? 'Clear / Terminate' : 'Terminate'}
          </button>
        )}
      </div>
    </div>
  );
}

// Email Composer
function EmailComposer({ instance, onSent }) {
  const [smtpUser, setSmtpUser] = useState('');
  const [smtpPass, setSmtpPass] = useState('');
  const [toAddress, setToAddress] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  
  const handleSend = async (e) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    
    try {
      const response = await api.sendEmail({
        instance_id: instance.id,
        smtp_user: smtpUser,
        smtp_pass: smtpPass,
        to_address: toAddress,
        subject,
        body,
      });
      
      setResult({ success: true, message: `Email sent to ${toAddress}!` });
      setToAddress('');
      setSubject('');
      setBody('');
      onSent();
    } catch (err) {
      setResult({ success: false, message: err.message });
    } finally {
      setLoading(false);
    }
  };
  
  if (!instance) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 text-center">
        <p className="text-gray-400">Select a ready instance to compose emails</p>
      </div>
    );
  }
  
  return (
    <div className="bg-gray-800 rounded-lg p-6">
      <h2 className="text-xl font-bold text-white mb-4">
        ✉️ Send Email via {instance.public_ip}
      </h2>
      
      <form onSubmit={handleSend} className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <input
            type="email"
            placeholder="Gmail Address"
            value={smtpUser}
            onChange={(e) => setSmtpUser(e.target.value)}
            className="p-3 bg-gray-700 text-white rounded focus:ring-2 focus:ring-blue-500 outline-none"
            required
          />
          <input
            type="password"
            placeholder="App Password"
            value={smtpPass}
            onChange={(e) => setSmtpPass(e.target.value)}
            className="p-3 bg-gray-700 text-white rounded focus:ring-2 focus:ring-blue-500 outline-none"
            required
          />
        </div>
        
        <input
          type="email"
          placeholder="To Address"
          value={toAddress}
          onChange={(e) => setToAddress(e.target.value)}
          className="w-full p-3 bg-gray-700 text-white rounded focus:ring-2 focus:ring-blue-500 outline-none"
          required
        />
        
        <input
          type="text"
          placeholder="Subject"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          className="w-full p-3 bg-gray-700 text-white rounded focus:ring-2 focus:ring-blue-500 outline-none"
          required
        />
        
        <textarea
          placeholder="Message body..."
          value={body}
          onChange={(e) => setBody(e.target.value)}
          rows={5}
          className="w-full p-3 bg-gray-700 text-white rounded focus:ring-2 focus:ring-blue-500 outline-none resize-none"
          required
        />
        
        {result && (
          <div className={`p-3 rounded ${result.success ? 'bg-green-800 text-green-200' : 'bg-red-800 text-red-200'}`}>
            {result.message}
          </div>
        )}
        
        <button
          type="submit"
          disabled={loading}
          className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white rounded font-medium disabled:opacity-50"
        >
          {loading ? 'Sending...' : '📤 Send Email'}
        </button>
      </form>
    </div>
  );
}

// Email History
function EmailHistory({ emails }) {
  if (!emails.length) {
    return (
      <div className="text-gray-500 text-center py-4">
        No emails sent yet
      </div>
    );
  }
  
  return (
    <div className="space-y-2 max-h-96 overflow-y-auto">
      {emails.map((email) => (
        <div key={email.id} className="bg-gray-700 rounded p-3 text-sm">
          <div className="flex justify-between items-start">
            <span className="text-white font-medium truncate flex-1">
              {email.subject}
            </span>
            <span className={`px-2 py-0.5 rounded text-xs ml-2
              ${email.status === 'sent' ? 'bg-green-600' : email.status === 'failed' ? 'bg-red-600' : 'bg-yellow-600'}`}>
              {email.status}
            </span>
          </div>
          <div className="text-gray-400 mt-1">
            To: {email.to_address}
          </div>
          <div className="text-gray-500 text-xs mt-1">
            {email.relay_ip} • {new Date(email.created_at).toLocaleString()}
          </div>
          {email.error_message && (
            <div className="text-red-400 text-xs mt-1">{email.error_message}</div>
          )}
        </div>
      ))}
    </div>
  );
}

// Main Dashboard
function Dashboard({ user, onLogout }) {
  const [instances, setInstances] = useState([]);
  const [emails, setEmails] = useState([]);
  const [regions, setRegions] = useState([]);
  const [selectedInstance, setSelectedInstance] = useState(null);
  const [selectedRegion, setSelectedRegion] = useState('us-east-1');
  const [newInstanceName, setNewInstanceName] = useState('');
  
  // New state for handling launch errors
  const [loading, setLoading] = useState(false);
  const [launchError, setLaunchError] = useState(null);
  
  const loadData = useCallback(async () => {
    try {
      const [instancesData, emailsData, regionsData] = await Promise.all([
        api.getInstances(),
        api.getEmails(),
        api.getRegions(),
      ]);
      setInstances(instancesData);
      setEmails(emailsData);
      setRegions(regionsData);
    } catch (err) {
      console.error('Error loading data:', err);
    }
  }, []);
  
  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000); // 5s refresh
    return () => clearInterval(interval);
  }, [loadData]);
  
  const handleLaunch = async () => {
    setLoading(true);
    setLaunchError(null); 
    try {
      await api.createInstance({
        region: selectedRegion,
        name: newInstanceName || undefined,
      });
      setNewInstanceName('');
      loadData();
    } catch (err) {
      setLaunchError(err.message);
    } finally {
      setLoading(false);
    }
  };
  
  const readyInstances = instances.filter(i => i.status === 'ready');
  const activeInstances = instances.filter(i => !['terminated'].includes(i.status));
  
  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
          <h1 className="text-xl font-bold text-white">📧 Relay Platform</h1>
          <div className="flex items-center gap-4">
            <span className="text-gray-400">
              👤 {user.username} {user.is_admin && '(Admin)'}
            </span>
            <button
              onClick={onLogout}
              className="px-3 py-1 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm"
            >
              Logout
            </button>
          </div>
        </div>
      </header>
      
      <main className="max-w-7xl mx-auto px-4 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Instances */}
          <div className="lg:col-span-2 space-y-6">
            {/* Launch New Instance */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-xl font-bold text-white mb-4">🚀 Launch New Relay</h2>
              <div className="flex gap-4">
                <select
                  value={selectedRegion}
                  onChange={(e) => setSelectedRegion(e.target.value)}
                  className="flex-1 p-3 bg-gray-700 text-white rounded"
                >
                  {regions.map((r) => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </select>
                <input
                  type="text"
                  placeholder="Instance name (optional)"
                  value={newInstanceName}
                  onChange={(e) => setNewInstanceName(e.target.value)}
                  className="flex-1 p-3 bg-gray-700 text-white rounded"
                />
                <button
                  onClick={handleLaunch}
                  disabled={loading}
                  className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded font-medium disabled:opacity-50"
                >
                  {loading ? 'Launching...' : '🚀 Launch'}
                </button>
              </div>

              {/* API ERROR DISPLAY */}
              {launchError && (
                <div className="mt-4 p-3 bg-red-900/50 border border-red-500 rounded text-red-200">
                   <strong>Launch Failed:</strong> {launchError}
                </div>
              )}
            </div>
            
            {/* Active Instances */}
            <div>
              <h2 className="text-xl font-bold text-white mb-4">
                📡 Active Instances ({activeInstances.length})
              </h2>
              
              {activeInstances.length === 0 ? (
                <div className="bg-gray-800 rounded-lg p-8 text-center">
                  <p className="text-gray-400">No active instances. Launch one to get started!</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {activeInstances.map((instance) => (
                    <InstanceCard
                      key={instance.id}
                      instance={instance}
                      onRefresh={loadData}
                      onSelect={setSelectedInstance}
                      isSelected={selectedInstance?.id === instance.id}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
          
          {/* Right Column - Email */}
          <div className="space-y-6">
            <EmailComposer
              instance={selectedInstance}
              onSent={loadData}
            />
            
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-bold text-white mb-4">📜 Recent Emails</h2>
              <EmailHistory emails={emails} />
            </div>
          </div>
        </div>
        
        {/* Stats Footer */}
        <div className="mt-8 grid grid-cols-4 gap-4">
          <div className="bg-gray-800 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-white">{activeInstances.length}</div>
            <div className="text-gray-400 text-sm">Active Instances</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-green-400">{readyInstances.length}</div>
            <div className="text-gray-400 text-sm">Ready to Send</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-blue-400">
              {emails.filter(e => e.status === 'sent').length}
            </div>
            <div className="text-gray-400 text-sm">Emails Sent</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-purple-400">
              {new Set(instances.map(i => i.public_ip).filter(Boolean)).size}
            </div>
            <div className="text-gray-400 text-sm">Unique IPs Used</div>
          </div>
        </div>
      </main>
    </div>
  );
}

// Main App
export default function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    const checkAuth = async () => {
      if (api.token) {
        try {
          const userData = await api.getMe();
          setUser(userData);
        } catch {
          api.setToken(null);
        }
      }
      setLoading(false);
    };
    checkAuth();
  }, []);
  
  const handleLogin = async () => {
    const userData = await api.getMe();
    setUser(userData);
  };
  
  const handleLogout = () => {
    api.setToken(null);
    setUser(null);
  };
  
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="text-white text-xl">Loading...</div>
      </div>
    );
  }
  
  if (!user) {
    return <AuthForm onLogin={handleLogin} />;
  }
  
  return <Dashboard user={user} onLogout={handleLogout} />;
}
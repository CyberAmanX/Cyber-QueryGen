import React, { useState, useEffect, useMemo } from "react";
import "./App.css";
import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Tool configurations
const TOOL_CONFIGS = {
  wireshark: {
    name: "Wireshark",
    description: "Network packet analysis display filters",
    icon: "🌐",
    fields: [
      { name: "protocol", type: "select", label: "Protocol", options: ["", "tcp", "udp", "icmp", "http", "https", "dns", "ftp"], placeholder: "Select protocol" },
      { name: "ip_filter", type: "text", label: "IP Filter", placeholder: "192.168.1.1 or 192.168.1.0/24" },
      { name: "port", type: "number", label: "Port", placeholder: "80" },
      { name: "payload_content", type: "text", label: "Payload Content", placeholder: "Content to search for" },
      { name: "time_range", type: "object", label: "Time Range", fields: [
        { name: "start", type: "text", label: "Start Time", placeholder: "2024-01-01 00:00:00" },
        { name: "end", type: "text", label: "End Time", placeholder: "2024-01-01 23:59:59" }
      ]}
    ]
  },
  nmap: {
    name: "Nmap",
    description: "Network scanner and security auditing tool",
    icon: "🔍",
    fields: [
      { name: "target_ip", type: "text", label: "Target IP/Host", placeholder: "192.168.1.1 or example.com", required: true },
      { name: "scan_type", type: "select", label: "Scan Type", options: ["syn", "tcp", "udp", "ping", "version", "os", "aggressive"], placeholder: "Select scan type" },
      { name: "ports", type: "text", label: "Ports", placeholder: "80, 1-1000, all, or top1000" },
      { name: "timing", type: "select", label: "Timing", options: ["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"], placeholder: "Select timing" },
      { name: "output_format", type: "select", label: "Output Format", options: ["", "normal", "xml", "greppable", "all"], placeholder: "Select output format" },
      { name: "extra_flags", type: "text", label: "Extra Flags", placeholder: "-v --script vuln" }
    ]
  },
  splunk: {
    name: "Splunk",
    description: "Search Processing Language (SPL) queries",
    icon: "📊",
    fields: [
      { name: "index", type: "text", label: "Index", placeholder: "security, web_logs, *" },
      { name: "sourcetype", type: "text", label: "Sourcetype", placeholder: "wineventlog, access_log" },
      { name: "search_filter", type: "text", label: "Search Filter", placeholder: "error OR warning" },
      { name: "time_range", type: "object", label: "Time Range", fields: [
        { name: "earliest", type: "text", label: "Earliest", placeholder: "-24h@h" },
        { name: "latest", type: "text", label: "Latest", placeholder: "now" }
      ]},
      { name: "output_fields", type: "text", label: "Output Fields", placeholder: "host, source, _time (comma-separated)" },
      { name: "stats_command", type: "text", label: "Stats Command", placeholder: "stats count by host" }
    ]
  },
  wazuh: {
    name: "Wazuh",
    description: "Security monitoring and detection rules",
    icon: "🛡️",
    fields: [
      { name: "description", type: "text", label: "Description", placeholder: "Failed login attempt", required: true },
      { name: "if_sid", type: "text", label: "Parent SID", placeholder: "5500" },
      { name: "regex", type: "text", label: "Regex Pattern", placeholder: "authentication failure" },
      { name: "match", type: "text", label: "Match Pattern", placeholder: "failed login" },
      { name: "field", type: "text", label: "Field Name", placeholder: "srcip, user, etc." },
      { name: "field_value", type: "text", label: "Field Value", placeholder: "Value to match" },
      { name: "group", type: "text", label: "Group", placeholder: "authentication_failed" }
    ]
  },
  yara: {
    name: "YARA",
    description: "Malware pattern matching rules",
    icon: "🦠",
    fields: [
      { name: "rule_name", type: "text", label: "Rule Name", placeholder: "SuspiciousMalware", required: true },
      { name: "meta", type: "object", label: "Metadata", fields: [
        { name: "author", type: "text", label: "Author", placeholder: "Security Team" },
        { name: "description", type: "text", label: "Description", placeholder: "Detects suspicious malware" },
        { name: "date", type: "text", label: "Date", placeholder: "2024-01-01" }
      ]},
      { name: "strings", type: "textarea", label: "String Patterns", placeholder: "Enter strings (one per line)" },
      { name: "hex_strings", type: "textarea", label: "Hex Patterns", placeholder: "48 65 6C 6C 6F" },
      { name: "condition", type: "text", label: "Condition", placeholder: "any of them or $string1 and $string2" }
    ]
  },
  suricata: {
    name: "Suricata",
    description: "Network intrusion detection rules",
    icon: "🚨",
    fields: [
      { name: "action", type: "select", label: "Action", options: ["alert", "drop", "reject", "pass"], placeholder: "Select action" },
      { name: "protocol", type: "select", label: "Protocol", options: ["tcp", "udp", "icmp", "ip"], placeholder: "Select protocol" },
      { name: "src_ip", type: "text", label: "Source IP", placeholder: "any or 192.168.1.0/24" },
      { name: "src_port", type: "text", label: "Source Port", placeholder: "any or 80" },
      { name: "dst_ip", type: "text", label: "Destination IP", placeholder: "any or 10.0.0.1" },
      { name: "dst_port", type: "text", label: "Destination Port", placeholder: "any or 443" },
      { name: "msg", type: "text", label: "Message", placeholder: "Suspicious HTTP traffic", required: true },
      { name: "content", type: "text", label: "Content", placeholder: "Content to match" },
      { name: "flow", type: "text", label: "Flow", placeholder: "to_server,established" },
      { name: "sid", type: "number", label: "Signature ID", placeholder: "1000001", required: true }
    ]
  },
  elasticsearch: {
    name: "Elasticsearch",
    description: "Search and analytics query DSL",
    icon: "🔎",
    fields: [
      { name: "query_type", type: "select", label: "Query Type", options: ["match", "term", "range", "bool", "match_all"], placeholder: "Select query type" },
      { name: "field", type: "text", label: "Field", placeholder: "message, @timestamp, status" },
      { name: "value", type: "text", label: "Value", placeholder: "Search value" },
      { name: "range", type: "object", label: "Range", fields: [
        { name: "gte", type: "text", label: "Greater than or equal", placeholder: "2024-01-01" },
        { name: "lte", type: "text", label: "Less than or equal", placeholder: "2024-12-31" }
      ]},
      { name: "size", type: "number", label: "Size", placeholder: "10" },
      { name: "sort", type: "text", label: "Sort", placeholder: "@timestamp:desc" }
    ]
  }
};

// Components
const Navigation = ({ activeView, setActiveView }) => (
  <nav className="bg-gray-900 border-b border-gray-700">
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="flex items-center justify-between h-16">
        <div className="flex items-center">
          <h1 className="text-2xl font-bold text-white flex items-center">
            <span className="text-3xl mr-2">🔐</span>
            CyberQueryMaker
          </h1>
        </div>
        <div className="flex space-x-4">
          {[
            { key: 'builder', label: 'Build Query', icon: '⚡' },
            { key: 'saved', label: 'Saved Queries', icon: '💾' },
            { key: 'knowledge', label: 'Knowledge Base', icon: '📚' }
          ].map(item => (
            <button
              key={item.key}
              onClick={() => setActiveView(item.key)}
              className={`px-3 py-2 rounded-md text-sm font-medium flex items-center space-x-1 transition-colors ${
                activeView === item.key
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-300 hover:bg-gray-700 hover:text-white'
              }`}
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  </nav>
);

const FieldRenderer = ({ field, value, onChange, prefix = '' }) => {
  const fieldName = prefix ? `${prefix}.${field.name}` : field.name;
  
  if (field.type === 'object' && field.fields) {
    return (
      <div className="space-y-4 p-4 bg-gray-50 rounded-lg">
        <label className="block text-sm font-medium text-gray-700">{field.label}</label>
        {field.fields.map(subField => (
          <FieldRenderer
            key={subField.name}
            field={subField}
            value={value?.[subField.name] || ''}
            onChange={(val) => onChange({
              ...value,
              [subField.name]: val
            })}
          />
        ))}
      </div>
    );
  }

  const inputClasses = "w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500";

  switch (field.type) {
    case 'select':
      return (
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            {field.label} {field.required && <span className="text-red-500">*</span>}
          </label>
          <select
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
            className={inputClasses}
          >
            <option value="">{field.placeholder}</option>
            {field.options.map(option => (
              <option key={option} value={option}>{option}</option>
            ))}
          </select>
        </div>
      );
    
    case 'textarea':
      return (
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            {field.label} {field.required && <span className="text-red-500">*</span>}
          </label>
          <textarea
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder}
            rows={4}
            className={inputClasses}
          />
        </div>
      );
    
    case 'number':
      return (
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            {field.label} {field.required && <span className="text-red-500">*</span>}
          </label>
          <input
            type="number"
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder}
            className={inputClasses}
          />
        </div>
      );
    
    default:
      return (
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            {field.label} {field.required && <span className="text-red-500">*</span>}
          </label>
          <input
            type="text"
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder}
            className={inputClasses}
          />
        </div>
      );
  }
};

const QueryBuilder = () => {
  const [selectedTool, setSelectedTool] = useState('');
  const [parameters, setParameters] = useState({});
  const [generatedQuery, setGeneratedQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [templateName, setTemplateName] = useState('');
  const [showSaveDialog, setShowSaveDialog] = useState(false);

  const handleParameterChange = (fieldName, value) => {
    setParameters(prev => ({
      ...prev,
      [fieldName]: value
    }));
  };

  const generateQuery = async () => {
    if (!selectedTool) return;
    
    setLoading(true);
    try {
      const response = await axios.post(`${API}/generate-query`, {
        tool: selectedTool,
        parameters
      });
      setGeneratedQuery(response.data.generated_query);
    } catch (error) {
      console.error('Error generating query:', error);
      alert('Error generating query. Please check your parameters.');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(generatedQuery);
    alert('Query copied to clipboard!');
  };

  const exportQuery = () => {
    const blob = new Blob([generatedQuery], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedTool}_query.txt`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const saveTemplate = async () => {
    if (!templateName || !selectedTool || !generatedQuery) {
      alert('Please generate a query and provide a template name');
      return;
    }

    try {
      await axios.post(`${API}/save-template`, {
        name: templateName,
        tool: selectedTool,
        parameters
      });
      alert('Template saved successfully!');
      setShowSaveDialog(false);
      setTemplateName('');
    } catch (error) {
      console.error('Error saving template:', error);
      alert('Error saving template');
    }
  };

  const currentConfig = selectedTool ? TOOL_CONFIGS[selectedTool] : null;

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Left Panel - Tool Selection and Parameters */}
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">🛠️ Select Cybersecurity Tool</h2>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
              {Object.entries(TOOL_CONFIGS).map(([key, config]) => (
                <button
                  key={key}
                  onClick={() => {
                    setSelectedTool(key);
                    setParameters({});
                    setGeneratedQuery('');
                  }}
                  className={`p-4 rounded-lg border-2 transition-all text-left ${
                    selectedTool === key
                      ? 'border-blue-500 bg-blue-50 shadow-md'
                      : 'border-gray-200 hover:border-blue-300 hover:bg-gray-50'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <span className="text-2xl">{config.icon}</span>
                    <div>
                      <h3 className="font-semibold">{config.name}</h3>
                      <p className="text-sm text-gray-600">{config.description}</p>
                    </div>
                  </div>
                </button>
              ))}
            </div>

            {currentConfig && (
              <div className="space-y-4">
                <h3 className="text-lg font-semibold text-gray-900">📝 Configure Parameters</h3>
                {currentConfig.fields.map(field => (
                  <FieldRenderer
                    key={field.name}
                    field={field}
                    value={parameters[field.name]}
                    onChange={(value) => handleParameterChange(field.name, value)}
                  />
                ))}
                
                <div className="flex space-x-3 pt-4">
                  <button
                    onClick={generateQuery}
                    disabled={loading || !selectedTool}
                    className="flex-1 bg-blue-600 text-white py-2 px-4 rounded-md font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {loading ? '⏳ Generating...' : '⚡ Generate Query'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Panel - Query Preview */}
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">🔍 Generated Query</h2>
            
            {generatedQuery ? (
              <div className="space-y-4">
                <div className="bg-gray-900 rounded-lg p-4 overflow-auto">
                  <pre className="text-green-400 text-sm font-mono whitespace-pre-wrap">
                    {generatedQuery}
                  </pre>
                </div>
                
                <div className="flex flex-wrap gap-3">
                  <button
                    onClick={copyToClipboard}
                    className="bg-gray-600 text-white py-2 px-4 rounded-md font-medium hover:bg-gray-700 transition-colors flex items-center space-x-1"
                  >
                    <span>📋</span>
                    <span>Copy</span>
                  </button>
                  
                  <button
                    onClick={exportQuery}
                    className="bg-green-600 text-white py-2 px-4 rounded-md font-medium hover:bg-green-700 transition-colors flex items-center space-x-1"
                  >
                    <span>📄</span>
                    <span>Export</span>
                  </button>
                  
                  <button
                    onClick={() => setShowSaveDialog(true)}
                    className="bg-purple-600 text-white py-2 px-4 rounded-md font-medium hover:bg-purple-700 transition-colors flex items-center space-x-1"
                  >
                    <span>💾</span>
                    <span>Save Template</span>
                  </button>
                </div>
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500">
                <div className="text-4xl mb-4">📋</div>
                <p>Select a tool and generate a query to see the preview here</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Save Template Dialog */}
      {showSaveDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold mb-4">💾 Save Template</h3>
            <input
              type="text"
              value={templateName}
              onChange={(e) => setTemplateName(e.target.value)}
              placeholder="Enter template name..."
              className="w-full px-3 py-2 border border-gray-300 rounded-md mb-4"
            />
            <div className="flex space-x-3">
              <button
                onClick={saveTemplate}
                className="flex-1 bg-blue-600 text-white py-2 px-4 rounded-md font-medium hover:bg-blue-700"
              >
                Save
              </button>
              <button
                onClick={() => {
                  setShowSaveDialog(false);
                  setTemplateName('');
                }}
                className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-md font-medium hover:bg-gray-400"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const SavedQueries = () => {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchTemplates();
  }, []);

  const fetchTemplates = async () => {
    try {
      const response = await axios.get(`${API}/templates`);
      setTemplates(response.data);
    } catch (error) {
      console.error('Error fetching templates:', error);
    } finally {
      setLoading(false);
    }
  };

  const deleteTemplate = async (templateId) => {
    if (!window.confirm('Are you sure you want to delete this template?')) return;
    
    try {
      await axios.delete(`${API}/template/${templateId}`);
      setTemplates(templates.filter(t => t.id !== templateId));
      alert('Template deleted successfully!');
    } catch (error) {
      console.error('Error deleting template:', error);
      alert('Error deleting template');
    }
  };

  const copyQuery = (query) => {
    navigator.clipboard.writeText(query);
    alert('Query copied to clipboard!');
  };

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="text-center py-12">
          <div className="text-4xl mb-4">⏳</div>
          <p>Loading saved queries...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <div className="bg-white rounded-lg shadow-lg">
        <div className="p-6 border-b border-gray-200">
          <h2 className="text-2xl font-bold text-gray-900">💾 Saved Query Templates</h2>
          <p className="text-gray-600 mt-2">Manage your saved cybersecurity query templates</p>
        </div>
        
        {templates.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            <div className="text-4xl mb-4">📂</div>
            <p>No saved templates yet. Create some queries and save them as templates!</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Tool</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Query Preview</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {templates.map((template) => (
                  <tr key={template.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="font-medium text-gray-900">{template.name}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                        {TOOL_CONFIGS[template.tool]?.icon} {TOOL_CONFIGS[template.tool]?.name || template.tool}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm text-gray-900 font-mono bg-gray-100 p-2 rounded max-w-md truncate">
                        {template.generated_query}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(template.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
                      <button
                        onClick={() => copyQuery(template.generated_query)}
                        className="text-blue-600 hover:text-blue-900"
                      >
                        📋 Copy
                      </button>
                      <button
                        onClick={() => deleteTemplate(template.id)}
                        className="text-red-600 hover:text-red-900"
                      >
                        🗑️ Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

const KnowledgeBase = () => {
  const [docs, setDocs] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedTool, setSelectedTool] = useState('');

  useEffect(() => {
    fetchDocs();
  }, []);

  const fetchDocs = async () => {
    try {
      const response = await axios.get(`${API}/docs`);
      setDocs(response.data);
    } catch (error) {
      console.error('Error fetching docs:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="text-center py-12">
          <div className="text-4xl mb-4">⏳</div>
          <p>Loading knowledge base...</p>
        </div>
      </div>
    );
  }

  const tools = docs?.tools || {};

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <div className="bg-white rounded-lg shadow-lg">
        <div className="p-6 border-b border-gray-200">
          <h2 className="text-2xl font-bold text-gray-900">📚 Knowledge Base</h2>
          <p className="text-gray-600 mt-2">Reference documentation for cybersecurity tools</p>
        </div>
        
        <div className="flex">
          {/* Sidebar */}
          <div className="w-64 bg-gray-50 border-r border-gray-200">
            <nav className="p-4 space-y-2">
              {Object.entries(tools).map(([key, tool]) => (
                <button
                  key={key}
                  onClick={() => setSelectedTool(key)}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    selectedTool === key
                      ? 'bg-blue-100 text-blue-700'
                      : 'text-gray-700 hover:bg-gray-100'
                  }`}
                >
                  {TOOL_CONFIGS[key]?.icon} {tool.name}
                </button>
              ))}
            </nav>
          </div>
          
          {/* Content */}
          <div className="flex-1 p-6">
            {selectedTool && tools[selectedTool] ? (
              <div className="space-y-6">
                <div>
                  <h3 className="text-xl font-bold text-gray-900 mb-2">
                    {TOOL_CONFIGS[selectedTool]?.icon} {tools[selectedTool].name}
                  </h3>
                  <p className="text-gray-600">{tools[selectedTool].description}</p>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold text-gray-900 mb-2">📖 Official Documentation</h4>
                  <a
                    href={tools[selectedTool].official_docs}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-600 hover:text-blue-800 underline"
                  >
                    {tools[selectedTool].official_docs}
                  </a>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold text-gray-900 mb-2">🔧 Available Fields</h4>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {Object.entries(tools[selectedTool].fields).map(([field, description]) => (
                        <div key={field} className="border-l-4 border-blue-500 pl-3">
                          <h5 className="font-medium text-gray-900">{field}</h5>
                          <p className="text-sm text-gray-600">
                            {Array.isArray(description) ? description.join(', ') : description}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold text-gray-900 mb-2">💡 Examples</h4>
                  <div className="space-y-2">
                    {tools[selectedTool].examples.map((example, index) => (
                      <div key={index} className="bg-gray-900 rounded-lg p-3">
                        <code className="text-green-400 text-sm">{example}</code>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500">
                <div className="text-4xl mb-4">📚</div>
                <p>Select a tool from the sidebar to view its documentation</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

function App() {
  const [activeView, setActiveView] = useState('builder');

  return (
    <div className="min-h-screen bg-gray-100">
      <Navigation activeView={activeView} setActiveView={setActiveView} />
      
      {activeView === 'builder' && <QueryBuilder />}
      {activeView === 'saved' && <SavedQueries />}
      {activeView === 'knowledge' && <KnowledgeBase />}
    </div>
  );
}

export default App;
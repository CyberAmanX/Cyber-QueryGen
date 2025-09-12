from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime, timezone
import json
import hashlib
import re

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="CyberQueryMaker Advanced Investigation Platform", version="2.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Define Models
class QueryTemplate(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    tool: str
    parameters: Dict[str, Any]
    generated_query: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class QueryTemplateCreate(BaseModel):
    name: str
    tool: str
    parameters: Dict[str, Any]

class QueryGenerateRequest(BaseModel):
    tool: str
    parameters: Dict[str, Any]

class QueryGenerateResponse(BaseModel):
    tool: str
    generated_query: str
    parameters: Dict[str, Any]

class IOCEnrichmentRequest(BaseModel):
    ioc_type: str  # "hash", "ip", "domain", "url"
    ioc_value: str
    investigation_focus: Optional[str] = "general"  # "malware", "network", "user_activity"

class IOCEnrichmentResponse(BaseModel):
    ioc_type: str
    ioc_value: str
    generated_queries: Dict[str, str]  # tool -> query mapping
    investigation_steps: List[Dict[str, Any]]
    recommendations: List[str]

class IncidentWorkflowRequest(BaseModel):
    incident_type: str  # "malware_infection", "unauthorized_access", "data_exfiltration", etc.
    context: Optional[Dict[str, Any]] = {}
    custom_iocs: Optional[List[Dict[str, str]]] = []

class IncidentWorkflowResponse(BaseModel):
    incident_type: str
    workflow_steps: List[Dict[str, Any]]
    queries: Dict[str, List[Dict[str, str]]]  # step -> [{"tool": "tool_name", "query": "query_string"}]
    timeline: List[Dict[str, Any]]

class CorrelationRequest(BaseModel):
    primary_tool: str
    secondary_tools: List[str]
    correlation_field: str  # "host", "user", "ip", "hash", "time_window"
    parameters: Dict[str, Any]

class CorrelationResponse(BaseModel):
    correlation_type: str
    correlated_queries: Dict[str, str]
    join_logic: str
    explanation: str

# Advanced Investigation Templates
class AdvancedInvestigationEngine:
    
    @staticmethod
    def get_incident_workflows():
        """Define investigation workflows for different incident types"""
        return {
            "malware_infection": {
                "name": "Malware Infection Investigation",
                "description": "Comprehensive malware investigation workflow",
                "steps": [
                    {
                        "step": 1,
                        "name": "Initial IOC Detection",
                        "description": "Detect initial indicators of compromise",
                        "tools": ["yara", "splunk", "wazuh"],
                        "focus": "file_analysis"
                    },
                    {
                        "step": 2,
                        "name": "Process Tree Analysis",
                        "description": "Analyze parent-child process relationships",
                        "tools": ["wazuh", "splunk"],
                        "focus": "process_analysis"
                    },
                    {
                        "step": 3,
                        "name": "Network Activity Investigation",
                        "description": "Investigate suspicious network connections",
                        "tools": ["splunk", "wireshark", "suricata"],
                        "focus": "network_analysis"
                    },
                    {
                        "step": 4,
                        "name": "Lateral Movement Detection",
                        "description": "Check for lateral movement patterns",
                        "tools": ["splunk", "wazuh"],
                        "focus": "lateral_movement"
                    },
                    {
                        "step": 5,
                        "name": "Impact Assessment",
                        "description": "Assess the scope and impact of infection",
                        "tools": ["splunk", "elasticsearch"],
                        "focus": "impact_analysis"
                    }
                ]
            },
            "unauthorized_access": {
                "name": "Unauthorized Access Investigation",
                "description": "Investigation workflow for unauthorized access attempts",
                "steps": [
                    {
                        "step": 1,
                        "name": "Authentication Analysis",
                        "description": "Analyze failed and successful authentication attempts",
                        "tools": ["splunk", "wazuh"],
                        "focus": "authentication"
                    },
                    {
                        "step": 2,
                        "name": "User Behavior Analysis",
                        "description": "Investigate unusual user behavior patterns",
                        "tools": ["splunk", "elasticsearch"],
                        "focus": "user_behavior"
                    },
                    {
                        "step": 3,
                        "name": "Privilege Escalation Detection",
                        "description": "Check for privilege escalation attempts",
                        "tools": ["wazuh", "splunk"],
                        "focus": "privilege_escalation"
                    },
                    {
                        "step": 4,
                        "name": "Access Pattern Analysis",
                        "description": "Analyze access patterns and data touched",
                        "tools": ["splunk", "elasticsearch"],
                        "focus": "access_analysis"
                    }
                ]
            },
            "data_exfiltration": {
                "name": "Data Exfiltration Investigation",
                "description": "Investigation workflow for potential data theft",
                "steps": [
                    {
                        "step": 1,
                        "name": "Network Traffic Analysis",
                        "description": "Analyze unusual outbound network traffic",
                        "tools": ["wireshark", "splunk", "suricata"],
                        "focus": "network_traffic"
                    },
                    {
                        "step": 2,
                        "name": "File Access Investigation",
                        "description": "Investigate file access and transfer patterns",
                        "tools": ["wazuh", "splunk"],
                        "focus": "file_access"
                    },
                    {
                        "step": 3,
                        "name": "User Activity Timeline",
                        "description": "Build timeline of user activities",
                        "tools": ["splunk", "elasticsearch"],
                        "focus": "user_timeline"
                    },
                    {
                        "step": 4,
                        "name": "Data Volume Analysis",
                        "description": "Analyze data transfer volumes and destinations",
                        "tools": ["splunk", "elasticsearch"],
                        "focus": "data_volume"
                    }
                ]
            },
            "privilege_escalation": {
                "name": "Privilege Escalation Investigation",
                "description": "Investigation workflow for privilege escalation attempts",
                "steps": [
                    {
                        "step": 1,
                        "name": "Account Activity Analysis",
                        "description": "Analyze account privilege changes and usage",
                        "tools": ["wazuh", "splunk"],
                        "focus": "account_analysis"
                    },
                    {
                        "step": 2,
                        "name": "Process Execution Analysis",
                        "description": "Investigate processes running with elevated privileges",
                        "tools": ["wazuh", "splunk"],
                        "focus": "process_privileges"
                    },
                    {
                        "step": 3,
                        "name": "System Modification Detection",
                        "description": "Check for unauthorized system modifications",
                        "tools": ["wazuh", "splunk"],
                        "focus": "system_changes"
                    }
                ]
            },
            "lateral_movement": {
                "name": "Lateral Movement Investigation",
                "description": "Investigation workflow for lateral movement detection",
                "steps": [
                    {
                        "step": 1,
                        "name": "Network Connection Analysis",
                        "description": "Analyze internal network connections and patterns",
                        "tools": ["wireshark", "splunk", "suricata"],
                        "focus": "internal_network"
                    },
                    {
                        "step": 2,
                        "name": "Remote Access Investigation",
                        "description": "Investigate remote access tools and sessions",
                        "tools": ["splunk", "wazuh"],
                        "focus": "remote_access"
                    },
                    {
                        "step": 3,
                        "name": "Credential Usage Analysis",
                        "description": "Analyze credential usage across multiple systems",
                        "tools": ["splunk", "wazuh"],
                        "focus": "credential_analysis"
                    }
                ]
            }
        }
    
    @staticmethod
    def generate_ioc_enrichment_queries(ioc_type: str, ioc_value: str, focus: str = "general") -> Dict[str, Any]:
        """Generate queries for IOC enrichment across multiple tools"""
        
        # Validate IOC type
        valid_ioc_types = ["hash", "ip", "domain", "url"]
        if ioc_type not in valid_ioc_types:
            raise ValueError(f"Unsupported IOC type: {ioc_type}. Supported types: {valid_ioc_types}")
        
        queries = {}
        steps = []
        recommendations = []
        
        if ioc_type == "hash":
            # File hash investigation
            queries["yara"] = f'''rule IOC_Hash_Detection {{
    meta:
        description = "Detection rule for IOC hash {ioc_value}"
        author = "CyberQueryMaker"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
    
    condition:
        hash.sha256("{ioc_value}") or 
        hash.md5("{ioc_value}") or
        hash.sha1("{ioc_value}")
}}'''
            
            queries["splunk"] = f'''index=ossec sourcetype=file_integrity 
| search file.hash="{ioc_value}" OR file.md5="{ioc_value}" OR file.sha1="{ioc_value}" OR file.sha256="{ioc_value}"
| table _time host file.path file.hash user process.name
| sort -_time'''
            
            queries["wazuh"] = f'''<rule id="100300" level="10">
  <description>Suspicious file hash detected: {ioc_value}</description>
  <field name="file.hash">{ioc_value}</field>
  <options>no_full_log</options>
  <group>file_integrity,malware</group>
</rule>'''
            
            queries["elasticsearch"] = f'''{{
  "query": {{
    "bool": {{
      "should": [
        {{"term": {{"file.hash.sha256": "{ioc_value}"}}}},
        {{"term": {{"file.hash.md5": "{ioc_value}"}}}},
        {{"term": {{"file.hash.sha1": "{ioc_value}"}}}}
      ]
    }}
  }},
  "sort": [{{"@timestamp": {{"order": "desc"}}}}]
}}'''
            
            steps = [
                {"step": 1, "action": "Search for file hash across all systems", "tool": "splunk"},
                {"step": 2, "action": "Create YARA rule for ongoing detection", "tool": "yara"},
                {"step": 3, "action": "Check file integrity logs", "tool": "wazuh"},
                {"step": 4, "action": "Correlate with process execution", "tool": "elasticsearch"}
            ]
            
            recommendations = [
                "Check if hash appears in VirusTotal or threat intelligence feeds",
                "Investigate parent processes that created this file",
                "Look for network connections made by processes using this file",
                "Check for similar hashes or file patterns on other systems"
            ]
        
        elif ioc_type == "ip":
            # IP address investigation
            queries["wireshark"] = f'ip.addr == {ioc_value}'
            
            queries["splunk"] = f'''index=network_traffic 
| search src_ip="{ioc_value}" OR dest_ip="{ioc_value}" OR ip="{ioc_value}"
| table _time src_ip dest_ip src_port dest_port protocol bytes
| sort -_time'''
            
            queries["suricata"] = f'''alert ip any any -> {ioc_value} any (msg:"Suspicious IP communication to {ioc_value}"; reference:url,internal_investigation; sid:1000100; rev:1;)'''
            
            queries["elasticsearch"] = f'''{{
  "query": {{
    "bool": {{
      "should": [
        {{"term": {{"source.ip": "{ioc_value}"}}}},
        {{"term": {{"destination.ip": "{ioc_value}"}}}},
        {{"term": {{"network.src_ip": "{ioc_value}"}}}},
        {{"term": {{"network.dest_ip": "{ioc_value}"}}}}
      ]
    }}
  }},
  "aggs": {{
    "unique_hosts": {{
      "terms": {{"field": "host.name"}}
    }}
  }}
}}'''
            
            steps = [
                {"step": 1, "action": "Analyze network traffic to/from IP", "tool": "splunk"},
                {"step": 2, "action": "Create network filter for packet analysis", "tool": "wireshark"},
                {"step": 3, "action": "Set up detection rule for future connections", "tool": "suricata"},
                {"step": 4, "action": "Check for connections across all hosts", "tool": "elasticsearch"}
            ]
            
            recommendations = [
                "Check IP reputation in threat intelligence feeds",
                "Investigate geographic location and ASN of IP",
                "Look for other IPs in same subnet or ASN",
                "Check DNS resolutions for this IP"
            ]
        
        elif ioc_type == "domain":
            # Domain investigation
            queries["wireshark"] = f'dns.qry.name == "{ioc_value}" or http.host == "{ioc_value}"'
            
            queries["splunk"] = f'''index=dns OR index=web_proxy OR index=network_traffic
| search query="{ioc_value}" OR domain="{ioc_value}" OR host="{ioc_value}" OR url="*{ioc_value}*"
| table _time src_ip query domain url action
| sort -_time'''
            
            queries["suricata"] = f'''alert dns any any -> any 53 (msg:"Suspicious DNS query to {ioc_value}"; dns_query; content:"{ioc_value}"; sid:1000200; rev:1;)
alert http any any -> any any (msg:"Suspicious HTTP connection to {ioc_value}"; http_host; content:"{ioc_value}"; sid:1000201; rev:1;)'''
            
            steps = [
                {"step": 1, "action": "Search DNS queries and web traffic", "tool": "splunk"},
                {"step": 2, "action": "Analyze network packets for domain", "tool": "wireshark"},
                {"step": 3, "action": "Create detection rules for domain", "tool": "suricata"}
            ]
            
            recommendations = [
                "Check domain reputation and registration details",
                "Look for subdomains and related domains",
                "Investigate SSL certificates associated with domain",
                "Check for DGA (Domain Generation Algorithm) patterns"
            ]
        
        return {
            "queries": queries,
            "investigation_steps": steps,
            "recommendations": recommendations
        }
    
    @staticmethod
    def generate_correlation_queries(primary_tool: str, secondary_tools: List[str], 
                                   correlation_field: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Generate correlation queries between multiple tools"""
        
        if correlation_field == "host":
            # Correlate by hostname/system
            if primary_tool == "splunk" and "wazuh" in secondary_tools:
                correlation_query = f'''
# Primary Splunk Query
index=security sourcetype=wineventlog host="{parameters.get('host', '*')}"
| table _time host user process.name event_code
| join host [
    # Secondary Wazuh Query  
    search index=wazuh rule.level>=5 host="{parameters.get('host', '*')}"
    | table _time host rule.description rule.level
]
| sort -_time'''
                
                explanation = "Correlates Windows security events from Splunk with Wazuh security alerts for the same host"
            
            elif primary_tool == "wazuh" and "elasticsearch" in secondary_tools:
                correlation_query = f'''
# Elasticsearch correlation query
{{
  "query": {{
    "bool": {{
      "must": [
        {{"term": {{"host.name": "{parameters.get('host', 'unknown')}"}}}},
        {{"range": {{"@timestamp": {{"gte": "now-24h"}}}}}}
      ]
    }}
  }},
  "aggs": {{
    "events_by_source": {{
      "terms": {{"field": "event.module"}},
      "aggs": {{
        "event_timeline": {{
          "date_histogram": {{"field": "@timestamp", "interval": "1h"}}
        }}
      }}
    }}
  }}
}}'''
                
                explanation = "Correlates Wazuh alerts with Elasticsearch events by hostname for comprehensive host analysis"
            
            else:
                correlation_query = f"# Basic host correlation between {primary_tool} and {secondary_tools}"
                explanation = f"Correlating {primary_tool} with {secondary_tools} by host field"
        
        elif correlation_field == "user":
            # Correlate by username
            correlation_query = f'''
index=security (sourcetype=wineventlog OR sourcetype=ossec) user="{parameters.get('user', '*')}"
| table _time host user action source_ip process.name
| join user [
    search index=network_traffic user="{parameters.get('user', '*')}"
    | table _time user src_ip dest_ip dest_port
]
| sort -_time'''
            
            explanation = "Correlates user authentication and system events with network activity for user behavior analysis"
        
        elif correlation_field == "ip":
            # Correlate by IP address
            correlation_query = f'''
# Multi-tool IP correlation
index=network_traffic src_ip="{parameters.get('ip', '*')}" OR dest_ip="{parameters.get('ip', '*')}"
| table _time src_ip dest_ip dest_port protocol bytes
| appendcols [
    search index=wazuh srcip="{parameters.get('ip', '*')}" OR dstip="{parameters.get('ip', '*')}"
    | table _time rule.description rule.level
]
| sort -_time'''
            
            explanation = "Correlates network traffic with security alerts for comprehensive IP analysis"
        
        else:
            correlation_query = f"# Time-based correlation between {primary_tool} and {secondary_tools}"
            explanation = f"Time-based correlation analysis"
        
        return {
            "correlation_type": f"{primary_tool}_to_{','.join(secondary_tools)}",
            "correlated_queries": {
                "correlation_query": correlation_query,
                "primary_tool": primary_tool,
                "secondary_tools": ','.join(secondary_tools)
            },
            "join_logic": f"JOIN ON {correlation_field}",
            "explanation": explanation
        }

# Existing QueryGenerator class with enhancements
class QueryGenerator:
    @staticmethod
    def generate_advanced_investigation_query(tool: str, investigation_type: str, parameters: Dict[str, Any]) -> str:
        """Generate advanced investigation queries with context awareness"""
        
        if investigation_type == "process_analysis" and tool == "splunk":
            return f'''index=security sourcetype=wineventlog EventCode=4688
| search NewProcessName="*{parameters.get('process_name', '*')}*"
| eval parent_process=coalesce(ParentProcessName, "unknown")
| table _time host user NewProcessName parent_process CommandLine
| join host, parent_process [
    search index=security sourcetype=wineventlog EventCode=4688
    | rename NewProcessName as parent_process
    | table _time host parent_process user
]
| sort -_time
| head 100'''
        
        elif investigation_type == "network_analysis" and tool == "wireshark":
            return f'''(ip.addr == {parameters.get('ip', '0.0.0.0')} and tcp.port == {parameters.get('port', 80)}) or 
(dns.qry.name contains "{parameters.get('domain', 'suspicious')}" and dns.flags.response == 1) or
(http.request.method == "POST" and http.request.uri contains "{parameters.get('uri_pattern', 'login')}")'''
        
        elif investigation_type == "file_analysis" and tool == "yara":
            return f'''rule Advanced_File_Investigation {{
    meta:
        description = "Advanced file analysis for {parameters.get('investigation_focus', 'malware')}"
        author = "CyberQueryMaker Advanced"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
    
    strings:
        $suspicious_string1 = "{parameters.get('string_pattern1', 'malicious')}"
        $suspicious_string2 = "{parameters.get('string_pattern2', 'trojan')}"
        $file_extension = ".{parameters.get('file_extension', 'exe')}"
        
    condition:
        (any of ($suspicious_string*)) and 
        (filesize < {parameters.get('max_size', '10MB')}) and
        $file_extension
}}'''
        
        else:
            # Fall back to basic query generation
            return QueryGenerator.generate_query(tool, parameters)
    
    @staticmethod
    def generate_wireshark_query(params: Dict[str, Any]) -> str:
        """Generate Wireshark display filter"""
        filters = []
        
        if params.get('protocol'):
            protocol = params['protocol'].lower()
            if protocol in ['tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'ftp']:
                filters.append(protocol)
        
        if params.get('ip_filter'):
            ip = params['ip_filter']
            if '/' in ip:  # CIDR notation
                filters.append(f"ip.addr == {ip}")
            else:
                filters.append(f"ip.addr == {ip}")
        
        if params.get('port'):
            port = params['port']
            if params.get('protocol') in ['tcp', 'udp']:
                filters.append(f"{params.get('protocol', 'tcp')}.port == {port}")
            else:
                filters.append(f"port == {port}")
        
        if params.get('payload_content'):
            content = params['payload_content']
            filters.append(f'frame contains "{content}"')
        
        if params.get('time_range'):
            time_range = params['time_range']
            if time_range.get('start') and time_range.get('end'):
                filters.append(f'frame.time >= "{time_range["start"]}" and frame.time <= "{time_range["end"]}"')
        
        return " and ".join(filters) if filters else "ip"

    @staticmethod
    def generate_nmap_query(params: Dict[str, Any]) -> str:
        """Generate Nmap command"""
        cmd_parts = ["nmap"]
        
        # Scan type
        scan_type = params.get('scan_type', 'syn')
        scan_types = {
            'syn': '-sS',
            'tcp': '-sT',
            'udp': '-sU',
            'ping': '-sn',
            'version': '-sV',
            'os': '-O',
            'aggressive': '-A'
        }
        if scan_type in scan_types:
            cmd_parts.append(scan_types[scan_type])
        
        # Ports
        if params.get('ports'):
            ports = params['ports']
            if ports == 'all':
                cmd_parts.append('-p-')
            elif ports == 'top1000':
                cmd_parts.append('--top-ports 1000')
            else:
                cmd_parts.append(f'-p {ports}')
        
        # Timing template
        timing = params.get('timing', 'normal')
        timing_templates = {
            'paranoid': '-T0',
            'sneaky': '-T1',
            'polite': '-T2',
            'normal': '-T3',
            'aggressive': '-T4',
            'insane': '-T5'
        }
        if timing in timing_templates:
            cmd_parts.append(timing_templates[timing])
        
        # Output format
        output_format = params.get('output_format')
        if output_format:
            formats = {
                'normal': '-oN output.txt',
                'xml': '-oX output.xml',
                'greppable': '-oG output.gnmap',
                'all': '-oA output'
            }
            if output_format in formats:
                cmd_parts.append(formats[output_format])
        
        # Extra flags
        if params.get('extra_flags'):
            cmd_parts.append(params['extra_flags'])
        
        # Target IP (required)
        target = params.get('target_ip', '127.0.0.1')
        cmd_parts.append(target)
        
        return " ".join(cmd_parts)

    @staticmethod
    def generate_splunk_query(params: Dict[str, Any]) -> str:
        """Generate Splunk SPL query"""
        query_parts = []
        
        # Index
        if params.get('index'):
            query_parts.append(f'index={params["index"]}')
        
        # Sourcetype
        if params.get('sourcetype'):
            query_parts.append(f'sourcetype={params["sourcetype"]}')
        
        # Time range
        if params.get('time_range'):
            time_range = params['time_range']
            if time_range.get('earliest'):
                query_parts.append(f'earliest={time_range["earliest"]}')
            if time_range.get('latest'):
                query_parts.append(f'latest={time_range["latest"]}')
        
        # Search filter
        if params.get('search_filter'):
            query_parts.append(params['search_filter'])
        
        # Output fields
        if params.get('output_fields'):
            fields = params['output_fields']
            if isinstance(fields, list):
                query_parts.append(f'| table {", ".join(fields)}')
            else:
                query_parts.append(f'| table {fields}')
        
        # Stats/aggregation
        if params.get('stats_command'):
            query_parts.append(f'| {params["stats_command"]}')
        
        return " ".join(query_parts) if query_parts else "index=*"

    @staticmethod
    def generate_wazuh_query(params: Dict[str, Any]) -> str:
        """Generate Wazuh rule"""
        rule_parts = []
        rule_parts.append('<rule id="100001" level="5">')
        
        if params.get('description'):
            rule_parts.append(f'  <description>{params["description"]}</description>')
        
        if params.get('if_sid'):
            rule_parts.append(f'  <if_sid>{params["if_sid"]}</if_sid>')
        
        if params.get('regex'):
            rule_parts.append(f'  <regex>{params["regex"]}</regex>')
        
        if params.get('match'):
            rule_parts.append(f'  <match>{params["match"]}</match>')
        
        if params.get('field'):
            field = params['field']
            if params.get('field_value'):
                rule_parts.append(f'  <field name="{field}">{params["field_value"]}</field>')
        
        if params.get('group'):
            rule_parts.append(f'  <group>{params["group"]}</group>')
        
        rule_parts.append('</rule>')
        
        return "\n".join(rule_parts)

    @staticmethod
    def generate_yara_query(params: Dict[str, Any]) -> str:
        """Generate YARA rule"""
        rule_name = params.get('rule_name', 'ExampleRule')
        
        rule_parts = []
        rule_parts.append(f'rule {rule_name} {{')
        
        # Meta section
        if params.get('meta'):
            rule_parts.append('    meta:')
            for key, value in params['meta'].items():
                rule_parts.append(f'        {key} = "{value}"')
        
        # Strings section
        rule_parts.append('    strings:')
        
        if params.get('strings'):
            strings = params['strings']
            if isinstance(strings, list):
                for i, string in enumerate(strings):
                    rule_parts.append(f'        $string{i+1} = "{string}"')
            else:
                rule_parts.append(f'        $string1 = "{strings}"')
        else:
            rule_parts.append('        $string1 = "suspicious_pattern"')
        
        if params.get('hex_strings'):
            hex_strings = params['hex_strings']
            if isinstance(hex_strings, list):
                for i, hex_str in enumerate(hex_strings):
                    rule_parts.append(f'        $hex{i+1} = {{ {hex_str} }}')
        
        # Condition section
        rule_parts.append('    condition:')
        
        if params.get('condition'):
            rule_parts.append(f'        {params["condition"]}')
        else:
            rule_parts.append('        any of them')
        
        rule_parts.append('}')
        
        return "\n".join(rule_parts)

    @staticmethod
    def generate_suricata_query(params: Dict[str, Any]) -> str:
        """Generate Suricata rule"""
        action = params.get('action', 'alert')
        protocol = params.get('protocol', 'tcp')
        src_ip = params.get('src_ip', 'any')
        src_port = params.get('src_port', 'any')
        dst_ip = params.get('dst_ip', 'any')
        dst_port = params.get('dst_port', 'any')
        
        rule_parts = [action, protocol, src_ip, src_port, '->', dst_ip, dst_port]
        
        # Rule options
        options = []
        
        if params.get('msg'):
            options.append(f'msg:"{params["msg"]}"')
        
        if params.get('content'):
            content = params['content']
            if isinstance(content, list):
                for c in content:
                    options.append(f'content:"{c}"')
            else:
                options.append(f'content:"{content}"')
        
        if params.get('flow'):
            options.append(f'flow:{params["flow"]}')
        
        if params.get('classtype'):
            options.append(f'classtype:{params["classtype"]}')
        
        if params.get('reference'):
            options.append(f'reference:{params["reference"]}')
        
        # SID is required
        sid = params.get('sid', '1000001')
        options.append(f'sid:{sid}')
        
        if params.get('rev'):
            options.append(f'rev:{params["rev"]}')
        
        rule_string = " ".join(rule_parts)
        if options:
            rule_string += f' ({"; ".join(options)};)'
        
        return rule_string

    @staticmethod
    def generate_elasticsearch_query(params: Dict[str, Any]) -> str:
        """Generate Elasticsearch query"""
        query = {
            "query": {}
        }
        
        query_type = params.get('query_type', 'match_all')
        
        if query_type == 'match':
            field = params.get('field', '_all')
            value = params.get('value', '*')
            query["query"] = {
                "match": {
                    field: value
                }
            }
        elif query_type == 'term':
            field = params.get('field', '_id')
            value = params.get('value', '1')
            query["query"] = {
                "term": {
                    field: value
                }
            }
        elif query_type == 'range':
            field = params.get('field', '@timestamp')
            range_params = params.get('range', {})
            query["query"] = {
                "range": {
                    field: range_params
                }
            }
        elif query_type == 'bool':
            bool_query = {"bool": {}}
            if params.get('must'):
                bool_query["bool"]["must"] = params["must"]
            if params.get('should'):
                bool_query["bool"]["should"] = params["should"]
            if params.get('must_not'):
                bool_query["bool"]["must_not"] = params["must_not"]
            if params.get('filter'):
                bool_query["bool"]["filter"] = params["filter"]
            query["query"] = bool_query
        else:
            query["query"] = {"match_all": {}}
        
        # Add aggregations if specified
        if params.get('aggs'):
            query["aggs"] = params["aggs"]
        
        # Add size if specified
        if params.get('size'):
            query["size"] = params["size"]
        
        # Add sort if specified
        if params.get('sort'):
            query["sort"] = params["sort"]
        
        return json.dumps(query, indent=2)

    @classmethod
    def generate_query(cls, tool: str, parameters: Dict[str, Any]) -> str:
        """Main query generation method"""
        generators = {
            'wireshark': cls.generate_wireshark_query,
            'nmap': cls.generate_nmap_query,
            'splunk': cls.generate_splunk_query,
            'wazuh': cls.generate_wazuh_query,
            'yara': cls.generate_yara_query,
            'suricata': cls.generate_suricata_query,
            'elasticsearch': cls.generate_elasticsearch_query
        }
        
        if tool not in generators:
            raise ValueError(f"Unsupported tool: {tool}")
        
        return generators[tool](parameters)

# Advanced API Routes
@api_router.post("/incident-workflow", response_model=IncidentWorkflowResponse)
async def generate_incident_workflow(request: IncidentWorkflowRequest):
    """Generate comprehensive investigation workflow for incident type"""
    try:
        workflows = AdvancedInvestigationEngine.get_incident_workflows()
        
        if request.incident_type not in workflows:
            raise HTTPException(status_code=400, detail=f"Unsupported incident type: {request.incident_type}")
        
        workflow = workflows[request.incident_type]
        
        # Generate queries for each step
        queries = {}
        timeline = []
        
        for step in workflow["steps"]:
            step_queries = []
            
            for tool in step["tools"]:
                # Generate context-aware queries based on step focus
                if step["focus"] == "file_analysis":
                    params = {
                        "investigation_focus": "malware",
                        "file_extension": "exe",
                        "max_size": "50MB"
                    }
                    if request.custom_iocs:
                        for ioc in request.custom_iocs:
                            if ioc["type"] == "hash":
                                params["hash"] = ioc["value"]
                    
                    query = QueryGenerator.generate_advanced_investigation_query(tool, step["focus"], params)
                    
                elif step["focus"] == "process_analysis":
                    params = {
                        "process_name": request.context.get("suspicious_process", "*"),
                        "parent_process": request.context.get("parent_process", "*")
                    }
                    query = QueryGenerator.generate_advanced_investigation_query(tool, step["focus"], params)
                    
                elif step["focus"] == "network_analysis":
                    params = {
                        "ip": request.context.get("suspicious_ip", "0.0.0.0"),
                        "port": request.context.get("port", 80),
                        "domain": request.context.get("suspicious_domain", "suspicious")
                    }
                    query = QueryGenerator.generate_advanced_investigation_query(tool, step["focus"], params)
                    
                else:
                    # Generate basic query for the tool
                    query = QueryGenerator.generate_query(tool, request.context)
                
                step_queries.append({
                    "tool": tool,
                    "query": query,
                    "description": f"{tool.capitalize()} query for {step['description']}"
                })
            
            queries[f"step_{step['step']}"] = step_queries
            
            # Add to timeline
            timeline.append({
                "step": step['step'],
                "name": step['name'],
                "description": step['description'],
                "tools": step['tools'],
                "estimated_time": "5-15 minutes",
                "priority": "high" if step['step'] <= 2 else "medium"
            })
        
        return IncidentWorkflowResponse(
            incident_type=request.incident_type,
            workflow_steps=workflow["steps"],
            queries=queries,
            timeline=timeline
        )
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.post("/ioc-enrichment", response_model=IOCEnrichmentResponse)
async def enrich_ioc(request: IOCEnrichmentRequest):
    """Enrich IOC and generate investigation queries"""
    try:
        enrichment_data = AdvancedInvestigationEngine.generate_ioc_enrichment_queries(
            request.ioc_type, 
            request.ioc_value, 
            request.investigation_focus
        )
        
        return IOCEnrichmentResponse(
            ioc_type=request.ioc_type,
            ioc_value=request.ioc_value,
            generated_queries=enrichment_data["queries"],
            investigation_steps=enrichment_data["investigation_steps"],
            recommendations=enrichment_data["recommendations"]
        )
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.post("/correlation", response_model=CorrelationResponse)
async def generate_correlation(request: CorrelationRequest):
    """Generate correlation queries between multiple tools"""
    try:
        correlation_data = AdvancedInvestigationEngine.generate_correlation_queries(
            request.primary_tool,
            request.secondary_tools,
            request.correlation_field,
            request.parameters
        )
        
        return CorrelationResponse(**correlation_data)
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.get("/incident-types")
async def get_incident_types():
    """Get available incident types for investigation workflows"""
    workflows = AdvancedInvestigationEngine.get_incident_workflows()
    
    return {
        "incident_types": [
            {
                "type": key,
                "name": workflow["name"],
                "description": workflow["description"],
                "steps": len(workflow["steps"])
            }
            for key, workflow in workflows.items()
        ]
    }

# Original API Routes (unchanged)
@api_router.post("/generate-query", response_model=QueryGenerateResponse)
async def generate_query(request: QueryGenerateRequest):
    """Generate a query/command for the specified tool"""
    try:
        generated_query = QueryGenerator.generate_query(request.tool, request.parameters)
        return QueryGenerateResponse(
            tool=request.tool,
            generated_query=generated_query,
            parameters=request.parameters
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.post("/save-template", response_model=QueryTemplate)
async def save_template(request: QueryTemplateCreate):
    """Save a query template"""
    try:
        # Generate the query for the template
        generated_query = QueryGenerator.generate_query(request.tool, request.parameters)
        
        template_dict = request.dict()
        template_dict['generated_query'] = generated_query
        template = QueryTemplate(**template_dict)
        
        # Convert datetime objects to ISO strings for MongoDB
        template_data = template.dict()
        template_data['created_at'] = template_data['created_at'].isoformat()
        template_data['updated_at'] = template_data['updated_at'].isoformat()
        
        await db.query_templates.insert_one(template_data)
        return template
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.get("/templates", response_model=List[QueryTemplate])
async def get_templates():
    """Get all saved query templates"""
    templates = await db.query_templates.find().to_list(1000)
    
    # Convert ISO strings back to datetime objects
    for template in templates:
        if isinstance(template.get('created_at'), str):
            template['created_at'] = datetime.fromisoformat(template['created_at'].replace('Z', '+00:00'))
        if isinstance(template.get('updated_at'), str):
            template['updated_at'] = datetime.fromisoformat(template['updated_at'].replace('Z', '+00:00'))
    
    return [QueryTemplate(**template) for template in templates]

@api_router.delete("/template/{template_id}")
async def delete_template(template_id: str):
    """Delete a query template"""
    result = await db.query_templates.delete_one({"id": template_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Template not found")
    return {"message": "Template deleted successfully"}

@api_router.get("/docs")
async def get_knowledge_base():
    """Get knowledge base documentation"""
    docs = {
        "tools": {
            "wireshark": {
                "name": "Wireshark Display Filters",
                "description": "Create display filters for network packet analysis",
                "official_docs": "https://www.wireshark.org/docs/dfref/",
                "examples": [
                    "ip.addr == 192.168.1.1",
                    "tcp.port == 80",
                    "http and ip.addr == 10.0.0.1"
                ],
                "fields": {
                    "protocol": ["tcp", "udp", "icmp", "http", "https", "dns", "ftp"],
                    "ip_filter": "IP address or CIDR notation",
                    "port": "Port number",
                    "payload_content": "Content to search for in packet payload",
                    "time_range": "Time range filter"
                }
            },
            "nmap": {
                "name": "Nmap Network Scanner",
                "description": "Generate network scanning commands",
                "official_docs": "https://nmap.org/book/man.html",
                "examples": [
                    "nmap -sS -p 1-65535 192.168.1.1",
                    "nmap -sV --top-ports 1000 target.com",
                    "nmap -A -T4 192.168.1.0/24"
                ],
                "fields": {
                    "target_ip": "Target IP address or hostname",
                    "scan_type": ["syn", "tcp", "udp", "ping", "version", "os", "aggressive"],
                    "ports": "Port specification (e.g., 80, 1-1000, all, top1000)",
                    "timing": ["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"],
                    "output_format": ["normal", "xml", "greppable", "all"]
                }
            },
            "splunk": {
                "name": "Splunk SPL Queries",
                "description": "Create Splunk Search Processing Language queries",
                "official_docs": "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/",
                "examples": [
                    "index=security sourcetype=wineventlog EventCode=4625",
                    "index=web_logs status=404 | stats count by uri",
                    "index=* error | head 100"
                ],
                "fields": {
                    "index": "Splunk index name",
                    "sourcetype": "Source type",
                    "search_filter": "Search terms and filters",
                    "time_range": "Time range specification",
                    "output_fields": "Fields to display",
                    "stats_command": "Statistical commands"
                }
            },
            "wazuh": {
                "name": "Wazuh Rules",
                "description": "Create Wazuh detection rules",
                "official_docs": "https://documentation.wazuh.com/current/user-manual/ruleset/",
                "examples": [
                    "Rule for failed SSH login attempts",
                    "Rule for file integrity monitoring",
                    "Rule for privilege escalation detection"
                ],
                "fields": {
                    "description": "Rule description",
                    "if_sid": "Parent rule SID",
                    "regex": "Regular expression pattern",
                    "match": "Match pattern",
                    "field": "Field name and value",
                    "group": "Rule group"
                }
            },
            "yara": {
                "name": "YARA Rules",
                "description": "Create malware detection patterns",
                "official_docs": "https://yara.readthedocs.io/en/stable/",
                "examples": [
                    "Rule to detect specific malware family",
                    "Rule to identify suspicious strings",
                    "Rule for file type identification"
                ],
                "fields": {
                    "rule_name": "Name of the YARA rule",
                    "meta": "Metadata information",
                    "strings": "String patterns to match",
                    "hex_strings": "Hexadecimal patterns",
                    "condition": "Rule condition logic"
                }
            },
            "suricata": {
                "name": "Suricata Rules",
                "description": "Create network intrusion detection rules",
                "official_docs": "https://suricata.readthedocs.io/en/latest/rules/",
                "examples": [
                    "alert tcp any any -> any 80 (msg:\"HTTP Traffic\"; sid:1000001;)",
                    "drop tcp any any -> any 22 (msg:\"SSH Brute Force\"; sid:1000002;)"
                ],
                "fields": {
                    "action": ["alert", "drop", "reject", "pass"],
                    "protocol": ["tcp", "udp", "icmp", "ip"],
                    "src_ip": "Source IP address",
                    "src_port": "Source port",
                    "dst_ip": "Destination IP address",
                    "dst_port": "Destination port",
                    "msg": "Alert message",
                    "content": "Content to match",
                    "flow": "Flow direction",
                    "sid": "Signature ID"
                }
            },
            "elasticsearch": {
                "name": "Elasticsearch Queries",
                "description": "Create Elasticsearch Query DSL",
                "official_docs": "https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html",
                "examples": [
                    "Match query for text search",
                    "Range query for date filtering",
                    "Boolean query with multiple conditions"
                ],
                "fields": {
                    "query_type": ["match", "term", "range", "bool", "match_all"],
                    "field": "Field name to query",
                    "value": "Value to search for",
                    "range": "Range parameters (gte, lte, etc.)",
                    "size": "Number of results to return",
                    "sort": "Sort parameters"
                }
            }
        }
    }
    return docs

# Health check
@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
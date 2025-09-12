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

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="CyberQueryMaker API", version="1.0.0")

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

# Query Generation Templates
class QueryGenerator:
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

# API Routes
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
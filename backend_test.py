#!/usr/bin/env python3
"""
Comprehensive Backend API Testing for CyberQueryMaker
Tests all 7 cybersecurity tools and template management functionality
"""

import requests
import json
import sys
from datetime import datetime
import uuid

# Backend URL from environment
BACKEND_URL = "https://querybuilder.preview.emergentagent.com/api"

class CyberQueryMakerTester:
    def __init__(self):
        self.session = requests.Session()
        self.test_results = []
        self.saved_template_ids = []
        
    def log_test(self, test_name, success, details="", response_data=None):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   Details: {details}")
        if response_data and not success:
            print(f"   Response: {response_data}")
        print()
        
        self.test_results.append({
            'test': test_name,
            'success': success,
            'details': details,
            'response': response_data
        })
    
    def test_health_check(self):
        """Test health check endpoint"""
        try:
            response = self.session.get(f"{BACKEND_URL}/health")
            if response.status_code == 200:
                data = response.json()
                if 'status' in data and data['status'] == 'healthy':
                    self.log_test("Health Check", True, f"Status: {data['status']}")
                    return True
                else:
                    self.log_test("Health Check", False, f"Invalid response format: {data}")
                    return False
            else:
                self.log_test("Health Check", False, f"HTTP {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("Health Check", False, f"Exception: {str(e)}")
            return False
    
    def test_wireshark_query_generation(self):
        """Test Wireshark query generation"""
        test_cases = [
            {
                "name": "Basic TCP Filter",
                "params": {
                    "tool": "wireshark",
                    "parameters": {
                        "protocol": "tcp",
                        "ip_filter": "192.168.1.100",
                        "port": "443"
                    }
                },
                "expected_contains": ["tcp", "192.168.1.100", "443"]
            },
            {
                "name": "HTTP Traffic Analysis",
                "params": {
                    "tool": "wireshark",
                    "parameters": {
                        "protocol": "http",
                        "payload_content": "POST /login"
                    }
                },
                "expected_contains": ["http", "POST /login"]
            },
            {
                "name": "Network Range Filter",
                "params": {
                    "tool": "wireshark",
                    "parameters": {
                        "protocol": "udp",
                        "ip_filter": "10.0.0.0/24",
                        "port": "53"
                    }
                },
                "expected_contains": ["udp", "10.0.0.0/24", "53"]
            }
        ]
        
        for case in test_cases:
            try:
                response = self.session.post(f"{BACKEND_URL}/generate-query", json=case["params"])
                if response.status_code == 200:
                    data = response.json()
                    query = data.get('generated_query', '')
                    
                    # Check if expected elements are in the query
                    all_found = all(expected in query.lower() for expected in [str(e).lower() for e in case["expected_contains"]])
                    
                    if all_found:
                        self.log_test(f"Wireshark - {case['name']}", True, f"Generated: {query}")
                    else:
                        self.log_test(f"Wireshark - {case['name']}", False, f"Missing expected elements in: {query}")
                else:
                    self.log_test(f"Wireshark - {case['name']}", False, f"HTTP {response.status_code}", response.text)
            except Exception as e:
                self.log_test(f"Wireshark - {case['name']}", False, f"Exception: {str(e)}")
    
    def test_nmap_query_generation(self):
        """Test Nmap query generation"""
        test_cases = [
            {
                "name": "SYN Scan",
                "params": {
                    "tool": "nmap",
                    "parameters": {
                        "target_ip": "scanme.nmap.org",
                        "scan_type": "syn",
                        "ports": "1-1000",
                        "timing": "aggressive"
                    }
                },
                "expected_contains": ["nmap", "-sS", "scanme.nmap.org", "-p 1-1000", "-T4"]
            },
            {
                "name": "Version Detection",
                "params": {
                    "tool": "nmap",
                    "parameters": {
                        "target_ip": "192.168.1.1",
                        "scan_type": "version",
                        "ports": "top1000",
                        "output_format": "xml"
                    }
                },
                "expected_contains": ["nmap", "-sV", "192.168.1.1", "--top-ports 1000", "-oX"]
            },
            {
                "name": "OS Detection",
                "params": {
                    "tool": "nmap",
                    "parameters": {
                        "target_ip": "10.0.0.1",
                        "scan_type": "os",
                        "timing": "polite"
                    }
                },
                "expected_contains": ["nmap", "-O", "10.0.0.1", "-T2"]
            }
        ]
        
        for case in test_cases:
            try:
                response = self.session.post(f"{BACKEND_URL}/generate-query", json=case["params"])
                if response.status_code == 200:
                    data = response.json()
                    query = data.get('generated_query', '')
                    
                    all_found = all(expected in query for expected in case["expected_contains"])
                    
                    if all_found:
                        self.log_test(f"Nmap - {case['name']}", True, f"Generated: {query}")
                    else:
                        self.log_test(f"Nmap - {case['name']}", False, f"Missing expected elements in: {query}")
                else:
                    self.log_test(f"Nmap - {case['name']}", False, f"HTTP {response.status_code}", response.text)
            except Exception as e:
                self.log_test(f"Nmap - {case['name']}", False, f"Exception: {str(e)}")
    
    def test_splunk_query_generation(self):
        """Test Splunk query generation"""
        test_cases = [
            {
                "name": "Security Event Search",
                "params": {
                    "tool": "splunk",
                    "parameters": {
                        "index": "security",
                        "sourcetype": "wineventlog",
                        "search_filter": "EventCode=4625",
                        "output_fields": ["user", "src_ip", "_time"]
                    }
                },
                "expected_contains": ["index=security", "sourcetype=wineventlog", "EventCode=4625", "table user, src_ip, _time"]
            },
            {
                "name": "Web Log Analysis",
                "params": {
                    "tool": "splunk",
                    "parameters": {
                        "index": "web_logs",
                        "search_filter": "status=404",
                        "stats_command": "stats count by uri"
                    }
                },
                "expected_contains": ["index=web_logs", "status=404", "stats count by uri"]
            },
            {
                "name": "Time Range Query",
                "params": {
                    "tool": "splunk",
                    "parameters": {
                        "index": "firewall",
                        "time_range": {
                            "earliest": "-24h",
                            "latest": "now"
                        },
                        "search_filter": "action=blocked"
                    }
                },
                "expected_contains": ["index=firewall", "earliest=-24h", "latest=now", "action=blocked"]
            }
        ]
        
        for case in test_cases:
            try:
                response = self.session.post(f"{BACKEND_URL}/generate-query", json=case["params"])
                if response.status_code == 200:
                    data = response.json()
                    query = data.get('generated_query', '')
                    
                    all_found = all(expected in query for expected in case["expected_contains"])
                    
                    if all_found:
                        self.log_test(f"Splunk - {case['name']}", True, f"Generated: {query}")
                    else:
                        self.log_test(f"Splunk - {case['name']}", False, f"Missing expected elements in: {query}")
                else:
                    self.log_test(f"Splunk - {case['name']}", False, f"HTTP {response.status_code}", response.text)
            except Exception as e:
                self.log_test(f"Splunk - {case['name']}", False, f"Exception: {str(e)}")
    
    def test_wazuh_query_generation(self):
        """Test Wazuh rule generation"""
        test_cases = [
            {
                "name": "Failed Login Detection",
                "params": {
                    "tool": "wazuh",
                    "parameters": {
                        "description": "Multiple failed SSH login attempts",
                        "if_sid": "5716",
                        "regex": "authentication failure.*user=(\S+)",
                        "group": "authentication_failed,pci_dss_10.2.4"
                    }
                },
                "expected_contains": ["<rule id=", "<description>Multiple failed SSH login attempts</description>", "<if_sid>5716</if_sid>", "<regex>authentication failure.*user=(\\S+)</regex>"]
            },
            {
                "name": "File Integrity Monitoring",
                "params": {
                    "tool": "wazuh",
                    "parameters": {
                        "description": "Critical system file modified",
                        "match": "/etc/passwd",
                        "field": "file",
                        "field_value": "/etc/passwd",
                        "group": "syscheck,pci_dss_11.5"
                    }
                },
                "expected_contains": ["<description>Critical system file modified</description>", "<match>/etc/passwd</match>", "<field name=\"file\">/etc/passwd</field>"]
            }
        ]
        
        for case in test_cases:
            try:
                response = self.session.post(f"{BACKEND_URL}/generate-query", json=case["params"])
                if response.status_code == 200:
                    data = response.json()
                    query = data.get('generated_query', '')
                    
                    all_found = all(expected in query for expected in case["expected_contains"])
                    
                    if all_found:
                        self.log_test(f"Wazuh - {case['name']}", True, f"Generated rule with proper XML structure")
                    else:
                        self.log_test(f"Wazuh - {case['name']}", False, f"Missing expected elements in: {query}")
                else:
                    self.log_test(f"Wazuh - {case['name']}", False, f"HTTP {response.status_code}", response.text)
            except Exception as e:
                self.log_test(f"Wazuh - {case['name']}", False, f"Exception: {str(e)}")
    
    def test_yara_query_generation(self):
        """Test YARA rule generation"""
        test_cases = [
            {
                "name": "Malware Detection Rule",
                "params": {
                    "tool": "yara",
                    "parameters": {
                        "rule_name": "SuspiciousPowerShell",
                        "meta": {
                            "author": "Security Team",
                            "description": "Detects suspicious PowerShell commands",
                            "date": "2024-01-15"
                        },
                        "strings": ["powershell.exe -enc", "IEX (New-Object", "DownloadString"],
                        "condition": "any of them"
                    }
                },
                "expected_contains": ["rule SuspiciousPowerShell", "meta:", "author = \"Security Team\"", "strings:", "$string1 = \"powershell.exe -enc\"", "condition:", "any of them"]
            },
            {
                "name": "File Type Detection",
                "params": {
                    "tool": "yara",
                    "parameters": {
                        "rule_name": "PEFileDetection",
                        "hex_strings": ["4D 5A", "50 45 00 00"],
                        "condition": "$hex1 at 0 and $hex2"
                    }
                },
                "expected_contains": ["rule PEFileDetection", "$hex1 = { 4D 5A }", "$hex2 = { 50 45 00 00 }", "$hex1 at 0 and $hex2"]
            }
        ]
        
        for case in test_cases:
            try:
                response = self.session.post(f"{BACKEND_URL}/generate-query", json=case["params"])
                if response.status_code == 200:
                    data = response.json()
                    query = data.get('generated_query', '')
                    
                    all_found = all(expected in query for expected in case["expected_contains"])
                    
                    if all_found:
                        self.log_test(f"YARA - {case['name']}", True, f"Generated valid YARA rule structure")
                    else:
                        self.log_test(f"YARA - {case['name']}", False, f"Missing expected elements in: {query}")
                else:
                    self.log_test(f"YARA - {case['name']}", False, f"HTTP {response.status_code}", response.text)
            except Exception as e:
                self.log_test(f"YARA - {case['name']}", False, f"Exception: {str(e)}")
    
    def test_suricata_query_generation(self):
        """Test Suricata rule generation"""
        test_cases = [
            {
                "name": "HTTP Attack Detection",
                "params": {
                    "tool": "suricata",
                    "parameters": {
                        "action": "alert",
                        "protocol": "tcp",
                        "src_ip": "any",
                        "src_port": "any",
                        "dst_ip": "any",
                        "dst_port": "80",
                        "msg": "Possible SQL Injection Attack",
                        "content": ["SELECT * FROM", "UNION SELECT"],
                        "flow": "to_server,established",
                        "classtype": "web-application-attack",
                        "sid": "2000001"
                    }
                },
                "expected_contains": ["alert tcp any any -> any 80", "msg:\"Possible SQL Injection Attack\"", "content:\"SELECT * FROM\"", "content:\"UNION SELECT\"", "sid:2000001"]
            },
            {
                "name": "SSH Brute Force Detection",
                "params": {
                    "tool": "suricata",
                    "parameters": {
                        "action": "drop",
                        "protocol": "tcp",
                        "src_ip": "any",
                        "src_port": "any",
                        "dst_ip": "$HOME_NET",
                        "dst_port": "22",
                        "msg": "SSH Brute Force Attack Detected",
                        "content": "SSH-2.0",
                        "classtype": "attempted-admin",
                        "sid": "2000002",
                        "rev": "1"
                    }
                },
                "expected_contains": ["drop tcp any any -> $HOME_NET 22", "msg:\"SSH Brute Force Attack Detected\"", "content:\"SSH-2.0\"", "sid:2000002", "rev:1"]
            }
        ]
        
        for case in test_cases:
            try:
                response = self.session.post(f"{BACKEND_URL}/generate-query", json=case["params"])
                if response.status_code == 200:
                    data = response.json()
                    query = data.get('generated_query', '')
                    
                    all_found = all(expected in query for expected in case["expected_contains"])
                    
                    if all_found:
                        self.log_test(f"Suricata - {case['name']}", True, f"Generated: {query}")
                    else:
                        self.log_test(f"Suricata - {case['name']}", False, f"Missing expected elements in: {query}")
                else:
                    self.log_test(f"Suricata - {case['name']}", False, f"HTTP {response.status_code}", response.text)
            except Exception as e:
                self.log_test(f"Suricata - {case['name']}", False, f"Exception: {str(e)}")
    
    def test_elasticsearch_query_generation(self):
        """Test Elasticsearch query generation"""
        test_cases = [
            {
                "name": "Security Log Search",
                "params": {
                    "tool": "elasticsearch",
                    "parameters": {
                        "query_type": "match",
                        "field": "event.action",
                        "value": "login_failed",
                        "size": 100,
                        "sort": [{"@timestamp": {"order": "desc"}}]
                    }
                },
                "expected_contains": ["\"match\"", "\"event.action\"", "\"login_failed\"", "\"size\": 100", "\"sort\""]
            },
            {
                "name": "Time Range Query",
                "params": {
                    "tool": "elasticsearch",
                    "parameters": {
                        "query_type": "range",
                        "field": "@timestamp",
                        "range": {
                            "gte": "2024-01-01T00:00:00Z",
                            "lte": "2024-01-31T23:59:59Z"
                        }
                    }
                },
                "expected_contains": ["\"range\"", "\"@timestamp\"", "\"gte\"", "\"lte\"", "2024-01-01T00:00:00Z"]
            },
            {
                "name": "Boolean Query",
                "params": {
                    "tool": "elasticsearch",
                    "parameters": {
                        "query_type": "bool",
                        "must": [{"match": {"source.ip": "192.168.1.100"}}],
                        "should": [{"match": {"event.severity": "high"}}],
                        "must_not": [{"match": {"event.outcome": "success"}}]
                    }
                },
                "expected_contains": ["\"bool\"", "\"must\"", "\"should\"", "\"must_not\"", "\"source.ip\"", "192.168.1.100"]
            }
        ]
        
        for case in test_cases:
            try:
                response = self.session.post(f"{BACKEND_URL}/generate-query", json=case["params"])
                if response.status_code == 200:
                    data = response.json()
                    query = data.get('generated_query', '')
                    
                    # Parse JSON to validate structure
                    try:
                        json.loads(query)
                        json_valid = True
                    except:
                        json_valid = False
                    
                    all_found = all(expected in query for expected in case["expected_contains"])
                    
                    if all_found and json_valid:
                        self.log_test(f"Elasticsearch - {case['name']}", True, f"Generated valid JSON query")
                    else:
                        self.log_test(f"Elasticsearch - {case['name']}", False, f"Invalid JSON or missing elements in: {query}")
                else:
                    self.log_test(f"Elasticsearch - {case['name']}", False, f"HTTP {response.status_code}", response.text)
            except Exception as e:
                self.log_test(f"Elasticsearch - {case['name']}", False, f"Exception: {str(e)}")
    
    def test_template_management(self):
        """Test template save, retrieve, and delete functionality"""
        
        # Test saving templates
        test_templates = [
            {
                "name": "Network Reconnaissance Scan",
                "tool": "nmap",
                "parameters": {
                    "target_ip": "target.example.com",
                    "scan_type": "syn",
                    "ports": "1-65535",
                    "timing": "aggressive",
                    "output_format": "xml"
                }
            },
            {
                "name": "Failed Login Detection",
                "tool": "splunk",
                "parameters": {
                    "index": "security",
                    "sourcetype": "wineventlog",
                    "search_filter": "EventCode=4625",
                    "output_fields": ["user", "src_ip", "_time"],
                    "stats_command": "stats count by user"
                }
            },
            {
                "name": "Suspicious PowerShell Activity",
                "tool": "yara",
                "parameters": {
                    "rule_name": "SuspiciousPowerShell",
                    "meta": {
                        "author": "SOC Team",
                        "description": "Detects obfuscated PowerShell commands"
                    },
                    "strings": ["powershell.exe -enc", "IEX (New-Object"],
                    "condition": "any of them"
                }
            }
        ]
        
        # Save templates
        for template in test_templates:
            try:
                response = self.session.post(f"{BACKEND_URL}/save-template", json=template)
                if response.status_code == 200:
                    data = response.json()
                    template_id = data.get('id')
                    if template_id:
                        self.saved_template_ids.append(template_id)
                        self.log_test(f"Save Template - {template['name']}", True, f"Saved with ID: {template_id}")
                    else:
                        self.log_test(f"Save Template - {template['name']}", False, "No ID returned")
                else:
                    self.log_test(f"Save Template - {template['name']}", False, f"HTTP {response.status_code}", response.text)
            except Exception as e:
                self.log_test(f"Save Template - {template['name']}", False, f"Exception: {str(e)}")
        
        # Retrieve all templates
        try:
            response = self.session.get(f"{BACKEND_URL}/templates")
            if response.status_code == 200:
                templates = response.json()
                if isinstance(templates, list) and len(templates) >= len(test_templates):
                    self.log_test("Retrieve Templates", True, f"Retrieved {len(templates)} templates")
                    
                    # Verify template structure
                    for template in templates:
                        required_fields = ['id', 'name', 'tool', 'parameters', 'generated_query']
                        if all(field in template for field in required_fields):
                            continue
                        else:
                            self.log_test("Template Structure Validation", False, f"Missing required fields in template: {template}")
                            break
                    else:
                        self.log_test("Template Structure Validation", True, "All templates have required fields")
                else:
                    self.log_test("Retrieve Templates", False, f"Expected at least {len(test_templates)} templates, got {len(templates) if isinstance(templates, list) else 'invalid response'}")
            else:
                self.log_test("Retrieve Templates", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Retrieve Templates", False, f"Exception: {str(e)}")
        
        # Delete templates
        for template_id in self.saved_template_ids:
            try:
                response = self.session.delete(f"{BACKEND_URL}/template/{template_id}")
                if response.status_code == 200:
                    self.log_test(f"Delete Template - {template_id}", True, "Template deleted successfully")
                else:
                    self.log_test(f"Delete Template - {template_id}", False, f"HTTP {response.status_code}", response.text)
            except Exception as e:
                self.log_test(f"Delete Template - {template_id}", False, f"Exception: {str(e)}")
    
    def test_knowledge_base(self):
        """Test knowledge base endpoint"""
        try:
            response = self.session.get(f"{BACKEND_URL}/docs")
            if response.status_code == 200:
                docs = response.json()
                
                # Check if all 7 tools are documented
                expected_tools = ['wireshark', 'nmap', 'splunk', 'wazuh', 'yara', 'suricata', 'elasticsearch']
                tools_data = docs.get('tools', {})
                
                missing_tools = []
                for tool in expected_tools:
                    if tool not in tools_data:
                        missing_tools.append(tool)
                    else:
                        # Check if tool has required documentation fields
                        tool_doc = tools_data[tool]
                        required_fields = ['name', 'description', 'official_docs', 'examples', 'fields']
                        missing_fields = [field for field in required_fields if field not in tool_doc]
                        if missing_fields:
                            self.log_test(f"Knowledge Base - {tool} documentation", False, f"Missing fields: {missing_fields}")
                        else:
                            self.log_test(f"Knowledge Base - {tool} documentation", True, f"Complete documentation with {len(tool_doc.get('examples', []))} examples")
                
                if missing_tools:
                    self.log_test("Knowledge Base - Tool Coverage", False, f"Missing tools: {missing_tools}")
                else:
                    self.log_test("Knowledge Base - Tool Coverage", True, "All 7 tools documented")
                    
            else:
                self.log_test("Knowledge Base", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Knowledge Base", False, f"Exception: {str(e)}")
    
    def test_error_handling(self):
        """Test error handling and validation"""
        
        # Test invalid tool
        try:
            response = self.session.post(f"{BACKEND_URL}/generate-query", json={
                "tool": "invalid_tool",
                "parameters": {}
            })
            if response.status_code == 400:
                self.log_test("Error Handling - Invalid Tool", True, "Properly rejected invalid tool")
            else:
                self.log_test("Error Handling - Invalid Tool", False, f"Expected 400, got {response.status_code}")
        except Exception as e:
            self.log_test("Error Handling - Invalid Tool", False, f"Exception: {str(e)}")
        
        # Test malformed request
        try:
            response = self.session.post(f"{BACKEND_URL}/generate-query", json={
                "invalid_field": "test"
            })
            if response.status_code in [400, 422]:  # 422 for validation errors
                self.log_test("Error Handling - Malformed Request", True, "Properly rejected malformed request")
            else:
                self.log_test("Error Handling - Malformed Request", False, f"Expected 400/422, got {response.status_code}")
        except Exception as e:
            self.log_test("Error Handling - Malformed Request", False, f"Exception: {str(e)}")
        
        # Test delete non-existent template
        try:
            fake_id = str(uuid.uuid4())
            response = self.session.delete(f"{BACKEND_URL}/template/{fake_id}")
            if response.status_code == 404:
                self.log_test("Error Handling - Delete Non-existent Template", True, "Properly returned 404 for non-existent template")
            else:
                self.log_test("Error Handling - Delete Non-existent Template", False, f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("Error Handling - Delete Non-existent Template", False, f"Exception: {str(e)}")
    
    def run_all_tests(self):
        """Run all backend tests"""
        print("=" * 80)
        print("CYBERQUERYMAKER BACKEND API COMPREHENSIVE TESTING")
        print("=" * 80)
        print(f"Testing Backend URL: {BACKEND_URL}")
        print(f"Test Started: {datetime.now().isoformat()}")
        print("=" * 80)
        print()
        
        # Health check first
        self.test_health_check()
        
        # Test query generation for all 7 tools
        print("🔍 TESTING QUERY GENERATION FOR ALL 7 TOOLS")
        print("-" * 50)
        self.test_wireshark_query_generation()
        self.test_nmap_query_generation()
        self.test_splunk_query_generation()
        self.test_wazuh_query_generation()
        self.test_yara_query_generation()
        self.test_suricata_query_generation()
        self.test_elasticsearch_query_generation()
        
        # Test template management
        print("📝 TESTING TEMPLATE MANAGEMENT")
        print("-" * 50)
        self.test_template_management()
        
        # Test knowledge base
        print("📚 TESTING KNOWLEDGE BASE")
        print("-" * 50)
        self.test_knowledge_base()
        
        # Test error handling
        print("⚠️  TESTING ERROR HANDLING")
        print("-" * 50)
        self.test_error_handling()
        
        # Summary
        print("=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  - {result['test']}: {result['details']}")
        
        print(f"\nTest Completed: {datetime.now().isoformat()}")
        print("=" * 80)
        
        return failed_tests == 0

if __name__ == "__main__":
    tester = CyberQueryMakerTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)
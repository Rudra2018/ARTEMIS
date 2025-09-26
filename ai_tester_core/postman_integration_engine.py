#!/usr/bin/env python3
"""
Postman Integration Engine for ARTEMIS
=====================================

Advanced Postman collection parser and auto-discovery system that:
- Automatically extracts all API endpoints from Postman collections
- Identifies LLM-related endpoints (chat, completion, conversation endpoints)
- Maps request/response patterns specific to LLM services
- Detects authentication mechanisms (API keys, tokens, OAuth)
- Analyzes request body structures for prompt injection points
- Identifies session management patterns

This engine transforms ARTEMIS into a developer-friendly tool that can
automatically configure security testing from existing Postman collections.
"""

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse

import aiohttp
import yaml


class EndpointType(Enum):
    """Types of API endpoints detected"""
    LLM_CHAT = "llm_chat"
    LLM_COMPLETION = "llm_completion"
    LLM_CONVERSATION = "llm_conversation"
    LLM_EMBEDDING = "llm_embedding"
    LLM_FINE_TUNING = "llm_fine_tuning"
    AUTHENTICATION = "authentication"
    SESSION_MANAGEMENT = "session_management"
    DATA_RETRIEVAL = "data_retrieval"
    FILE_UPLOAD = "file_upload"
    GENERIC_API = "generic_api"
    WEBHOOK = "webhook"
    STREAMING = "streaming"


class AuthType(Enum):
    """Authentication mechanisms detected"""
    API_KEY_HEADER = "api_key_header"
    API_KEY_QUERY = "api_key_query"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    OAUTH2 = "oauth2"
    CUSTOM_HEADER = "custom_header"
    SESSION_COOKIE = "session_cookie"
    NONE = "none"


@dataclass
class InjectionPoint:
    """Represents a potential injection point in a request"""
    location: str  # "body", "header", "query", "path"
    field_path: str  # JSONPath-like notation for nested fields
    field_name: str
    field_type: str  # "text", "json", "array", "file"
    sample_value: Any
    injection_priority: int  # 1-10, higher = more likely to be vulnerable
    context_hints: List[str] = field(default_factory=list)


@dataclass
class APIEndpoint:
    """Represents an analyzed API endpoint"""
    id: str
    url: str
    method: str
    endpoint_type: EndpointType
    auth_type: AuthType
    headers: Dict[str, str]
    query_params: Dict[str, Any]
    body_schema: Dict[str, Any]
    injection_points: List[InjectionPoint]
    session_management: Dict[str, Any]
    rate_limiting: Dict[str, Any]
    context_clues: List[str]
    security_priority: int  # 1-10, higher = more critical to test
    llm_indicators: List[str] = field(default_factory=list)
    healthcare_indicators: List[str] = field(default_factory=list)
    compliance_tags: List[str] = field(default_factory=list)


@dataclass
class PostmanCollection:
    """Represents a parsed Postman collection"""
    name: str
    description: str
    endpoints: List[APIEndpoint]
    variables: Dict[str, Any]
    auth_config: Dict[str, Any]
    base_urls: Set[str]
    testing_profile: Dict[str, Any]
    metadata: Dict[str, Any]


class PostmanIntegrationEngine:
    """Advanced Postman collection parser and analysis engine"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the Postman integration engine"""
        self.logger = logger or logging.getLogger(__name__)

        # LLM-specific patterns
        self.llm_url_patterns = [
            r'/chat(/|$)',
            r'/completion(/|$)',
            r'/generate(/|$)',
            r'/v1/chat/completions',
            r'/v1/completions',
            r'/api/conversation',
            r'/ask',
            r'/query',
            r'/prompt',
            r'/inference',
            r'/models?/[^/]+/(chat|complete|generate)',
        ]

        # Healthcare-specific patterns
        self.healthcare_patterns = [
            r'medical', r'health', r'patient', r'doctor', r'clinic',
            r'hospital', r'diagnosis', r'treatment', r'prescription',
            r'symptom', r'medication', r'therapy'
        ]

        # Authentication patterns
        self.auth_patterns = {
            'api_key_headers': ['x-api-key', 'api-key', 'apikey', 'authorization'],
            'bearer_patterns': [r'bearer\s+', r'token\s+'],
            'oauth_indicators': ['oauth', 'access_token', 'refresh_token'],
        }

    async def parse_collection(self, collection_data: Union[str, Dict, Path]) -> PostmanCollection:
        """Parse a Postman collection from various sources"""
        try:
            # Handle different input types
            if isinstance(collection_data, (str, Path)):
                if Path(collection_data).exists():
                    with open(collection_data, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                else:
                    data = json.loads(collection_data)
            else:
                data = collection_data

            self.logger.info(f"Parsing Postman collection: {data.get('info', {}).get('name', 'Unknown')}")

            # Extract basic information
            info = data.get('info', {})
            name = info.get('name', 'Unnamed Collection')
            description = info.get('description', '')

            # Extract variables
            variables = self._extract_variables(data)

            # Extract authentication
            auth_config = self._extract_auth_config(data)

            # Parse all endpoints
            endpoints = await self._parse_items(data.get('item', []), variables)

            # Analyze base URLs
            base_urls = self._extract_base_urls(endpoints)

            # Generate testing profile
            testing_profile = self._generate_testing_profile(endpoints, auth_config)

            # Collect metadata
            metadata = {
                'parsed_at': datetime.utcnow().isoformat(),
                'total_endpoints': len(endpoints),
                'llm_endpoints': len([e for e in endpoints if e.endpoint_type.value.startswith('llm_')]),
                'high_priority_endpoints': len([e for e in endpoints if e.security_priority >= 8]),
                'auth_types': list(set([e.auth_type.value for e in endpoints])),
                'postman_version': info.get('schema', 'unknown')
            }

            collection = PostmanCollection(
                name=name,
                description=description,
                endpoints=endpoints,
                variables=variables,
                auth_config=auth_config,
                base_urls=base_urls,
                testing_profile=testing_profile,
                metadata=metadata
            )

            self.logger.info(f"Successfully parsed collection with {len(endpoints)} endpoints")
            return collection

        except Exception as e:
            self.logger.error(f"Error parsing Postman collection: {str(e)}")
            raise

    def _extract_variables(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract collection and environment variables"""
        variables = {}

        # Collection variables
        for var in data.get('variable', []):
            key = var.get('key')
            value = var.get('value', '')
            if key:
                variables[key] = value

        # Check for environment references
        # These would typically be resolved at runtime
        return variables

    def _extract_auth_config(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract authentication configuration"""
        auth_config = {}

        auth = data.get('auth', {})
        if auth:
            auth_type = auth.get('type', 'none')
            auth_config['type'] = auth_type
            auth_config['config'] = auth.get(auth_type, {})

        return auth_config

    async def _parse_items(self, items: List[Dict[str, Any]], variables: Dict[str, Any],
                          parent_auth: Optional[Dict[str, Any]] = None) -> List[APIEndpoint]:
        """Recursively parse Postman collection items"""
        endpoints = []

        for item in items:
            if 'item' in item:
                # This is a folder, recurse into it
                folder_auth = item.get('auth', parent_auth)
                sub_endpoints = await self._parse_items(item['item'], variables, folder_auth)
                endpoints.extend(sub_endpoints)
            elif 'request' in item:
                # This is an actual request
                endpoint = await self._parse_request(item, variables, parent_auth)
                if endpoint:
                    endpoints.append(endpoint)

        return endpoints

    async def _parse_request(self, item: Dict[str, Any], variables: Dict[str, Any],
                           parent_auth: Optional[Dict[str, Any]] = None) -> Optional[APIEndpoint]:
        """Parse a single request item into an APIEndpoint"""
        try:
            request = item['request']

            # Extract basic request information
            url_info = self._parse_url(request.get('url', ''), variables)
            if not url_info:
                return None

            url, query_params = url_info
            method = request.get('method', 'GET').upper()

            # Extract headers
            headers = self._parse_headers(request.get('header', []))

            # Extract body
            body_schema, body_injection_points = self._parse_body(request.get('body', {}))

            # Determine authentication
            auth_type, auth_headers = self._determine_auth_type(
                request.get('auth', parent_auth), headers
            )
            headers.update(auth_headers)

            # Analyze endpoint type
            endpoint_type, context_clues = self._analyze_endpoint_type(url, method, headers, body_schema)

            # Find all injection points
            injection_points = []
            injection_points.extend(body_injection_points)
            injection_points.extend(self._find_header_injection_points(headers))
            injection_points.extend(self._find_query_injection_points(query_params))
            injection_points.extend(self._find_path_injection_points(url))

            # Calculate security priority
            security_priority = self._calculate_security_priority(
                endpoint_type, auth_type, injection_points, context_clues
            )

            # Detect LLM indicators
            llm_indicators = self._detect_llm_indicators(url, headers, body_schema, context_clues)

            # Detect healthcare indicators
            healthcare_indicators = self._detect_healthcare_indicators(url, headers, body_schema)

            # Detect compliance requirements
            compliance_tags = self._detect_compliance_tags(healthcare_indicators, endpoint_type)

            endpoint = APIEndpoint(
                id=str(uuid.uuid4()),
                url=url,
                method=method,
                endpoint_type=endpoint_type,
                auth_type=auth_type,
                headers=headers,
                query_params=query_params,
                body_schema=body_schema,
                injection_points=injection_points,
                session_management={},
                rate_limiting={},
                context_clues=context_clues,
                security_priority=security_priority,
                llm_indicators=llm_indicators,
                healthcare_indicators=healthcare_indicators,
                compliance_tags=compliance_tags
            )

            return endpoint

        except Exception as e:
            self.logger.warning(f"Error parsing request item: {str(e)}")
            return None

    def _parse_url(self, url_data: Union[str, Dict[str, Any]], variables: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Parse URL and extract query parameters"""
        try:
            if isinstance(url_data, str):
                url = url_data
                query_params = {}
            else:
                # Handle Postman URL object
                raw_parts = url_data.get('raw', '').split('?')
                url = raw_parts[0]
                query_params = {}

                # Extract query parameters
                for query in url_data.get('query', []):
                    key = query.get('key')
                    value = query.get('value', '')
                    if key:
                        query_params[key] = value

            # Substitute variables
            url = self._substitute_variables(url, variables)

            return url, query_params

        except Exception:
            return None

    def _parse_headers(self, headers_list: List[Dict[str, Any]]) -> Dict[str, str]:
        """Parse headers from Postman format"""
        headers = {}
        for header in headers_list:
            key = header.get('key')
            value = header.get('value', '')
            disabled = header.get('disabled', False)

            if key and not disabled:
                headers[key.lower()] = value

        return headers

    def _parse_body(self, body: Dict[str, Any]) -> Tuple[Dict[str, Any], List[InjectionPoint]]:
        """Parse request body and identify injection points"""
        body_schema = {}
        injection_points = []

        mode = body.get('mode', 'none')

        if mode == 'raw':
            raw_content = body.get('raw', '')
            try:
                # Try to parse as JSON
                json_data = json.loads(raw_content)
                body_schema = {'type': 'json', 'content': json_data}
                injection_points.extend(self._find_json_injection_points(json_data))
            except json.JSONDecodeError:
                # Handle as plain text
                body_schema = {'type': 'text', 'content': raw_content}
                if raw_content.strip():
                    injection_points.append(InjectionPoint(
                        location="body",
                        field_path="raw",
                        field_name="raw_content",
                        field_type="text",
                        sample_value=raw_content,
                        injection_priority=7,
                        context_hints=["raw_text"]
                    ))

        elif mode == 'formdata':
            form_data = {}
            for item in body.get('formdata', []):
                key = item.get('key')
                value = item.get('value', '')
                if key:
                    form_data[key] = value
                    injection_points.append(InjectionPoint(
                        location="body",
                        field_path=f"formdata.{key}",
                        field_name=key,
                        field_type="text",
                        sample_value=value,
                        injection_priority=6,
                        context_hints=["form_data"]
                    ))
            body_schema = {'type': 'formdata', 'content': form_data}

        elif mode == 'urlencoded':
            urlencoded_data = {}
            for item in body.get('urlencoded', []):
                key = item.get('key')
                value = item.get('value', '')
                if key:
                    urlencoded_data[key] = value
                    injection_points.append(InjectionPoint(
                        location="body",
                        field_path=f"urlencoded.{key}",
                        field_name=key,
                        field_type="text",
                        sample_value=value,
                        injection_priority=6,
                        context_hints=["url_encoded"]
                    ))
            body_schema = {'type': 'urlencoded', 'content': urlencoded_data}

        return body_schema, injection_points

    def _find_json_injection_points(self, json_data: Any, path: str = "") -> List[InjectionPoint]:
        """Recursively find injection points in JSON data"""
        injection_points = []

        if isinstance(json_data, dict):
            for key, value in json_data.items():
                current_path = f"{path}.{key}" if path else key

                if isinstance(value, str):
                    priority = self._calculate_field_priority(key, value)
                    injection_points.append(InjectionPoint(
                        location="body",
                        field_path=current_path,
                        field_name=key,
                        field_type="text",
                        sample_value=value,
                        injection_priority=priority,
                        context_hints=self._get_field_context_hints(key, value)
                    ))
                elif isinstance(value, (dict, list)):
                    injection_points.extend(self._find_json_injection_points(value, current_path))

        elif isinstance(json_data, list):
            for i, item in enumerate(json_data):
                current_path = f"{path}[{i}]"
                injection_points.extend(self._find_json_injection_points(item, current_path))

        return injection_points

    def _calculate_field_priority(self, field_name: str, value: Any) -> int:
        """Calculate injection priority for a field"""
        field_name_lower = field_name.lower()

        # High priority fields (likely to be user input or prompts)
        high_priority = ['message', 'prompt', 'query', 'text', 'content', 'input', 'question']
        if any(term in field_name_lower for term in high_priority):
            return 9

        # Medium priority fields
        medium_priority = ['description', 'title', 'name', 'comment', 'note']
        if any(term in field_name_lower for term in medium_priority):
            return 7

        # Low priority but still testable
        if isinstance(value, str) and len(str(value)) > 10:
            return 5

        return 3

    def _get_field_context_hints(self, field_name: str, value: Any) -> List[str]:
        """Get context hints for a field"""
        hints = []
        field_name_lower = field_name.lower()

        # LLM-specific hints
        llm_terms = ['prompt', 'message', 'query', 'completion', 'generate']
        if any(term in field_name_lower for term in llm_terms):
            hints.append('llm_input')

        # User input hints
        user_terms = ['user', 'input', 'request', 'question']
        if any(term in field_name_lower for term in user_terms):
            hints.append('user_input')

        # System hints
        system_terms = ['system', 'role', 'instruction', 'context']
        if any(term in field_name_lower for term in system_terms):
            hints.append('system_context')

        return hints

    def _find_header_injection_points(self, headers: Dict[str, str]) -> List[InjectionPoint]:
        """Find injection points in headers"""
        injection_points = []

        # Headers that might be vulnerable
        testable_headers = [
            'user-agent', 'referer', 'x-forwarded-for', 'x-real-ip',
            'x-custom-header', 'x-user-id', 'x-session-id'
        ]

        for header_name, value in headers.items():
            if header_name.lower() in testable_headers or header_name.startswith('x-'):
                injection_points.append(InjectionPoint(
                    location="header",
                    field_path=header_name,
                    field_name=header_name,
                    field_type="text",
                    sample_value=value,
                    injection_priority=4,
                    context_hints=["header"]
                ))

        return injection_points

    def _find_query_injection_points(self, query_params: Dict[str, Any]) -> List[InjectionPoint]:
        """Find injection points in query parameters"""
        injection_points = []

        for param_name, value in query_params.items():
            priority = self._calculate_field_priority(param_name, value)
            injection_points.append(InjectionPoint(
                location="query",
                field_path=param_name,
                field_name=param_name,
                field_type="text",
                sample_value=value,
                injection_priority=priority,
                context_hints=["query_param"]
            ))

        return injection_points

    def _find_path_injection_points(self, url: str) -> List[InjectionPoint]:
        """Find injection points in URL path parameters"""
        injection_points = []

        # Find path parameters (like {id}, :id, etc.)
        path_param_patterns = [
            r'\{([^}]+)\}',  # {param}
            r':([a-zA-Z_][a-zA-Z0-9_]*)',  # :param
            r'\[([^\]]+)\]'  # [param]
        ]

        for pattern in path_param_patterns:
            for match in re.finditer(pattern, url):
                param_name = match.group(1)
                injection_points.append(InjectionPoint(
                    location="path",
                    field_path=f"path.{param_name}",
                    field_name=param_name,
                    field_type="text",
                    sample_value="",
                    injection_priority=6,
                    context_hints=["path_param"]
                ))

        return injection_points

    def _determine_auth_type(self, auth_config: Optional[Dict[str, Any]],
                           headers: Dict[str, str]) -> Tuple[AuthType, Dict[str, str]]:
        """Determine authentication type and extract auth headers"""
        auth_headers = {}

        # Check explicit auth config first
        if auth_config:
            auth_type_str = auth_config.get('type', '').lower()

            if auth_type_str == 'bearer':
                return AuthType.BEARER_TOKEN, auth_headers
            elif auth_type_str == 'basic':
                return AuthType.BASIC_AUTH, auth_headers
            elif auth_type_str == 'apikey':
                return AuthType.API_KEY_HEADER, auth_headers
            elif auth_type_str == 'oauth2':
                return AuthType.OAUTH2, auth_headers

        # Analyze headers for auth patterns
        for header_name, value in headers.items():
            header_lower = header_name.lower()
            value_lower = value.lower()

            if header_lower == 'authorization':
                if value_lower.startswith('bearer'):
                    return AuthType.BEARER_TOKEN, auth_headers
                elif value_lower.startswith('basic'):
                    return AuthType.BASIC_AUTH, auth_headers

            if any(pattern in header_lower for pattern in self.auth_patterns['api_key_headers']):
                return AuthType.API_KEY_HEADER, auth_headers

        return AuthType.NONE, auth_headers

    def _analyze_endpoint_type(self, url: str, method: str, headers: Dict[str, str],
                             body_schema: Dict[str, Any]) -> Tuple[EndpointType, List[str]]:
        """Analyze and determine the endpoint type"""
        url_lower = url.lower()
        context_clues = []

        # Check for LLM patterns
        for pattern in self.llm_url_patterns:
            if re.search(pattern, url_lower):
                context_clues.append(f"url_pattern_{pattern}")

                # Determine specific LLM type
                if 'chat' in pattern:
                    return EndpointType.LLM_CHAT, context_clues
                elif 'completion' in pattern:
                    return EndpointType.LLM_COMPLETION, context_clues
                elif 'conversation' in pattern:
                    return EndpointType.LLM_CONVERSATION, context_clues
                else:
                    return EndpointType.LLM_CHAT, context_clues  # Default LLM type

        # Check body content for LLM indicators
        if body_schema.get('type') == 'json':
            content = body_schema.get('content', {})
            if isinstance(content, dict):
                llm_fields = ['prompt', 'message', 'messages', 'query', 'input', 'text']
                for field in llm_fields:
                    if field in content:
                        context_clues.append(f"body_field_{field}")
                        return EndpointType.LLM_CHAT, context_clues

        # Check for other endpoint types
        if 'auth' in url_lower or 'login' in url_lower or 'token' in url_lower:
            context_clues.append("auth_endpoint")
            return EndpointType.AUTHENTICATION, context_clues

        if 'upload' in url_lower or 'file' in url_lower:
            context_clues.append("file_endpoint")
            return EndpointType.FILE_UPLOAD, context_clues

        if 'stream' in url_lower or headers.get('accept') == 'text/event-stream':
            context_clues.append("streaming_endpoint")
            return EndpointType.STREAMING, context_clues

        return EndpointType.GENERIC_API, context_clues

    def _calculate_security_priority(self, endpoint_type: EndpointType, auth_type: AuthType,
                                   injection_points: List[InjectionPoint],
                                   context_clues: List[str]) -> int:
        """Calculate security testing priority for an endpoint"""
        priority = 5  # Base priority

        # Endpoint type modifiers
        if endpoint_type.value.startswith('llm_'):
            priority += 3  # LLM endpoints are high priority
        elif endpoint_type == EndpointType.AUTHENTICATION:
            priority += 2
        elif endpoint_type == EndpointType.FILE_UPLOAD:
            priority += 2

        # Authentication modifiers
        if auth_type == AuthType.NONE:
            priority += 2  # Unauthenticated endpoints are higher priority
        elif auth_type in [AuthType.API_KEY_HEADER, AuthType.BEARER_TOKEN]:
            priority += 1

        # Injection points modifiers
        high_priority_points = [p for p in injection_points if p.injection_priority >= 8]
        priority += min(len(high_priority_points), 3)  # Cap the bonus

        # Context clues modifiers
        healthcare_clues = [c for c in context_clues if 'medical' in c or 'health' in c]
        if healthcare_clues:
            priority += 2  # Healthcare endpoints need extra attention

        return min(priority, 10)  # Cap at 10

    def _detect_llm_indicators(self, url: str, headers: Dict[str, str],
                              body_schema: Dict[str, Any], context_clues: List[str]) -> List[str]:
        """Detect LLM-specific indicators"""
        indicators = []

        # URL indicators
        llm_terms = ['ai', 'llm', 'gpt', 'chat', 'completion', 'generate', 'inference']
        url_lower = url.lower()
        for term in llm_terms:
            if term in url_lower:
                indicators.append(f"url_contains_{term}")

        # Header indicators
        llm_headers = ['openai', 'anthropic', 'cohere', 'huggingface']
        for header_name, value in headers.items():
            for llm_provider in llm_headers:
                if llm_provider in header_name.lower() or llm_provider in value.lower():
                    indicators.append(f"header_indicates_{llm_provider}")

        # Body indicators
        if body_schema.get('type') == 'json':
            content = body_schema.get('content', {})
            if isinstance(content, dict):
                llm_body_fields = ['model', 'temperature', 'max_tokens', 'top_p', 'messages']
                for field in llm_body_fields:
                    if field in content:
                        indicators.append(f"body_contains_{field}")

        return indicators

    def _detect_healthcare_indicators(self, url: str, headers: Dict[str, str],
                                    body_schema: Dict[str, Any]) -> List[str]:
        """Detect healthcare-specific indicators"""
        indicators = []

        # Check URL
        url_lower = url.lower()
        for pattern in self.healthcare_patterns:
            if re.search(pattern, url_lower):
                indicators.append(f"url_healthcare_{pattern}")

        # Check headers
        for header_name, value in headers.items():
            header_content = f"{header_name} {value}".lower()
            for pattern in self.healthcare_patterns:
                if re.search(pattern, header_content):
                    indicators.append(f"header_healthcare_{pattern}")

        return indicators

    def _detect_compliance_tags(self, healthcare_indicators: List[str],
                               endpoint_type: EndpointType) -> List[str]:
        """Detect compliance requirements"""
        tags = []

        if healthcare_indicators:
            tags.extend(['HIPAA', 'GDPR', 'healthcare_compliance'])

        if endpoint_type.value.startswith('llm_'):
            tags.extend(['AI_ethics', 'data_privacy'])

        return tags

    def _extract_base_urls(self, endpoints: List[APIEndpoint]) -> Set[str]:
        """Extract base URLs from endpoints"""
        base_urls = set()

        for endpoint in endpoints:
            parsed = urlparse(endpoint.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            if base_url not in ['http://', 'https://']:
                base_urls.add(base_url)

        return base_urls

    def _generate_testing_profile(self, endpoints: List[APIEndpoint],
                                 auth_config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate optimal testing profile for the collection"""
        llm_endpoints = [e for e in endpoints if e.endpoint_type.value.startswith('llm_')]
        high_priority = [e for e in endpoints if e.security_priority >= 8]

        auth_types = list(set([e.auth_type.value for e in endpoints]))
        endpoint_types = list(set([e.endpoint_type.value for e in endpoints]))

        # Determine testing intensity
        if len(llm_endpoints) > 5 or len(high_priority) > 3:
            intensity = "comprehensive"
        elif len(llm_endpoints) > 0 or len(high_priority) > 0:
            intensity = "balanced"
        else:
            intensity = "basic"

        # Determine rate limiting strategy
        if 'none' in auth_types:
            rate_limit_strategy = "conservative"
        else:
            rate_limit_strategy = "moderate"

        profile = {
            'intensity': intensity,
            'rate_limit_strategy': rate_limit_strategy,
            'priority_endpoints': [e.id for e in sorted(endpoints, key=lambda x: x.security_priority, reverse=True)[:10]],
            'auth_types': auth_types,
            'endpoint_types': endpoint_types,
            'recommended_tests': self._recommend_tests(endpoints),
            'estimated_duration_minutes': self._estimate_duration(endpoints, intensity),
            'compliance_requirements': list(set([tag for e in endpoints for tag in e.compliance_tags]))
        }

        return profile

    def _recommend_tests(self, endpoints: List[APIEndpoint]) -> List[str]:
        """Recommend specific tests based on endpoint analysis"""
        tests = ['prompt_injection', 'input_validation', 'authentication_bypass']

        llm_endpoints = [e for e in endpoints if e.endpoint_type.value.startswith('llm_')]
        if llm_endpoints:
            tests.extend(['jailbreaking', 'data_extraction', 'model_manipulation'])

        healthcare_endpoints = [e for e in endpoints if e.healthcare_indicators]
        if healthcare_endpoints:
            tests.extend(['hipaa_compliance', 'pii_leakage', 'medical_boundary_testing'])

        file_endpoints = [e for e in endpoints if e.endpoint_type == EndpointType.FILE_UPLOAD]
        if file_endpoints:
            tests.extend(['file_upload_attacks', 'malicious_file_detection'])

        return tests

    def _estimate_duration(self, endpoints: List[APIEndpoint], intensity: str) -> int:
        """Estimate testing duration in minutes"""
        base_time = len(endpoints) * 2  # 2 minutes per endpoint base

        if intensity == "comprehensive":
            multiplier = 3
        elif intensity == "balanced":
            multiplier = 2
        else:
            multiplier = 1

        return base_time * multiplier

    def _substitute_variables(self, text: str, variables: Dict[str, Any]) -> str:
        """Substitute Postman variables in text"""
        if not variables:
            return text

        # Handle {{variable}} syntax
        for var_name, var_value in variables.items():
            text = text.replace(f"{{{{{var_name}}}}}", str(var_value))

        return text

    async def generate_artemis_config(self, collection: PostmanCollection,
                                    output_path: Optional[Path] = None) -> Dict[str, Any]:
        """Generate ARTEMIS configuration from parsed collection"""
        config = {
            'collection_info': {
                'name': collection.name,
                'description': collection.description,
                'parsed_at': collection.metadata['parsed_at'],
                'total_endpoints': len(collection.endpoints)
            },
            'testing_profile': collection.testing_profile,
            'endpoints': [],
            'security_config': {
                'rate_limiting': {
                    'requests_per_second': 5 if collection.testing_profile['rate_limit_strategy'] == 'conservative' else 10,
                    'burst_limit': 20,
                    'backoff_strategy': 'exponential'
                },
                'timeout_settings': {
                    'connection_timeout': 30,
                    'read_timeout': 60,
                    'total_timeout': 120
                },
                'retry_policy': {
                    'max_retries': 3,
                    'retry_codes': [429, 502, 503, 504],
                    'backoff_factor': 2
                }
            },
            'attack_config': {
                'payload_categories': collection.testing_profile['recommended_tests'],
                'injection_strategies': ['direct', 'encoded', 'fragmented', 'chained'],
                'compliance_modes': collection.testing_profile['compliance_requirements']
            }
        }

        # Add endpoint configurations
        for endpoint in collection.endpoints:
            endpoint_config = {
                'id': endpoint.id,
                'url': endpoint.url,
                'method': endpoint.method,
                'endpoint_type': endpoint.endpoint_type.value,
                'security_priority': endpoint.security_priority,
                'auth_type': endpoint.auth_type.value,
                'headers': endpoint.headers,
                'injection_points': [
                    {
                        'location': ip.location,
                        'field_path': ip.field_path,
                        'field_name': ip.field_name,
                        'field_type': ip.field_type,
                        'priority': ip.injection_priority,
                        'context_hints': ip.context_hints
                    }
                    for ip in endpoint.injection_points
                ],
                'llm_indicators': endpoint.llm_indicators,
                'healthcare_indicators': endpoint.healthcare_indicators,
                'compliance_tags': endpoint.compliance_tags
            }
            config['endpoints'].append(endpoint_config)

        # Save to file if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)

            self.logger.info(f"ARTEMIS configuration saved to {output_path}")

        return config

    async def validate_collection(self, collection: PostmanCollection) -> Dict[str, Any]:
        """Validate a parsed collection for completeness and testability"""
        validation_results = {
            'valid': True,
            'warnings': [],
            'errors': [],
            'statistics': {
                'total_endpoints': len(collection.endpoints),
                'testable_endpoints': 0,
                'high_priority_endpoints': 0,
                'llm_endpoints': 0,
                'injection_points': 0
            }
        }

        if not collection.endpoints:
            validation_results['valid'] = False
            validation_results['errors'].append("No endpoints found in collection")
            return validation_results

        for endpoint in collection.endpoints:
            # Check if endpoint is testable
            if endpoint.injection_points:
                validation_results['statistics']['testable_endpoints'] += 1

            if endpoint.security_priority >= 8:
                validation_results['statistics']['high_priority_endpoints'] += 1

            if endpoint.endpoint_type.value.startswith('llm_'):
                validation_results['statistics']['llm_endpoints'] += 1

            validation_results['statistics']['injection_points'] += len(endpoint.injection_points)

            # Validate individual endpoint
            if not endpoint.url or not endpoint.method:
                validation_results['errors'].append(f"Endpoint {endpoint.id} missing URL or method")

            if endpoint.auth_type == AuthType.NONE and endpoint.security_priority < 6:
                validation_results['warnings'].append(f"Endpoint {endpoint.url} has no authentication but low priority")

        # Overall validation
        if validation_results['statistics']['testable_endpoints'] == 0:
            validation_results['warnings'].append("No injection points found - limited testing possible")

        if validation_results['statistics']['llm_endpoints'] == 0:
            validation_results['warnings'].append("No LLM endpoints detected - consider manual review")

        return validation_results


# CLI Interface for testing
async def main():
    """Main function for testing the Postman integration"""
    import sys
    from pathlib import Path

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    if len(sys.argv) != 2:
        print("Usage: python postman_integration_engine.py <postman_collection.json>")
        sys.exit(1)

    collection_path = Path(sys.argv[1])
    if not collection_path.exists():
        print(f"Collection file not found: {collection_path}")
        sys.exit(1)

    engine = PostmanIntegrationEngine(logger)

    try:
        # Parse collection
        collection = await engine.parse_collection(collection_path)
        print(f"✅ Successfully parsed collection: {collection.name}")
        print(f"   Endpoints: {len(collection.endpoints)}")
        print(f"   LLM endpoints: {len([e for e in collection.endpoints if e.endpoint_type.value.startswith('llm_')])}")

        # Validate collection
        validation = await engine.validate_collection(collection)
        if validation['valid']:
            print("✅ Collection validation passed")
        else:
            print("⚠️  Collection validation warnings/errors:")
            for error in validation['errors']:
                print(f"   ❌ {error}")
            for warning in validation['warnings']:
                print(f"   ⚠️  {warning}")

        # Generate ARTEMIS config
        config_path = collection_path.parent / f"{collection_path.stem}_artemis_config.yaml"
        await engine.generate_artemis_config(collection, config_path)
        print(f"✅ ARTEMIS configuration generated: {config_path}")

    except Exception as e:
        logger.error(f"Error processing collection: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
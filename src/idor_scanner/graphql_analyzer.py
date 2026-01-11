"""
GraphQL Support for IDOR Scanner.

Handles GraphQL-specific vulnerability detection including:
- Introspection query detection
- Mutation fuzzing with different user IDs
- Batch query abuse detection
"""

import json
import logging
import re
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger(__name__)


# Standard GraphQL introspection query
INTROSPECTION_QUERY = '''
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name } }
        type { name kind }
      }
    }
  }
}
'''

# Minimal introspection to detect GraphQL
MINIMAL_INTROSPECTION = '{"query":"{__typename}"}'


class GraphQLAnalyzer:
    """Analyzes GraphQL APIs for IDOR vulnerabilities."""
    
    # Common ID argument names in GraphQL
    ID_ARGUMENTS = ['id', 'userId', 'user_id', 'accountId', 'customerId', 'objectId', 'uuid']
    
    def __init__(self, http_client):
        self.http_client = http_client
        self.schema: Optional[Dict] = None
        self.mutations: List[Dict] = []
        self.queries: List[Dict] = []
    
    async def detect_graphql(self, url: str) -> bool:
        """
        Detect if an endpoint is a GraphQL API.
        
        Args:
            url: URL to test
            
        Returns:
            True if GraphQL endpoint detected
        """
        try:
            # Try typical GraphQL endpoints
            endpoints = [url, f"{url}/graphql", f"{url}/api/graphql", f"{url}/query"]
            
            for endpoint in endpoints:
                response = await self.http_client.request(
                    'POST',
                    endpoint,
                    json={"query": "{__typename}"},
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data or 'errors' in data:
                            logger.info(f"GraphQL endpoint found: {endpoint}")
                            return True
                    except:
                        pass
                        
            return False
            
        except Exception as e:
            logger.error(f"Error detecting GraphQL: {e}")
            return False
    
    async def run_introspection(self, url: str) -> Optional[Dict]:
        """
        Run introspection query to discover schema.
        
        Args:
            url: GraphQL endpoint URL
            
        Returns:
            Schema data if introspection is allowed
        """
        try:
            response = await self.http_client.request(
                'POST',
                url,
                json={"query": INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    self.schema = data['data']['__schema']
                    self._parse_schema()
                    return self.schema
                    
            return None
            
        except Exception as e:
            logger.error(f"Introspection failed: {e}")
            return None
    
    def _parse_schema(self):
        """Parse schema to extract queries and mutations with ID arguments."""
        if not self.schema:
            return
        
        for type_def in self.schema.get('types', []):
            type_name = type_def.get('name', '')
            
            # Skip internal types
            if type_name.startswith('__'):
                continue
            
            fields = type_def.get('fields', []) or []
            
            for field in fields:
                field_name = field.get('name', '')
                args = field.get('args', []) or []
                
                # Check if any argument looks like an ID
                id_args = [arg for arg in args if arg.get('name', '').lower() in 
                          [a.lower() for a in self.ID_ARGUMENTS]]
                
                if id_args:
                    entry = {
                        'type': type_name,
                        'field': field_name,
                        'id_args': id_args,
                        'all_args': args
                    }
                    
                    if type_name == self.schema.get('mutationType', {}).get('name'):
                        self.mutations.append(entry)
                    elif type_name == self.schema.get('queryType', {}).get('name'):
                        self.queries.append(entry)
    
    def generate_idor_queries(self, victim_id: str, attacker_id: str) -> List[Dict]:
        """
        Generate IDOR test queries.
        
        Creates pairs of queries: one with victim ID, one with attacker ID.
        
        Args:
            victim_id: Victim's user ID
            attacker_id: Attacker's user ID
            
        Returns:
            List of test query pairs
        """
        test_cases = []
        
        for query in self.queries:
            field_name = query['field']
            id_arg = query['id_args'][0]['name'] if query['id_args'] else 'id'
            
            # Create victim query (baseline)
            victim_query = f'query {{ {field_name}({id_arg}: "{victim_id}") {{ id }} }}'
            
            # Create attacker query (test)
            attacker_query = f'query {{ {field_name}({id_arg}: "{victim_id}") {{ id }} }}'
            
            test_cases.append({
                'name': field_name,
                'victim_query': {"query": victim_query},
                'attacker_query': {"query": attacker_query},
                'description': f"Test IDOR on {field_name} with ID argument"
            })
        
        return test_cases
    
    def generate_batch_abuse_query(self, ids: List[str], field_name: str = "user") -> Dict:
        """
        Generate batch query to enumerate multiple IDs at once.
        
        Args:
            ids: List of IDs to query
            field_name: Field name to query
            
        Returns:
            Batch query payload
        """
        aliases = []
        for i, user_id in enumerate(ids):
            aliases.append(f'u{i}: {field_name}(id: "{user_id}") {{ id email name }}')
        
        query = "query {\n  " + "\n  ".join(aliases) + "\n}"
        return {"query": query}
    
    def is_vulnerable_response(self, baseline: Dict, attack: Dict) -> Tuple[bool, str]:
        """
        Compare GraphQL responses to detect IDOR.
        
        Args:
            baseline: Response when victim queries their own data
            attack: Response when attacker queries victim's data
            
        Returns:
            Tuple of (is_vulnerable, description)
        """
        # If attack got errors, probably not vulnerable
        if 'errors' in attack and not 'data' in attack:
            return False, "Access denied (GraphQL error)"
        
        # If attack got data similar to baseline, vulnerable
        if 'data' in attack and attack.get('data') == baseline.get('data'):
            return True, "GraphQL IDOR: Attacker can access victim's data"
        
        # If attack got non-empty data (and baseline was also valid)
        if 'data' in attack and 'data' in baseline:
            attack_data = attack['data']
            if attack_data and attack_data != {"__typename": None}:
                return True, "GraphQL IDOR: Attacker received data from victim's query"
        
        return False, "No vulnerability detected"

import json
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs

from .models import Endpoint, HttpMethod, ResourceID, IDType
from .discovery import ID_PATTERNS

logger = logging.getLogger(__name__)

class HARImporter:
    """Imports API endpoints and traffic patterns from HAR files."""
    
    def __init__(self, target_domain: Optional[str] = None):
        self.target_domain = target_domain
        self.endpoints: List[Endpoint] = []
        
    def load_file(self, file_path: str) -> List[Endpoint]:
        """Load endpoints from a HAR file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            entries = data.get('log', {}).get('entries', [])
            logger.info(f"Processing {len(entries)} HAR entries...")
            
            for entry in entries:
                self._process_entry(entry)
                
            logger.info(f"Loaded {len(self.endpoints)} unique endpoints from HAR")
            return self.endpoints
            
        except Exception as e:
            logger.error(f"Failed to load HAR file: {e}")
            return []

    def _process_entry(self, entry: Dict[str, Any]):
        """Process a single HAR entry."""
        request = entry.get('request', {})
        url_str = request.get('url', '')
        method = request.get('method', 'GET')
        
        # Filter by domain if set
        if self.target_domain and self.target_domain not in url_str:
            return
            
        # Parse URL
        parsed = urlparse(url_str)
        path = parsed.path
        
        # Skip static assets
        if any(path.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.woff', '.ico']):
            return

        # Extract IDs from Path
        resource_ids = []
        clean_path = path
        
        # Reuse existing discovery logic for path IDs?
        # Ideally we reuse the regex patterns from discovery.
        # Simple extraction:
        import re
        for pattern, id_type in ID_PATTERNS:
            # We want to find matches and replace them with placeholders for the generic endpoint path
            # But Endpoint model stores the RAW path usually? 
            # No, typically Endpoint stores the path with values, and resource_ids tells us where they are.
            
            # Let's extract IDs
            if id_type in [IDType.QUERY_NUMERIC, IDType.QUERY_STRING]:
                continue # Skip query params for now, handled by parse_qs
                
            matches = list(re.finditer(pattern, path))
            for match in matches:
                val = match.group(1)
                # We assume the last ID found is likely the resource ID? 
                # Or we capture all.
                resource_ids.append(ResourceID(
                    value=val,
                    id_type=id_type,
                    position=match.start(1)
                ))

        # JSON Body Analysis
        body_template = None
        post_data = request.get('postData', {})
        mime_type = post_data.get('mimeType', '')
        text = post_data.get('text', '')
        
        if 'application/json' in mime_type and text:
            try:
                body_json = json.loads(text)
                body_template, body_ids = self._analyze_json_body(body_json)
                if body_ids:
                    # found IDs in body
                    resource_ids.extend(body_ids)
            except json.JSONDecodeError:
                pass

        # Deduplicate endpoints (method + path)
        # If we have the same method+path, we might merge or skip.
        # For now, simple append if unique enough.
        
        # Note: If we found body IDs, we definitely want this endpoint.
        
        ep = Endpoint(
            path=path,
            method=HttpMethod(method.upper()),
            resource_ids=resource_ids,
            body_template=body_template,
            description="Imported from HAR"
        )
        self.endpoints.append(ep)

    def _analyze_json_body(self, data: Any) -> tuple[Dict[str, Any], List[ResourceID]]:
        """
        Recursively identify potential IDs in JSON body.
        Returns (template_with_placeholders, list_of_resource_ids)
        """
        # This is complex. 
        # Simple heuristic: Look for keys named "id", "user_id", "uuid", "account_id"
        # AND values that look like UUIDs or Integers.
        
        ids = []
        template = data # Copy?
        
        # TODO: Implement recursive search and replace with "{id}" placeholder
        # For now, let's implement a shallow check for the Notion case specifically + generic flat keys
        
        import re
        uuid_regex = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
        
        def walk(obj):
            if isinstance(obj, dict):
                new_obj = {}
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        new_obj[k] = walk(v)
                    elif isinstance(v, str) and (k in ['id', 'uuid', 'user_id', 'objectId'] or uuid_regex.match(v)):
                        # It's an ID!
                        # Mark it for replacement
                        placeholder = "{id}"
                        ids.append(ResourceID(value=v, id_type=IDType.UUID, position=-1)) # -1 for body
                        new_obj[k] = placeholder
                    else:
                        new_obj[k] = v
                return new_obj
            elif isinstance(obj, list):
                return [walk(i) for i in obj]
            return obj

        template = walk(data)
        return template, ids

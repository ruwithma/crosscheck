"""
Tests for Endpoint Discovery.
"""

import pytest
from unittest.mock import Mock, AsyncMock

from idor_scanner.discovery import EndpointDiscovery, ID_PATTERNS
from idor_scanner.models import IDType, HttpMethod


class TestIDExtraction:
    """Tests for ID extraction from URLs."""
    
    @pytest.fixture
    def discovery(self):
        mock_client = Mock()
        return EndpointDiscovery(mock_client, "https://api.example.com")
    
    def test_extract_numeric_id(self, discovery):
        """Test extraction of numeric IDs."""
        ids = discovery.extract_ids_from_path("/api/users/123")
        
        assert len(ids) >= 1
        assert any(rid.value == "123" for rid in ids)
        assert any(rid.id_type == IDType.NUMERIC for rid in ids)
    
    def test_extract_uuid(self, discovery):
        """Test extraction of UUID IDs."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        ids = discovery.extract_ids_from_path(f"/api/orders/{uuid}")
        
        assert len(ids) >= 1
        assert any(rid.value == uuid for rid in ids)
        assert any(rid.id_type == IDType.UUID for rid in ids)
    
    def test_extract_alphanumeric_id(self, discovery):
        """Test extraction of alphanumeric IDs."""
        ids = discovery.extract_ids_from_path("/api/posts/abc123xyz")
        
        assert len(ids) >= 1
        assert any(rid.value == "abc123xyz" for rid in ids)
    
    def test_extract_query_param_id(self, discovery):
        """Test extraction of query parameter IDs."""
        ids = discovery.extract_ids_from_path("/api/search?id=456")
        
        assert any(rid.value == "456" for rid in ids)
    
    def test_extract_path_parameter(self, discovery):
        """Test extraction of path parameters like {id}."""
        ids = discovery.extract_ids_from_path("/api/users/{user_id}/orders/{order_id}")
        
        assert any(rid.value == "user_id" for rid in ids)
        assert any(rid.value == "order_id" for rid in ids)
    
    def test_multiple_ids_in_path(self, discovery):
        """Test extraction of multiple IDs from a single path."""
        ids = discovery.extract_ids_from_path("/api/users/123/orders/456/items/789")
        
        values = [rid.value for rid in ids]
        assert "123" in values
        assert "456" in values
        assert "789" in values
    
    def test_no_ids_in_path(self, discovery):
        """Test path with no extractable IDs."""
        ids = discovery.extract_ids_from_path("/api/health")
        
        # Should be empty or only contain path parameters
        numeric_ids = [rid for rid in ids if rid.id_type == IDType.NUMERIC]
        assert len(numeric_ids) == 0


class TestEndpointLoading:
    """Tests for endpoint loading from files."""
    
    @pytest.fixture
    def discovery(self):
        mock_client = Mock()
        return EndpointDiscovery(mock_client, "https://api.example.com")
    
    def test_load_from_file(self, discovery, tmp_path):
        """Test loading endpoints from a text file."""
        # Create test file
        endpoints_file = tmp_path / "endpoints.txt"
        endpoints_file.write_text("""
GET /api/users/{id}
POST /api/orders
PUT /api/accounts/{id}/settings
DELETE /api/posts/{id}
# This is a comment
""")
        
        endpoints = discovery.load_from_file(str(endpoints_file))
        
        assert len(endpoints) == 4
        assert any(ep.method == HttpMethod.GET for ep in endpoints)
        assert any(ep.method == HttpMethod.POST for ep in endpoints)
        assert any(ep.method == HttpMethod.PUT for ep in endpoints)
        assert any(ep.method == HttpMethod.DELETE for ep in endpoints)
    
    def test_load_nonexistent_file(self, discovery):
        """Test loading from non-existent file."""
        endpoints = discovery.load_from_file("/nonexistent/file.txt")
        assert endpoints == []


class TestEndpointDeduplication:
    """Tests for endpoint deduplication."""
    
    @pytest.fixture
    def discovery(self):
        mock_client = Mock()
        return EndpointDiscovery(mock_client, "https://api.example.com")
    
    def test_deduplicate_identical_endpoints(self, discovery):
        """Test that identical endpoints are deduplicated."""
        from idor_scanner.models import Endpoint
        
        endpoints = [
            Endpoint(path="/api/users/{id}", method=HttpMethod.GET),
            Endpoint(path="/api/users/{id}", method=HttpMethod.GET),  # Duplicate
            Endpoint(path="/api/users/{id}", method=HttpMethod.POST),  # Different method
        ]
        
        unique = discovery._deduplicate_endpoints(endpoints)
        
        assert len(unique) == 2


class TestTestableEndpoints:
    """Tests for identifying testable endpoints."""
    
    @pytest.fixture
    def discovery(self):
        mock_client = Mock()
        return EndpointDiscovery(mock_client, "https://api.example.com")
    
    def test_get_testable_endpoints(self, discovery):
        """Test filtering for endpoints with resource IDs."""
        from idor_scanner.models import Endpoint, ResourceID
        
        discovery.discovered_endpoints = [
            Endpoint(
                path="/api/users/{id}",
                method=HttpMethod.GET,
                resource_ids=[ResourceID(value="id", id_type=IDType.ALPHANUMERIC, position=0)]
            ),
            Endpoint(
                path="/api/health",
                method=HttpMethod.GET,
                resource_ids=[]  # No IDs
            ),
        ]
        
        testable = discovery.get_testable_endpoints()
        
        assert len(testable) == 1
        assert testable[0].path == "/api/users/{id}"

"""
Tests for the Response Comparator.
"""

import pytest
from unittest.mock import Mock

from idor_scanner.comparator import ResponseComparator, ComparisonResult
from idor_scanner.models import Severity


class TestResponseComparator:
    """Tests for ResponseComparator class."""
    
    @pytest.fixture
    def comparator(self):
        return ResponseComparator()
    
    def _mock_response(self, status_code: int, json_data: dict = None, text: str = ""):
        """Create a mock httpx.Response."""
        response = Mock()
        response.status_code = status_code
        response.text = text or (str(json_data) if json_data else "")
        
        if json_data is not None:
            response.json = Mock(return_value=json_data)
        else:
            response.json = Mock(side_effect=Exception("Not JSON"))
        
        return response
    
    def test_properly_blocked_returns_none(self, comparator):
        """Test that 401/403/404 responses return None (properly blocked)."""
        baseline = self._mock_response(200, {"user": "alice"})
        
        for status in [401, 403, 404]:
            blocked = self._mock_response(status)
            result = comparator.compare(baseline, blocked, "horizontal")
            assert result is None
    
    def test_server_error_returns_none(self, comparator):
        """Test that 5xx errors return None."""
        baseline = self._mock_response(200, {"user": "alice"})
        error = self._mock_response(500)
        
        result = comparator.compare(baseline, error, "horizontal")
        assert result is None
    
    def test_identical_responses_detected(self, comparator):
        """Test detection of identical responses (VULNERABLE)."""
        data = {"user_id": 123, "email": "alice@example.com", "balance": 1000}
        
        baseline = self._mock_response(200, data)
        test = self._mock_response(200, data)
        
        result = comparator.compare(baseline, test, "horizontal")
        
        assert result is not None
        assert result.is_vulnerable is True
        assert "identical" in result.vuln_type.lower()
    
    def test_sensitive_fields_detected(self, comparator):
        """Test that sensitive fields are correctly identified."""
        data = {
            "user_id": 123,
            "email": "test@example.com",
            "phone": "555-1234",
            "ssn": "123-45-6789",
            "password_hash": "abc123",
        }
        
        sensitive = comparator._find_sensitive_fields(data)
        
        assert "email" in sensitive
        assert "phone" in sensitive
        assert "ssn" in sensitive
        # password_hash should match because it contains 'password'
        assert any("password" in s.lower() for s in sensitive)
    
    def test_critical_severity_for_ssn(self, comparator):
        """Test that SSN exposure results in CRITICAL severity."""
        data = {"ssn": "123-45-6789", "name": "John"}
        
        baseline = self._mock_response(200, data)
        test = self._mock_response(200, data)
        
        result = comparator.compare(baseline, test, "horizontal")
        
        assert result is not None
        assert result.severity == Severity.CRITICAL
    
    def test_high_severity_for_multiple_fields(self, comparator):
        """Test that multiple sensitive fields result in HIGH severity."""
        data = {
            "email": "test@example.com",
            "phone": "555-1234",
            "address": "123 Main St",
            "dob": "1990-01-01",
            "account_id": 123,
        }
        
        baseline = self._mock_response(200, data)
        test = self._mock_response(200, data)
        
        result = comparator.compare(baseline, test, "horizontal")
        
        assert result is not None
        assert result.severity in [Severity.HIGH, Severity.CRITICAL]
    
    def test_different_responses_not_flagged(self, comparator):
        """Test that completely different responses are not flagged."""
        baseline = self._mock_response(200, {"user_id": 1, "data": "alice_private"})
        test = self._mock_response(200, {"error": "Access denied"})
        
        result = comparator.compare(baseline, test, "horizontal")
        
        # Different data should not be flagged as identical
        if result is not None:
            assert "identical" not in result.vuln_type.lower()
    
    def test_partial_similarity_detected(self, comparator):
        """Test detection of partial data leakage."""
        baseline = self._mock_response(200, {
            "user_id": 123,
            "email": "alice@example.com",
            "name": "Alice",
            "phone": "555-1234",
        })
        
        # Test response has most of the same data
        test = self._mock_response(200, {
            "user_id": 123,
            "email": "alice@example.com",
            "name": "Alice",
            "phone": "555-0000",  # Different phone
        })
        
        result = comparator.compare(baseline, test, "horizontal")
        
        # Should detect partial disclosure due to high similarity
        assert result is not None
        assert result.is_vulnerable is True
    
    def test_nested_sensitive_fields(self, comparator):
        """Test detection of sensitive fields in nested objects."""
        data = {
            "user": {
                "profile": {
                    "email": "test@example.com",
                    "personal": {
                        "ssn": "123-45-6789"
                    }
                }
            }
        }
        
        sensitive = comparator._find_sensitive_fields(data)
        
        assert any("email" in s for s in sensitive)
        assert any("ssn" in s for s in sensitive)
    
    def test_similarity_calculation(self, comparator):
        """Test the similarity calculation."""
        obj1 = {"a": 1, "b": 2, "c": 3}
        obj2 = {"a": 1, "b": 2, "c": 3}
        
        similarity = comparator._calculate_similarity(obj1, obj2)
        assert similarity == 1.0
        
        obj3 = {"a": 1, "b": 99, "c": 99}
        similarity = comparator._calculate_similarity(obj1, obj3)
        assert 0 < similarity < 1
    
    def test_text_response_comparison(self, comparator):
        """Test comparison of non-JSON text responses."""
        baseline = self._mock_response(200, None, "User profile: Alice, alice@test.com")
        test = self._mock_response(200, None, "User profile: Alice, alice@test.com")
        
        result = comparator.compare(baseline, test, "horizontal")
        
        assert result is not None
        assert result.is_vulnerable is True


class TestSensitiveFieldDetection:
    """Tests specifically for sensitive field detection."""
    
    @pytest.fixture
    def comparator(self):
        return ResponseComparator()
    
    def test_all_sensitive_patterns(self, comparator):
        """Test all defined sensitive field patterns."""
        data = {
            "email": "test@test.com",
            "phone_number": "555-1234",
            "credit_card": "4111-1111-1111-1111",
            "password": "secret123",
            "token": "jwt.token.here",
            "api_key": "sk-12345",
            "ssn": "123-45-6789",
            "bank_account": "123456789",
        }
        
        sensitive = comparator._find_sensitive_fields(data)
        
        assert len(sensitive) >= 8
    
    def test_case_insensitive_detection(self, comparator):
        """Test that detection works for various field names."""
        data = {
            "email": "test@test.com",
            "phone_number": "555-1234",
            "credit_card": "4111111111111111",
        }
        
        sensitive = comparator._find_sensitive_fields(data)
        
        # Should detect all fields
        assert len(sensitive) >= 3

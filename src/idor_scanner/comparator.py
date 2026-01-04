"""
Response Comparator for the IDOR Scanner.

Intelligently compares API responses to detect unauthorized data access.
Uses semantic comparison, sensitive field detection, and similarity scoring.
"""

import logging
from typing import Any, Dict, List, Optional, Set

from deepdiff import DeepDiff
import httpx

from .models import Severity

logger = logging.getLogger(__name__)


# Sensitive field names to look for
SENSITIVE_FIELDS: Set[str] = {
    # Personal info
    'email', 'emails', 'e-mail', 'e_mail',
    'phone', 'phone_number', 'phoneNumber', 'mobile', 'telephone',
    'ssn', 'social_security', 'socialSecurityNumber',
    'address', 'street', 'city', 'zip', 'zipcode', 'postal',
    'dob', 'date_of_birth', 'dateOfBirth', 'birthday',
    
    # Financial
    'credit_card', 'creditCard', 'card_number', 'cardNumber',
    'cvv', 'cvc', 'expiry', 'expiration',
    'bank_account', 'bankAccount', 'account_number', 'accountNumber',
    'routing_number', 'routingNumber', 'iban', 'swift',
    'balance', 'salary', 'income',
    
    # Authentication
    'password', 'passwd', 'pass', 'pwd',
    'token', 'access_token', 'accessToken', 'auth_token',
    'api_key', 'apiKey', 'secret', 'private_key', 'privateKey',
    'session', 'session_id', 'sessionId',
    'refresh_token', 'refreshToken',
    
    # Identity
    'user_id', 'userId', 'account_id', 'accountId',
    'national_id', 'nationalId', 'passport', 'license',
    'username', 'user_name',
    
    # Health
    'medical', 'health', 'diagnosis', 'prescription',
    'insurance', 'patient',
}

# Critical fields that indicate CRITICAL severity
CRITICAL_FIELDS: Set[str] = {
    'ssn', 'social_security', 'password', 'credit_card', 'cardNumber',
    'cvv', 'token', 'access_token', 'api_key', 'secret', 'private_key',
}


class ComparisonResult:
    """Result of comparing two responses."""
    
    def __init__(
        self,
        is_vulnerable: bool,
        vuln_type: str,
        severity: Severity,
        description: str,
        evidence: Dict[str, Any],
    ):
        self.is_vulnerable = is_vulnerable
        self.vuln_type = vuln_type
        self.severity = severity
        self.description = description
        self.evidence = evidence


class ResponseComparator:
    """
    Intelligently compares API responses to detect unauthorized access.
    
    Features:
    - Status code analysis
    - Semantic JSON comparison using DeepDiff
    - Sensitive field detection
    - Partial data leakage detection
    - Similarity scoring
    - Error message analysis
    """
    
    def __init__(self, sensitivity_threshold: float = 0.7):
        """
        Initialize the comparator.
        
        Args:
            sensitivity_threshold: Similarity threshold above which
                                   partial disclosure is flagged (0.0-1.0)
        """
        self.sensitivity_threshold = sensitivity_threshold
    
    def compare(
        self,
        baseline: httpx.Response,
        test: httpx.Response,
        check_type: str = "horizontal",
    ) -> Optional[ComparisonResult]:
        """
        Compare baseline (authorized) and test (potentially unauthorized) responses.
        
        Args:
            baseline: Response from authorized access
            test: Response from potentially unauthorized access
            check_type: Type of check ("horizontal", "vertical", "method")
            
        Returns:
            ComparisonResult if vulnerable, None otherwise
        """
        # Step 1: Check for proper blocking
        if self._is_properly_blocked(test):
            logger.debug(f"Access properly blocked: {test.status_code}")
            return None
        
        # Step 2: Check for errors
        if test.status_code >= 500:
            logger.debug(f"Server error, not an IDOR: {test.status_code}")
            return None
        
        # Step 3: Compare successful responses
        if baseline.status_code == 200 and test.status_code == 200:
            return self._compare_success_responses(baseline, test, check_type)
        
        # Step 4: Check for unexpected success
        if test.status_code == 200 and baseline.status_code != 200:
            return self._analyze_unexpected_success(test, check_type)
        
        # Step 5: Check error messages for info disclosure
        return self._check_error_disclosure(test, check_type)
    
    def _is_properly_blocked(self, response: httpx.Response) -> bool:
        """Check if access is properly denied."""
        blocked_codes = {401, 403, 404}
        return response.status_code in blocked_codes
    
    def _compare_success_responses(
        self,
        baseline: httpx.Response,
        test: httpx.Response,
        check_type: str,
    ) -> Optional[ComparisonResult]:
        """Compare two successful (200) responses."""
        
        try:
            baseline_data = baseline.json()
            test_data = test.json()
        except Exception:
            # Not JSON, compare as text
            return self._compare_text_responses(baseline.text, test.text, check_type)
        
        # Semantic comparison using DeepDiff
        diff = DeepDiff(
            baseline_data,
            test_data,
            ignore_order=True,
            exclude_regex_paths=[
                r"root\['timestamp'\]",
                r"root\['request_id'\]",
                r"root\['_id'\]",
                r"root\['created_at'\]",
                r"root\['updated_at'\]",
            ],
        )
        
        # Check 1: Responses are identical
        if not diff:
            sensitive_fields = self._find_sensitive_fields(baseline_data)
            severity = self._assess_severity(sensitive_fields)
            
            return ComparisonResult(
                is_vulnerable=True,
                vuln_type=f"{check_type}_identical_response",
                severity=severity,
                description="Attacker received identical data as the victim",
                evidence={
                    "baseline_data": baseline_data,
                    "test_data": test_data,
                    "sensitive_fields_exposed": sensitive_fields,
                    "diff": None,
                },
            )
        
        # Check 2: Partial data leakage
        similarity = self._calculate_similarity(baseline_data, test_data)
        
        if similarity >= self.sensitivity_threshold:
            sensitive_fields = self._find_sensitive_fields(test_data)
            
            if sensitive_fields:
                severity = self._assess_severity(sensitive_fields)
                
                return ComparisonResult(
                    is_vulnerable=True,
                    vuln_type=f"{check_type}_partial_disclosure",
                    severity=severity,
                    description=f"Partial data leakage detected ({similarity*100:.1f}% similarity)",
                    evidence={
                        "similarity_score": similarity,
                        "diff": str(diff),
                        "sensitive_fields_exposed": sensitive_fields,
                    },
                )
        
        # Check 3: Sensitive fields exposed even with different data
        test_sensitive = self._find_sensitive_fields(test_data)
        if test_sensitive:
            # Check if these fields contain actual data (not empty/null)
            meaningful_data = self._has_meaningful_sensitive_data(test_data, test_sensitive)
            
            if meaningful_data:
                severity = self._assess_severity(test_sensitive)
                
                return ComparisonResult(
                    is_vulnerable=True,
                    vuln_type=f"{check_type}_sensitive_exposure",
                    severity=severity,
                    description="Sensitive fields exposed in response",
                    evidence={
                        "sensitive_fields_exposed": test_sensitive,
                        "data_sample": self._sanitize_for_evidence(test_data),
                    },
                )
        
        return None
    
    def _compare_text_responses(
        self,
        baseline_text: str,
        test_text: str,
        check_type: str,
    ) -> Optional[ComparisonResult]:
        """Compare non-JSON text responses."""
        
        if baseline_text == test_text:
            return ComparisonResult(
                is_vulnerable=True,
                vuln_type=f"{check_type}_identical_response",
                severity=Severity.MEDIUM,
                description="Attacker received identical content as the victim",
                evidence={
                    "baseline_length": len(baseline_text),
                    "test_length": len(test_text),
                    "content_type": "text",
                },
            )
        
        # Check for similarity
        similarity = self._text_similarity(baseline_text, test_text)
        if similarity >= self.sensitivity_threshold:
            return ComparisonResult(
                is_vulnerable=True,
                vuln_type=f"{check_type}_partial_disclosure",
                severity=Severity.LOW,
                description=f"Similar content returned ({similarity*100:.1f}% similarity)",
                evidence={
                    "similarity_score": similarity,
                },
            )
        
        return None
    
    def _analyze_unexpected_success(
        self,
        test: httpx.Response,
        check_type: str,
    ) -> Optional[ComparisonResult]:
        """Analyze when test succeeds but baseline didn't."""
        
        try:
            data = test.json()
            sensitive_fields = self._find_sensitive_fields(data)
            
            if sensitive_fields:
                severity = self._assess_severity(sensitive_fields)
                return ComparisonResult(
                    is_vulnerable=True,
                    vuln_type=f"{check_type}_unexpected_access",
                    severity=severity,
                    description="Unexpected successful access with sensitive data",
                    evidence={
                        "status_code": test.status_code,
                        "sensitive_fields_exposed": sensitive_fields,
                    },
                )
        except Exception:
            pass
        
        return None
    
    def _check_error_disclosure(
        self,
        response: httpx.Response,
        check_type: str,
    ) -> Optional[ComparisonResult]:
        """Check if error messages reveal sensitive information."""
        
        disclosure_patterns = [
            r'user[_\s]?id[:\s]+\d+',
            r'account[_\s]?id[:\s]+\d+',
            r'email[:\s]+[^\s@]+@[^\s@]+',
            r'does not exist',
            r'not found for user',
            r'belongs to',
            r'owned by',
        ]
        
        import re
        text = response.text.lower()
        
        for pattern in disclosure_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return ComparisonResult(
                    is_vulnerable=True,
                    vuln_type=f"{check_type}_info_disclosure",
                    severity=Severity.LOW,
                    description="Error message reveals sensitive information",
                    evidence={
                        "status_code": response.status_code,
                        "error_message": response.text[:500],
                    },
                )
        
        return None
    
    def _find_sensitive_fields(
        self,
        data: Any,
        path: str = "",
    ) -> List[str]:
        """Recursively find sensitive fields in data."""
        found = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check if key is sensitive
                key_lower = key.lower()
                if key_lower in SENSITIVE_FIELDS or any(
                    sf in key_lower for sf in SENSITIVE_FIELDS
                ):
                    found.append(current_path)
                
                # Recurse
                found.extend(self._find_sensitive_fields(value, current_path))
                
        elif isinstance(data, list):
            for i, item in enumerate(data):
                found.extend(self._find_sensitive_fields(item, f"{path}[{i}]"))
        
        return found
    
    def _has_meaningful_sensitive_data(
        self,
        data: Any,
        sensitive_paths: List[str],
    ) -> bool:
        """Check if sensitive fields contain meaningful (non-empty) data."""
        
        def get_value(obj: Any, path: str) -> Any:
            """Get value at path."""
            parts = path.replace('[', '.').replace(']', '').split('.')
            current = obj
            for part in parts:
                if not part:
                    continue
                try:
                    if isinstance(current, list):
                        current = current[int(part)]
                    elif isinstance(current, dict):
                        current = current.get(part)
                    else:
                        return None
                except (KeyError, IndexError, TypeError):
                    return None
            return current
        
        for path in sensitive_paths:
            value = get_value(data, path)
            if value and value not in (None, '', [], {}):
                return True
        
        return False
    
    def _assess_severity(self, sensitive_fields: List[str]) -> Severity:
        """Assess vulnerability severity based on exposed fields."""
        
        # Check for critical fields
        for field in sensitive_fields:
            field_lower = field.lower()
            if any(cf in field_lower for cf in CRITICAL_FIELDS):
                return Severity.CRITICAL
        
        # High if many sensitive fields
        if len(sensitive_fields) > 3:
            return Severity.HIGH
        
        # Medium if some sensitive fields
        if len(sensitive_fields) > 0:
            return Severity.MEDIUM
        
        return Severity.LOW
    
    def _calculate_similarity(self, obj1: Any, obj2: Any) -> float:
        """Calculate similarity between two objects (0.0 to 1.0)."""
        
        if obj1 == obj2:
            return 1.0
        
        if type(obj1) != type(obj2):
            return 0.0
        
        if isinstance(obj1, dict):
            if not obj1 and not obj2:
                return 1.0
            
            all_keys = set(obj1.keys()) | set(obj2.keys())
            if not all_keys:
                return 1.0
            
            matching = 0
            for key in all_keys:
                if key in obj1 and key in obj2:
                    if obj1[key] == obj2[key]:
                        matching += 1
                    elif isinstance(obj1[key], (dict, list)):
                        matching += self._calculate_similarity(obj1[key], obj2[key])
            
            return matching / len(all_keys)
        
        elif isinstance(obj1, list):
            if not obj1 and not obj2:
                return 1.0
            if not obj1 or not obj2:
                return 0.0
            
            # Simple length-based comparison for lists
            min_len = min(len(obj1), len(obj2))
            max_len = max(len(obj1), len(obj2))
            
            matching = sum(1 for a, b in zip(obj1, obj2) if a == b)
            return matching / max_len if max_len > 0 else 1.0
        
        return 0.0
    
    def _text_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two text strings."""
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0
        
        # Simple character-based similarity
        set1 = set(text1)
        set2 = set(text2)
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        
        return intersection / union if union > 0 else 0.0
    
    def _sanitize_for_evidence(self, data: Any, max_length: int = 500) -> Any:
        """Sanitize data for including in evidence."""
        import json
        
        try:
            text = json.dumps(data)
            if len(text) > max_length:
                return json.loads(text[:max_length] + "...")
            return data
        except Exception:
            return str(data)[:max_length]

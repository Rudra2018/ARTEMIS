#!/usr/bin/env python3
"""
HackerOne Hai Defensive Countermeasures Implementation
Secure coding patterns and defensive measures to prevent SQL injection vulnerabilities

🛡️ This module provides production-ready security implementations
"""

import re
import logging
import sqlite3
import hashlib
import time
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from contextlib import contextmanager
from functools import wraps
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SecurityConfig:
    """Security configuration settings"""
    max_query_length: int = 1000
    max_context_reports: int = 5
    rate_limit_requests_per_minute: int = 60
    enable_query_logging: bool = True
    enable_input_sanitization: bool = True
    enable_parameterized_queries: bool = True

class SecurityException(Exception):
    """Custom exception for security violations"""
    pass

class InputValidationError(SecurityException):
    """Exception for input validation failures"""
    pass

class SQLInjectionDetected(SecurityException):
    """Exception for detected SQL injection attempts"""
    pass

class SecurityAuditLogger:
    """Security event logging system"""
    
    def __init__(self):
        self.logger = logging.getLogger('security_audit')
        handler = logging.FileHandler('security_audit.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security events for monitoring"""
        event_data = {
            'event_type': event_type,
            'timestamp': time.time(),
            'details': details
        }
        self.logger.warning(f"SECURITY_EVENT: {json.dumps(event_data)}")
    
    def log_sql_injection_attempt(self, input_data: str, source_ip: str = "unknown"):
        """Log SQL injection attempts"""
        self.log_security_event('sql_injection_attempt', {
            'input': input_data,
            'source_ip': source_ip,
            'severity': 'HIGH'
        })
    
    def log_input_validation_failure(self, input_data: str, reason: str):
        """Log input validation failures"""
        self.log_security_event('input_validation_failure', {
            'input': input_data,
            'reason': reason,
            'severity': 'MEDIUM'
        })

class InputValidator:
    """Comprehensive input validation system"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.audit_logger = SecurityAuditLogger()
        
        # SQL injection detection patterns
        self.sql_injection_patterns = [
            r'(\bunion\b.*\bselect\b)',
            r'(\bor\b.*=.*)',
            r'(\band\b.*=.*)',
            r'(;.*drop\b)',
            r'(;.*delete\b)',
            r'(;.*update\b)',
            r'(;.*insert\b)',
            r'(\/\*.*\*\/)',
            r'(--.*)',
            r'(\bexec\b.*\()',
            r'(\bsp_.*)',
            r'(\bxp_.*)',
        ]
        
        # Compile patterns for efficiency
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.sql_injection_patterns
        ]
    
    def validate_report_id(self, report_id: str) -> int:
        """
        Validate and sanitize report ID input
        
        Args:
            report_id: Raw report ID input (e.g., "#123456")
            
        Returns:
            int: Validated report ID as integer
            
        Raises:
            InputValidationError: If input is invalid
            SQLInjectionDetected: If SQL injection attempt detected
        """
        
        if not report_id:
            raise InputValidationError("Report ID cannot be empty")
        
        # Remove # prefix and whitespace
        clean_id = report_id.replace('#', '').strip()
        
        # Check for SQL injection patterns
        for pattern in self.compiled_patterns:
            if pattern.search(clean_id):
                self.audit_logger.log_sql_injection_attempt(report_id)
                raise SQLInjectionDetected(f"SQL injection pattern detected in input: {report_id}")
        
        # Validate format - must be numeric only
        if not re.match(r'^\d+$', clean_id):
            self.audit_logger.log_input_validation_failure(
                report_id, "Non-numeric characters in report ID"
            )
            raise InputValidationError("Report ID must contain only numbers")
        
        # Convert to integer
        try:
            report_id_int = int(clean_id)
        except ValueError:
            raise InputValidationError("Invalid numeric format")
        
        # Validate range (reasonable report ID range)
        if report_id_int <= 0 or report_id_int > 99999999:
            raise InputValidationError("Report ID out of valid range")
        
        return report_id_int
    
    def validate_context_list(self, report_ids: List[str]) -> List[int]:
        """
        Validate a list of report IDs for context window
        
        Args:
            report_ids: List of report ID strings
            
        Returns:
            List[int]: Validated report IDs as integers
            
        Raises:
            InputValidationError: If validation fails
        """
        
        if len(report_ids) > self.config.max_context_reports:
            raise InputValidationError(
                f"Too many reports in context. Maximum {self.config.max_context_reports} allowed"
            )
        
        validated_ids = []
        for report_id in report_ids:
            validated_ids.append(self.validate_report_id(report_id))
        
        return validated_ids
    
    def sanitize_query_input(self, user_input: str) -> str:
        """
        Sanitize user input for safe processing
        
        Args:
            user_input: Raw user input
            
        Returns:
            str: Sanitized input
        """
        
        if not self.config.enable_input_sanitization:
            return user_input
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', user_input)
        
        # Limit length
        if len(sanitized) > self.config.max_query_length:
            sanitized = sanitized[:self.config.max_query_length]
            self.audit_logger.log_input_validation_failure(
                user_input, "Input length exceeded maximum"
            )
        
        return sanitized

class SecureDatabase:
    """Secure database interface with SQL injection protection"""
    
    def __init__(self, db_path: str, config: SecurityConfig):
        self.db_path = db_path
        self.config = config
        self.validator = InputValidator(config)
        self.audit_logger = SecurityAuditLogger()
    
    @contextmanager
    def get_connection(self):
        """Secure database connection context manager"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def execute_secure_query(self, query: str, parameters: tuple = ()) -> List[Dict[str, Any]]:
        """
        Execute parameterized query safely
        
        Args:
            query: SQL query with parameter placeholders
            parameters: Tuple of parameter values
            
        Returns:
            List[Dict]: Query results
        """
        
        if not self.config.enable_parameterized_queries:
            raise SecurityException("Parameterized queries are disabled")
        
        # Log query execution if enabled
        if self.config.enable_query_logging:
            logger.info(f"Executing secure query: {query}")
            logger.info(f"Parameters: {parameters}")
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, parameters)
            
            # Convert rows to dictionaries
            results = []
            for row in cursor.fetchall():
                results.append(dict(row))
            
            return results
    
    def get_vulnerability_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        """
        Securely retrieve a vulnerability report by ID
        
        Args:
            report_id: Validated report ID
            
        Returns:
            Optional[Dict]: Report data or None if not found
        """
        
        query = """
            SELECT id, title, description, severity, status, 
                   reporter_email, program_name, created_date
            FROM vulnerability_reports 
            WHERE id = ?
        """
        
        results = self.execute_secure_query(query, (report_id,))
        return results[0] if results else None
    
    def get_multiple_reports(self, report_ids: List[int]) -> List[Dict[str, Any]]:
        """
        Securely retrieve multiple vulnerability reports
        
        Args:
            report_ids: List of validated report IDs
            
        Returns:
            List[Dict]: List of report data
        """
        
        if not report_ids:
            return []
        
        # Create placeholder string for IN clause
        placeholders = ','.join(['?' for _ in report_ids])
        
        query = f"""
            SELECT id, title, description, severity, status, 
                   reporter_email, program_name, created_date
            FROM vulnerability_reports 
            WHERE id IN ({placeholders})
            ORDER BY id
        """
        
        return self.execute_secure_query(query, tuple(report_ids))
    
    def search_reports_secure(self, search_term: str, user_permissions: List[str]) -> List[Dict[str, Any]]:
        """
        Securely search vulnerability reports with access control
        
        Args:
            search_term: Sanitized search term
            user_permissions: List of user permissions
            
        Returns:
            List[Dict]: Filtered search results
        """
        
        # Sanitize search term
        sanitized_term = self.validator.sanitize_query_input(search_term)
        
        # Base query with access control
        query = """
            SELECT id, title, description, severity, status, 
                   reporter_email, program_name, created_date
            FROM vulnerability_reports 
            WHERE (title LIKE ? OR description LIKE ?)
        """
        
        params = [f"%{sanitized_term}%", f"%{sanitized_term}%"]
        
        # Add confidentiality filter if user doesn't have admin access
        if 'admin_access' not in user_permissions:
            query += " AND is_confidential = 0"
        
        query += " ORDER BY created_date DESC LIMIT 50"
        
        return self.execute_secure_query(query, tuple(params))

class RateLimiter:
    """Rate limiting for API requests"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.request_counts = {}
        self.audit_logger = SecurityAuditLogger()
    
    def check_rate_limit(self, user_id: str) -> bool:
        """
        Check if user has exceeded rate limit
        
        Args:
            user_id: User identifier
            
        Returns:
            bool: True if within rate limit, False otherwise
        """
        
        current_time = time.time()
        current_minute = int(current_time // 60)
        
        # Clean old entries
        self.request_counts = {
            minute: count for minute, count in self.request_counts.items()
            if current_minute - minute < 2
        }
        
        # Check current minute's requests
        current_requests = self.request_counts.get(current_minute, 0)
        
        if current_requests >= self.config.rate_limit_requests_per_minute:
            self.audit_logger.log_security_event('rate_limit_exceeded', {
                'user_id': user_id,
                'requests_per_minute': current_requests,
                'limit': self.config.rate_limit_requests_per_minute
            })
            return False
        
        # Increment request count
        self.request_counts[current_minute] = current_requests + 1
        return True

def rate_limit_decorator(rate_limiter: RateLimiter):
    """Decorator for rate limiting function calls"""
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Extract user_id from arguments (assumes it's the first argument after self)
            user_id = args[0] if args else "unknown"
            
            if not rate_limiter.check_rate_limit(str(user_id)):
                raise SecurityException("Rate limit exceeded")
            
            return func(self, *args, **kwargs)
        return wrapper
    return decorator

class SecureHaiInterface:
    """Secure interface for Hai report processing"""
    
    def __init__(self, db_path: str, config: SecurityConfig = None):
        self.config = config or SecurityConfig()
        self.database = SecureDatabase(db_path, self.config)
        self.validator = InputValidator(self.config)
        self.rate_limiter = RateLimiter(self.config)
        self.audit_logger = SecurityAuditLogger()
    
    def process_report_request(self, user_id: str, report_id_input: str, 
                             user_permissions: List[str] = None) -> Dict[str, Any]:
        """
        Securely process a report request
        
        Args:
            user_id: User identifier for rate limiting
            report_id_input: Raw report ID input
            user_permissions: List of user permissions
            
        Returns:
            Dict: Processed report data or error response
        """
        
        user_permissions = user_permissions or ['read_reports']
        
        try:
            # Validate report ID
            validated_id = self.validator.validate_report_id(report_id_input)
            
            # Get report data
            report_data = self.database.get_vulnerability_report(validated_id)
            
            if not report_data:
                return {
                    'success': False,
                    'error': 'Report not found',
                    'report_id': validated_id
                }
            
            # Apply access control
            if report_data.get('is_confidential') and 'admin_access' not in user_permissions:
                self.audit_logger.log_security_event('unauthorized_access_attempt', {
                    'user_id': user_id,
                    'report_id': validated_id,
                    'reason': 'Attempted access to confidential report'
                })
                return {
                    'success': False,
                    'error': 'Access denied - insufficient permissions'
                }
            
            return {
                'success': True,
                'data': report_data
            }
            
        except (InputValidationError, SQLInjectionDetected) as e:
            self.audit_logger.log_security_event('security_violation', {
                'user_id': user_id,
                'input': report_id_input,
                'error': str(e),
                'severity': 'HIGH'
            })
            
            return {
                'success': False,
                'error': 'Invalid input - security violation detected'
            }
        
        except SecurityException as e:
            return {
                'success': False,
                'error': str(e)
            }
        
        except Exception as e:
            logger.error(f"Unexpected error processing report request: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def process_context_request(self, user_id: str, report_ids_input: List[str],
                              user_permissions: List[str] = None) -> Dict[str, Any]:
        """
        Securely process multiple reports for context window
        
        Args:
            user_id: User identifier
            report_ids_input: List of raw report ID inputs
            user_permissions: List of user permissions
            
        Returns:
            Dict: Context data or error response
        """
        
        user_permissions = user_permissions or ['read_reports']
        
        try:
            # Validate all report IDs
            validated_ids = self.validator.validate_context_list(report_ids_input)
            
            # Get report data
            reports_data = self.database.get_multiple_reports(validated_ids)
            
            # Apply access control
            accessible_reports = []
            for report in reports_data:
                if not report.get('is_confidential') or 'admin_access' in user_permissions:
                    accessible_reports.append(report)
                else:
                    self.audit_logger.log_security_event('unauthorized_access_attempt', {
                        'user_id': user_id,
                        'report_id': report['id'],
                        'reason': 'Attempted access to confidential report in context'
                    })
            
            return {
                'success': True,
                'data': accessible_reports,
                'context_size': len(accessible_reports)
            }
            
        except (InputValidationError, SQLInjectionDetected) as e:
            self.audit_logger.log_security_event('security_violation', {
                'user_id': user_id,
                'input': report_ids_input,
                'error': str(e),
                'severity': 'HIGH'
            })
            
            return {
                'success': False,
                'error': 'Invalid input - security violation detected'
            }
        
        except SecurityException as e:
            return {
                'success': False,
                'error': str(e)
            }

def create_secure_hai_system(db_path: str) -> SecureHaiInterface:
    """
    Factory function to create a secure Hai system
    
    Args:
        db_path: Path to database file
        
    Returns:
        SecureHaiInterface: Configured secure interface
    """
    
    # Production security configuration
    config = SecurityConfig(
        max_query_length=500,
        max_context_reports=5,
        rate_limit_requests_per_minute=60,
        enable_query_logging=True,
        enable_input_sanitization=True,
        enable_parameterized_queries=True
    )
    
    return SecureHaiInterface(db_path, config)

# Example usage and testing
def demonstrate_secure_implementation():
    """Demonstrate secure implementation usage"""
    
    logger.info("🛡️ Demonstrating Secure Hai Implementation")
    logger.info("=" * 60)
    
    # Create secure interface
    secure_hai = create_secure_hai_system(":memory:")
    
    # Test legitimate requests
    logger.info("\n✅ Testing legitimate requests:")
    
    # Normal report request
    result1 = secure_hai.process_report_request("user123", "#123456")
    logger.info(f"Normal request result: {result1['success']}")
    
    # Multiple reports request
    result2 = secure_hai.process_context_request("user123", ["#123456", "#789012"])
    logger.info(f"Context request result: {result2['success']}")
    
    # Test malicious requests
    logger.info("\n🚨 Testing malicious requests (should be blocked):")
    
    # SQL injection attempt
    result3 = secure_hai.process_report_request(
        "attacker", "#123456 UNION SELECT * FROM user_sessions"
    )
    logger.info(f"SQL injection blocked: {not result3['success']}")
    
    # Context overflow attempt
    result4 = secure_hai.process_context_request(
        "attacker", [f"#{i}" for i in range(100000, 100010)]
    )
    logger.info(f"Context overflow blocked: {not result4['success']}")
    
    logger.info("\n🔒 Secure implementation demonstration completed")

if __name__ == "__main__":
    demonstrate_secure_implementation()
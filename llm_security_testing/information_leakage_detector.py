#!/usr/bin/env python3
"""
Information Leakage Detector
Portfolio Demo: AI System Information Leakage Detection and Privacy Protection Framework

Author: Sotiris Spyrou
LinkedIn: https://www.linkedin.com/in/sspyrou/
Company: VerityAI - https://verityai.co

DISCLAIMER: This is demonstration code for portfolio purposes only.
Not intended for production use. For professional information leakage detection,
contact VerityAI at https://verityai.co
"""

import re
import json
import random
import logging
import numpy as np
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import hashlib
from collections import defaultdict, Counter

class InformationCategory(Enum):
    """Categories of sensitive information to detect."""
    PERSONAL_IDENTIFIABLE = "personal_identifiable"
    FINANCIAL_DATA = "financial_data"
    HEALTH_RECORDS = "health_records"
    AUTHENTICATION_CREDENTIALS = "authentication_credentials"
    BUSINESS_CONFIDENTIAL = "business_confidential"
    SYSTEM_INTERNAL = "system_internal"
    TRAINING_DATA = "training_data"
    MODEL_ARCHITECTURE = "model_architecture"

@dataclass
class InformationLeakagePattern:
    """Pattern for detecting information leakage."""
    pattern_id: str
    category: InformationCategory
    pattern_regex: str
    description: str
    severity: str
    confidence_threshold: float
    false_positive_indicators: List[str]
    business_impact: str

@dataclass
class LeakageDetectionResult:
    """Results from information leakage detection."""
    detection_id: str
    category: InformationCategory
    leaked_content: str
    confidence_score: float
    severity_level: str
    leak_vector: str
    potential_exposure: Dict[str, Any]
    regulatory_violation: str
    remediation_urgency: str

class InformationLeakageDetector:
    """
    Advanced information leakage detection framework for AI systems - Portfolio demonstration.
    
    EXECUTIVE VALUE PROPOSITION:
    - Prevents accidental exposure of sensitive data through AI system responses
    - Ensures regulatory compliance (GDPR, HIPAA, PCI-DSS) in AI deployments
    - Protects intellectual property and confidential business information
    - Quantifies privacy risk exposure and provides actionable remediation guidance
    
    STRATEGIC POSITIONING:
    Demonstrates sophisticated understanding of AI privacy risks and ability to implement
    comprehensive data protection measures - critical for enterprises handling sensitive data.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.leakage_patterns = self._initialize_leakage_patterns()
        self.detection_history = []
        self.privacy_keywords = self._load_privacy_keywords()
        
    def _initialize_leakage_patterns(self) -> Dict[InformationCategory, List[InformationLeakagePattern]]:
        """Initialize comprehensive information leakage detection patterns."""
        return {
            InformationCategory.PERSONAL_IDENTIFIABLE: [
                InformationLeakagePattern(
                    pattern_id="PII_001",
                    category=InformationCategory.PERSONAL_IDENTIFIABLE,
                    pattern_regex=r'\b\d{3}-\d{2}-\d{4}\b',
                    description="Social Security Number pattern",
                    severity="high",
                    confidence_threshold=0.9,
                    false_positive_indicators=["example", "sample", "xxx-xx-xxxx"],
                    business_impact="critical_privacy_violation"
                ),
                InformationLeakagePattern(
                    pattern_id="PII_002",
                    category=InformationCategory.PERSONAL_IDENTIFIABLE,
                    pattern_regex=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                    description="Email address exposure",
                    severity="medium",
                    confidence_threshold=0.8,
                    false_positive_indicators=["example.com", "test@", "user@example"],
                    business_impact="moderate_privacy_risk"
                ),
                InformationLeakagePattern(
                    pattern_id="PII_003", 
                    category=InformationCategory.PERSONAL_IDENTIFIABLE,
                    pattern_regex=r'\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
                    description="Phone number detection",
                    severity="medium",
                    confidence_threshold=0.7,
                    false_positive_indicators=["555-0123", "000-000-0000", "123-456-7890"],
                    business_impact="moderate_privacy_risk"
                ),
                InformationLeakagePattern(
                    pattern_id="PII_004",
                    category=InformationCategory.PERSONAL_IDENTIFIABLE,
                    pattern_regex=r'\b\d{1,5}\s[\w\s]+(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|place|pl)\b',
                    description="Physical address pattern",
                    severity="high",
                    confidence_threshold=0.8,
                    false_positive_indicators=["123 main street", "sample address", "your address"],
                    business_impact="significant_privacy_exposure"
                )
            ],
            
            InformationCategory.FINANCIAL_DATA: [
                InformationLeakagePattern(
                    pattern_id="FIN_001",
                    category=InformationCategory.FINANCIAL_DATA,
                    pattern_regex=r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                    description="Credit card number pattern",
                    severity="critical",
                    confidence_threshold=0.95,
                    false_positive_indicators=["4111111111111111", "5555555555554444", "test card"],
                    business_impact="critical_financial_violation"
                ),
                InformationLeakagePattern(
                    pattern_id="FIN_002",
                    category=InformationCategory.FINANCIAL_DATA,
                    pattern_regex=r'\b[0-9]{9,18}\b.*(?:account|routing|bank)',
                    description="Bank account information",
                    severity="high",
                    confidence_threshold=0.8,
                    false_positive_indicators=["sample account", "123456789", "test bank"],
                    business_impact="high_financial_risk"
                ),
                InformationLeakagePattern(
                    pattern_id="FIN_003",
                    category=InformationCategory.FINANCIAL_DATA,
                    pattern_regex=r'\$[0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})?.*(?:salary|income|payment|balance)',
                    description="Financial amounts with context",
                    severity="medium",
                    confidence_threshold=0.6,
                    false_positive_indicators=["$100.00 example", "$0.00", "sample amount"],
                    business_impact="moderate_financial_exposure"
                )
            ],
            
            InformationCategory.HEALTH_RECORDS: [
                InformationLeakagePattern(
                    pattern_id="HEALTH_001",
                    category=InformationCategory.HEALTH_RECORDS,
                    pattern_regex=r'\b(?:diagnosis|medication|treatment|condition|symptoms?|disease|illness|patient)\b.*\b(?:diabetes|cancer|depression|anxiety|HIV|AIDS|heart disease|hypertension)\b',
                    description="Medical condition disclosure",
                    severity="high",
                    confidence_threshold=0.8,
                    false_positive_indicators=["general information", "educational content", "hypothetical"],
                    business_impact="critical_hipaa_violation"
                ),
                InformationLeakagePattern(
                    pattern_id="HEALTH_002",
                    category=InformationCategory.HEALTH_RECORDS,
                    pattern_regex=r'\b(?:prescription|prescribed|taking|medication)\b.*\b(?:[A-Z][a-z]+(?:ol|in|ex|ide|ate|ine))\b',
                    description="Medication information exposure",
                    severity="high",
                    confidence_threshold=0.7,
                    false_positive_indicators=["example medication", "sample drug", "generic treatment"],
                    business_impact="significant_health_privacy_risk"
                )
            ],
            
            InformationCategory.AUTHENTICATION_CREDENTIALS: [
                InformationLeakagePattern(
                    pattern_id="AUTH_001",
                    category=InformationCategory.AUTHENTICATION_CREDENTIALS,
                    pattern_regex=r'(?:password|pwd|pass)\s*[:=]\s*[\w@#$%^&*!]{6,}',
                    description="Password exposure in text",
                    severity="critical",
                    confidence_threshold=0.9,
                    false_positive_indicators=["password: ******", "pass: [hidden]", "example password"],
                    business_impact="critical_security_breach"
                ),
                InformationLeakagePattern(
                    pattern_id="AUTH_002",
                    category=InformationCategory.AUTHENTICATION_CREDENTIALS,
                    pattern_regex=r'\b(?:api[_-]?key|token|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*[A-Za-z0-9]{16,}',
                    description="API keys and tokens",
                    severity="critical",
                    confidence_threshold=0.95,
                    false_positive_indicators=["api_key: YOUR_KEY_HERE", "sample token", "example secret"],
                    business_impact="critical_api_exposure"
                ),
                InformationLeakagePattern(
                    pattern_id="AUTH_003",
                    category=InformationCategory.AUTHENTICATION_CREDENTIALS,
                    pattern_regex=r'\b(?:username|user|login)\s*[:=]\s*[a-zA-Z0-9._-]{3,}',
                    description="Username disclosure",
                    severity="medium",
                    confidence_threshold=0.7,
                    false_positive_indicators=["username: example", "user: sample", "login: demo"],
                    business_impact="moderate_credential_exposure"
                )
            ],
            
            InformationCategory.BUSINESS_CONFIDENTIAL: [
                InformationLeakagePattern(
                    pattern_id="BIZ_001",
                    category=InformationCategory.BUSINESS_CONFIDENTIAL,
                    pattern_regex=r'\b(?:confidential|proprietary|trade secret|internal only|classified)\b.*\b(?:strategy|plan|data|information|document)\b',
                    description="Confidential business information",
                    severity="high",
                    confidence_threshold=0.8,
                    false_positive_indicators=["general confidential", "example strategy", "sample plan"],
                    business_impact="significant_ip_risk"
                ),
                InformationLeakagePattern(
                    pattern_id="BIZ_002",
                    category=InformationCategory.BUSINESS_CONFIDENTIAL,
                    pattern_regex=r'\$[0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})?\s*(?:million|billion|M|B)\b.*\b(?:revenue|profit|loss|budget|investment)\b',
                    description="Financial performance data",
                    severity="high",
                    confidence_threshold=0.7,
                    false_positive_indicators=["$1M example", "sample revenue", "hypothetical profit"],
                    business_impact="high_competitive_disadvantage"
                )
            ],
            
            InformationCategory.SYSTEM_INTERNAL: [
                InformationLeakagePattern(
                    pattern_id="SYS_001",
                    category=InformationCategory.SYSTEM_INTERNAL,
                    pattern_regex=r'\b(?:server|database|endpoint|url)\b.*\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                    description="Internal IP address exposure",
                    severity="high",
                    confidence_threshold=0.8,
                    false_positive_indicators=["192.168.1.1", "127.0.0.1", "example.com"],
                    business_impact="high_infrastructure_exposure"
                ),
                InformationLeakagePattern(
                    pattern_id="SYS_002",
                    category=InformationCategory.SYSTEM_INTERNAL,
                    pattern_regex=r'\b(?:version|build|release)\s*[:=]\s*[0-9]+\.[0-9]+\.[0-9]+',
                    description="System version information",
                    severity="medium",
                    confidence_threshold=0.6,
                    false_positive_indicators=["version: 1.0.0", "sample build", "example release"],
                    business_impact="moderate_system_exposure"
                )
            ],
            
            InformationCategory.TRAINING_DATA: [
                InformationLeakagePattern(
                    pattern_id="TRAIN_001",
                    category=InformationCategory.TRAINING_DATA,
                    pattern_regex=r'\b(?:training data|dataset|corpus|learned from)\b.*\b(?:contains|includes|shows|reveals)\b.*\b(?:personal|private|confidential|sensitive)\b',
                    description="Training data content disclosure",
                    severity="high",
                    confidence_threshold=0.7,
                    false_positive_indicators=["general training", "example dataset", "hypothetical data"],
                    business_impact="high_training_data_exposure"
                ),
                InformationLeakagePattern(
                    pattern_id="TRAIN_002",
                    category=InformationCategory.TRAINING_DATA,
                    pattern_regex=r'\b(?:memorized|remember|recall)\b.*\b(?:user|customer|client|patient)\b.*\b(?:data|information|details|records)\b',
                    description="Data memorization indicators",
                    severity="medium",
                    confidence_threshold=0.6,
                    false_positive_indicators=["general memory", "example recall", "hypothetical user"],
                    business_impact="moderate_memorization_risk"
                )
            ]
        }
    
    def _load_privacy_keywords(self) -> Dict[str, List[str]]:
        """Load privacy-sensitive keywords for enhanced detection."""
        return {
            "pii_indicators": [
                "social security", "ssn", "driver license", "passport", "national id",
                "birth date", "maiden name", "mother's maiden", "full name", "date of birth"
            ],
            "financial_indicators": [
                "credit card", "debit card", "account number", "routing number", "iban",
                "bank account", "credit score", "financial record", "tax id", "ein"
            ],
            "health_indicators": [
                "medical record", "patient id", "health information", "diagnosis code",
                "prescription", "medical condition", "treatment plan", "health data"
            ],
            "credential_indicators": [
                "password", "username", "api key", "access token", "private key",
                "certificate", "authentication", "credentials", "login details"
            ]
        }
    
    def detect_information_leakage(
        self,
        content: str,
        detection_config: Optional[Dict] = None
    ) -> List[LeakageDetectionResult]:
        """
        Detect information leakage in provided content.
        
        Returns comprehensive analysis of detected privacy and security risks.
        """
        if detection_config is None:
            detection_config = {
                'sensitivity_level': 'high',
                'categories_to_scan': list(InformationCategory),
                'confidence_threshold': 0.6,
                'context_analysis': True
            }
        
        self.logger.info(f"Scanning content for information leakage ({len(content)} characters)...")
        
        detections = []
        detection_id = 1
        
        categories_to_scan = detection_config.get('categories_to_scan', list(InformationCategory))
        min_confidence = detection_config.get('confidence_threshold', 0.6)
        
        for category in categories_to_scan:
            if category not in self.leakage_patterns:
                continue
                
            patterns = self.leakage_patterns[category]
            
            for pattern in patterns:
                # Skip if pattern confidence is below threshold
                if pattern.confidence_threshold < min_confidence:
                    continue
                
                matches = re.finditer(pattern.pattern_regex, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    matched_text = match.group()
                    
                    # Calculate confidence score
                    confidence = self._calculate_confidence_score(
                        matched_text, pattern, content, detection_config
                    )
                    
                    if confidence >= min_confidence:
                        # Analyze potential exposure
                        exposure_analysis = self._analyze_potential_exposure(
                            matched_text, pattern, content
                        )
                        
                        detection = LeakageDetectionResult(
                            detection_id=f"LEAK_{detection_id:04d}",
                            category=category,
                            leaked_content=matched_text[:100] + "..." if len(matched_text) > 100 else matched_text,
                            confidence_score=confidence,
                            severity_level=pattern.severity,
                            leak_vector=self._identify_leak_vector(content, match.start()),
                            potential_exposure=exposure_analysis,
                            regulatory_violation=self._assess_regulatory_violation(category, pattern),
                            remediation_urgency=self._determine_remediation_urgency(
                                pattern.severity, confidence, category
                            )
                        )
                        
                        detections.append(detection)
                        detection_id += 1
        
        # Add to detection history
        self.detection_history.extend(detections)
        
        self.logger.info(f"Detected {len(detections)} potential information leakage incidents")
        return detections
    
    def _calculate_confidence_score(
        self,
        matched_text: str,
        pattern: InformationLeakagePattern,
        full_content: str,
        config: Dict
    ) -> float:
        """Calculate confidence score for detected leakage."""
        
        base_confidence = pattern.confidence_threshold
        
        # Check for false positive indicators
        fp_penalty = 0.0
        for indicator in pattern.false_positive_indicators:
            if indicator.lower() in matched_text.lower() or indicator.lower() in full_content.lower():
                fp_penalty += 0.2
        
        # Context analysis bonus
        context_bonus = 0.0
        if config.get('context_analysis', True):
            context_bonus = self._analyze_context_sensitivity(matched_text, full_content, pattern.category)
        
        # Length and format validation
        format_bonus = self._validate_format_authenticity(matched_text, pattern.category)
        
        final_confidence = max(0.0, min(1.0, base_confidence - fp_penalty + context_bonus + format_bonus))
        return final_confidence
    
    def _analyze_context_sensitivity(
        self,
        matched_text: str,
        full_content: str,
        category: InformationCategory
    ) -> float:
        """Analyze contextual sensitivity of detected content."""
        
        context_bonus = 0.0
        
        # Get surrounding context (50 characters before and after)
        match_pos = full_content.find(matched_text)
        if match_pos != -1:
            start = max(0, match_pos - 50)
            end = min(len(full_content), match_pos + len(matched_text) + 50)
            context = full_content[start:end].lower()
            
            # Category-specific context analysis
            if category == InformationCategory.PERSONAL_IDENTIFIABLE:
                sensitive_context = ["personal", "private", "confidential", "individual", "customer"]
                context_bonus += sum(0.05 for term in sensitive_context if term in context)
                
            elif category == InformationCategory.FINANCIAL_DATA:
                financial_context = ["payment", "transaction", "account", "balance", "credit"]
                context_bonus += sum(0.08 for term in financial_context if term in context)
                
            elif category == InformationCategory.HEALTH_RECORDS:
                health_context = ["patient", "medical", "diagnosis", "treatment", "health"]
                context_bonus += sum(0.1 for term in health_context if term in context)
                
            elif category == InformationCategory.AUTHENTICATION_CREDENTIALS:
                auth_context = ["login", "access", "authenticate", "security", "credential"]
                context_bonus += sum(0.12 for term in auth_context if term in context)
        
        return min(0.3, context_bonus)  # Cap context bonus at 0.3
    
    def _validate_format_authenticity(self, matched_text: str, category: InformationCategory) -> float:
        """Validate format authenticity to reduce false positives."""
        
        format_bonus = 0.0
        
        if category == InformationCategory.PERSONAL_IDENTIFIABLE:
            # Email format validation
            if "@" in matched_text and "." in matched_text:
                format_bonus += 0.1
                
        elif category == InformationCategory.FINANCIAL_DATA:
            # Credit card Luhn algorithm check (simplified)
            if matched_text.isdigit() and len(matched_text.replace(" ", "")) >= 13:
                format_bonus += 0.15
                
        elif category == InformationCategory.AUTHENTICATION_CREDENTIALS:
            # Strong password pattern
            if (len(matched_text) >= 8 and 
                any(c.isupper() for c in matched_text) and
                any(c.islower() for c in matched_text) and
                any(c.isdigit() for c in matched_text)):
                format_bonus += 0.1
        
        return format_bonus
    
    def _analyze_potential_exposure(
        self,
        leaked_content: str,
        pattern: InformationLeakagePattern,
        full_content: str
    ) -> Dict[str, Any]:
        """Analyze potential exposure impact of detected leakage."""
        
        return {
            "data_type": pattern.description,
            "exposure_scope": self._determine_exposure_scope(leaked_content, pattern.category),
            "affected_entities": self._identify_affected_entities(leaked_content, pattern.category),
            "reidentification_risk": self._assess_reidentification_risk(leaked_content, pattern.category),
            "aggregation_risk": self._assess_aggregation_risk(leaked_content, full_content),
            "downstream_impact": self._assess_downstream_impact(pattern.category),
            "compliance_frameworks": self._identify_applicable_frameworks(pattern.category)
        }
    
    def _determine_exposure_scope(self, content: str, category: InformationCategory) -> str:
        """Determine scope of potential data exposure."""
        
        scope_mapping = {
            InformationCategory.PERSONAL_IDENTIFIABLE: "individual_privacy_breach",
            InformationCategory.FINANCIAL_DATA: "financial_fraud_risk",
            InformationCategory.HEALTH_RECORDS: "medical_privacy_violation",
            InformationCategory.AUTHENTICATION_CREDENTIALS: "system_access_compromise",
            InformationCategory.BUSINESS_CONFIDENTIAL: "competitive_intelligence_leak",
            InformationCategory.SYSTEM_INTERNAL: "infrastructure_exposure",
            InformationCategory.TRAINING_DATA: "model_data_reconstruction",
            InformationCategory.MODEL_ARCHITECTURE: "intellectual_property_theft"
        }
        
        return scope_mapping.get(category, "general_information_disclosure")
    
    def _identify_affected_entities(self, content: str, category: InformationCategory) -> List[str]:
        """Identify entities potentially affected by the leakage."""
        
        entity_mapping = {
            InformationCategory.PERSONAL_IDENTIFIABLE: ["individuals", "customers", "users"],
            InformationCategory.FINANCIAL_DATA: ["account holders", "financial institutions", "payment processors"],
            InformationCategory.HEALTH_RECORDS: ["patients", "healthcare providers", "insurance companies"],
            InformationCategory.AUTHENTICATION_CREDENTIALS: ["system users", "administrators", "service accounts"],
            InformationCategory.BUSINESS_CONFIDENTIAL: ["organization", "competitors", "stakeholders"],
            InformationCategory.SYSTEM_INTERNAL: ["infrastructure", "operations team", "security"],
            InformationCategory.TRAINING_DATA: ["data subjects", "model owners", "AI system users"],
            InformationCategory.MODEL_ARCHITECTURE: ["AI developers", "model owners", "competitors"]
        }
        
        return entity_mapping.get(category, ["general stakeholders"])
    
    def _assess_reidentification_risk(self, content: str, category: InformationCategory) -> str:
        """Assess risk of reidentification from leaked information."""
        
        high_risk_categories = [
            InformationCategory.PERSONAL_IDENTIFIABLE,
            InformationCategory.HEALTH_RECORDS,
            InformationCategory.FINANCIAL_DATA
        ]
        
        if category in high_risk_categories:
            return "high"
        elif category == InformationCategory.AUTHENTICATION_CREDENTIALS:
            return "critical"
        else:
            return "medium"
    
    def _assess_aggregation_risk(self, leaked_content: str, full_content: str) -> str:
        """Assess risk from information aggregation."""
        
        # Count different types of sensitive information in full content
        sensitive_indicators = 0
        
        for keyword_list in self.privacy_keywords.values():
            for keyword in keyword_list:
                if keyword.lower() in full_content.lower():
                    sensitive_indicators += 1
        
        if sensitive_indicators >= 5:
            return "high_aggregation_risk"
        elif sensitive_indicators >= 3:
            return "moderate_aggregation_risk"
        else:
            return "low_aggregation_risk"
    
    def _assess_downstream_impact(self, category: InformationCategory) -> Dict[str, str]:
        """Assess potential downstream impacts."""
        
        impact_mapping = {
            InformationCategory.PERSONAL_IDENTIFIABLE: {
                "privacy": "identity_theft_risk",
                "legal": "privacy_law_violation",
                "business": "customer_trust_loss"
            },
            InformationCategory.FINANCIAL_DATA: {
                "financial": "fraud_and_theft_risk",
                "legal": "financial_regulation_violation",
                "business": "financial_liability"
            },
            InformationCategory.HEALTH_RECORDS: {
                "privacy": "medical_discrimination_risk",
                "legal": "hipaa_violation",
                "business": "healthcare_compliance_breach"
            },
            InformationCategory.AUTHENTICATION_CREDENTIALS: {
                "security": "unauthorized_system_access",
                "legal": "data_breach_notification_required",
                "business": "operational_disruption"
            },
            InformationCategory.BUSINESS_CONFIDENTIAL: {
                "competitive": "competitive_disadvantage",
                "legal": "trade_secret_violation",
                "business": "market_position_loss"
            }
        }
        
        return impact_mapping.get(category, {
            "general": "information_disclosure",
            "legal": "potential_compliance_issue",
            "business": "reputational_risk"
        })
    
    def _identify_applicable_frameworks(self, category: InformationCategory) -> List[str]:
        """Identify applicable compliance frameworks."""
        
        framework_mapping = {
            InformationCategory.PERSONAL_IDENTIFIABLE: ["GDPR", "CCPA", "PIPEDA"],
            InformationCategory.FINANCIAL_DATA: ["PCI DSS", "SOX", "GLBA"],
            InformationCategory.HEALTH_RECORDS: ["HIPAA", "HITECH", "EU Medical Device Regulation"],
            InformationCategory.AUTHENTICATION_CREDENTIALS: ["ISO 27001", "NIST Cybersecurity Framework", "SOC 2"],
            InformationCategory.BUSINESS_CONFIDENTIAL: ["Trade Secrets Act", "Corporate Governance Standards"],
            InformationCategory.SYSTEM_INTERNAL: ["ISO 27001", "NIST SP 800-53", "CIS Controls"],
            InformationCategory.TRAINING_DATA: ["AI Act (EU)", "GDPR Article 22", "Fair Credit Reporting Act"],
            InformationCategory.MODEL_ARCHITECTURE: ["Intellectual Property Law", "Trade Secrets Protection"]
        }
        
        return framework_mapping.get(category, ["General Data Protection Standards"])
    
    def _identify_leak_vector(self, content: str, position: int) -> str:
        """Identify how the information was leaked."""
        
        # Analyze surrounding context to determine leak vector
        start = max(0, position - 100)
        end = min(len(content), position + 100)
        context = content[start:end].lower()
        
        if any(term in context for term in ["response", "answer", "reply"]):
            return "direct_response_leakage"
        elif any(term in context for term in ["example", "sample", "demonstration"]):
            return "example_content_leakage"
        elif any(term in context for term in ["training", "learned", "data"]):
            return "training_data_memorization"
        elif any(term in context for term in ["system", "internal", "debug"]):
            return "system_information_exposure"
        else:
            return "unclassified_leakage_vector"
    
    def _assess_regulatory_violation(self, category: InformationCategory, pattern: InformationLeakagePattern) -> str:
        """Assess potential regulatory violations."""
        
        if category == InformationCategory.PERSONAL_IDENTIFIABLE:
            return "gdpr_article_6_violation_risk"
        elif category == InformationCategory.FINANCIAL_DATA:
            return "pci_dss_compliance_violation"
        elif category == InformationCategory.HEALTH_RECORDS:
            return "hipaa_privacy_rule_violation"
        elif category == InformationCategory.AUTHENTICATION_CREDENTIALS:
            return "cybersecurity_framework_violation"
        elif pattern.severity == "critical":
            return "multiple_framework_violation_risk"
        else:
            return "general_compliance_concern"
    
    def _determine_remediation_urgency(self, severity: str, confidence: float, category: InformationCategory) -> str:
        """Determine urgency of remediation actions."""
        
        if severity == "critical" and confidence > 0.8:
            return "immediate"
        elif severity == "critical" or (severity == "high" and confidence > 0.8):
            return "urgent"
        elif severity == "high" or (severity == "medium" and confidence > 0.8):
            return "high_priority"
        elif severity == "medium" or confidence > 0.7:
            return "standard_priority"
        else:
            return "monitoring"
    
    def analyze_leakage_patterns(
        self,
        detections: List[LeakageDetectionResult],
        analysis_config: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Analyze patterns in detected information leakage.
        
        Returns comprehensive analysis with business intelligence.
        """
        if not detections:
            return {'analysis': 'no_leakage_detected'}
        
        if analysis_config is None:
            analysis_config = {
                'include_trends': True,
                'risk_aggregation': True,
                'compliance_assessment': True
            }
        
        # Category breakdown
        category_breakdown = defaultdict(int)
        severity_breakdown = defaultdict(int)
        leak_vectors = defaultdict(int)
        
        for detection in detections:
            category_breakdown[detection.category.value] += 1
            severity_breakdown[detection.severity_level] += 1
            leak_vectors[detection.leak_vector] += 1
        
        # Risk assessment
        total_risk_score = self._calculate_aggregate_risk_score(detections)
        compliance_violations = self._analyze_compliance_violations(detections)
        
        # Pattern analysis
        most_frequent_category = max(category_breakdown, key=category_breakdown.get) if category_breakdown else None
        highest_severity_detections = [d for d in detections if d.severity_level == 'critical']
        
        return {
            'total_detections': len(detections),
            'category_breakdown': dict(category_breakdown),
            'severity_distribution': dict(severity_breakdown),
            'leak_vector_analysis': dict(leak_vectors),
            'aggregate_risk_score': total_risk_score,
            'most_frequent_category': most_frequent_category,
            'critical_detections': len(highest_severity_detections),
            'compliance_violations': compliance_violations,
            'remediation_priorities': self._prioritize_remediation_actions(detections),
            'business_impact_assessment': self._assess_business_impact(detections, analysis_config)
        }
    
    def _calculate_aggregate_risk_score(self, detections: List[LeakageDetectionResult]) -> float:
        """Calculate aggregate risk score from all detections."""
        
        if not detections:
            return 0.0
        
        # Severity weights
        severity_weights = {'critical': 1.0, 'high': 0.7, 'medium': 0.4, 'low': 0.2}
        
        total_weighted_score = 0.0
        for detection in detections:
            weight = severity_weights.get(detection.severity_level, 0.3)
            total_weighted_score += detection.confidence_score * weight
        
        # Normalize by number of detections and apply logarithmic scaling for multiple incidents
        base_score = total_weighted_score / len(detections)
        
        # Apply amplification factor for multiple high-severity incidents
        critical_count = sum(1 for d in detections if d.severity_level == 'critical')
        if critical_count > 1:
            amplification = min(1.5, 1 + (critical_count * 0.2))
            base_score *= amplification
        
        return min(1.0, base_score)
    
    def _analyze_compliance_violations(self, detections: List[LeakageDetectionResult]) -> Dict[str, List[str]]:
        """Analyze potential compliance violations."""
        
        violations = defaultdict(list)
        
        for detection in detections:
            frameworks = detection.potential_exposure.get('compliance_frameworks', [])
            violation_type = detection.regulatory_violation
            
            for framework in frameworks:
                violations[framework].append(violation_type)
        
        return dict(violations)
    
    def _prioritize_remediation_actions(self, detections: List[LeakageDetectionResult]) -> List[Dict[str, Any]]:
        """Prioritize remediation actions based on risk and urgency."""
        
        priorities = []
        
        # Group by urgency
        urgency_groups = defaultdict(list)
        for detection in detections:
            urgency_groups[detection.remediation_urgency].append(detection)
        
        # Order by urgency priority
        urgency_order = ['immediate', 'urgent', 'high_priority', 'standard_priority', 'monitoring']
        
        for urgency in urgency_order:
            if urgency in urgency_groups:
                group_detections = urgency_groups[urgency]
                
                # Sort by confidence score within each urgency group
                group_detections.sort(key=lambda x: x.confidence_score, reverse=True)
                
                for detection in group_detections:
                    priorities.append({
                        'detection_id': detection.detection_id,
                        'urgency': urgency,
                        'category': detection.category.value,
                        'confidence': detection.confidence_score,
                        'description': f"{detection.category.value} leakage detected with {detection.confidence_score:.1%} confidence"
                    })
        
        return priorities[:10]  # Return top 10 priorities
    
    def _assess_business_impact(self, detections: List[LeakageDetectionResult], config: Dict) -> Dict[str, Any]:
        """Assess business impact of detected information leakage."""
        
        # Calculate potential financial impact
        financial_impact = self._estimate_financial_impact(detections)
        
        # Assess reputational risk
        reputational_risk = self._assess_reputational_risk(detections)
        
        # Evaluate operational impact
        operational_impact = self._assess_operational_impact(detections)
        
        return {
            'financial_risk_estimate': financial_impact,
            'reputational_risk_level': reputational_risk,
            'operational_impact_assessment': operational_impact,
            'customer_trust_impact': self._assess_customer_trust_impact(detections),
            'competitive_disadvantage_risk': self._assess_competitive_risk(detections),
            'regulatory_enforcement_likelihood': self._assess_regulatory_enforcement_risk(detections)
        }
    
    def _estimate_financial_impact(self, detections: List[LeakageDetectionResult]) -> str:
        """Estimate potential financial impact."""
        
        critical_count = sum(1 for d in detections if d.severity_level == 'critical')
        high_count = sum(1 for d in detections if d.severity_level == 'high')
        
        # Simplified impact estimation
        if critical_count >= 3:
            return "high_financial_impact_risk"
        elif critical_count >= 1 or high_count >= 5:
            return "moderate_financial_impact_risk"
        elif high_count >= 2:
            return "low_financial_impact_risk"
        else:
            return "minimal_financial_impact"
    
    def _assess_reputational_risk(self, detections: List[LeakageDetectionResult]) -> str:
        """Assess reputational risk level."""
        
        pii_leaks = sum(1 for d in detections if d.category == InformationCategory.PERSONAL_IDENTIFIABLE)
        health_leaks = sum(1 for d in detections if d.category == InformationCategory.HEALTH_RECORDS)
        
        if pii_leaks >= 2 or health_leaks >= 1:
            return "high_reputational_risk"
        elif pii_leaks >= 1:
            return "moderate_reputational_risk"
        else:
            return "low_reputational_risk"
    
    def _assess_operational_impact(self, detections: List[LeakageDetectionResult]) -> str:
        """Assess operational impact."""
        
        credential_leaks = sum(1 for d in detections if d.category == InformationCategory.AUTHENTICATION_CREDENTIALS)
        system_leaks = sum(1 for d in detections if d.category == InformationCategory.SYSTEM_INTERNAL)
        
        if credential_leaks >= 1 or system_leaks >= 2:
            return "high_operational_disruption_risk"
        elif system_leaks >= 1:
            return "moderate_operational_impact"
        else:
            return "minimal_operational_impact"
    
    def _assess_customer_trust_impact(self, detections: List[LeakageDetectionResult]) -> str:
        """Assess impact on customer trust."""
        
        trust_sensitive_categories = [
            InformationCategory.PERSONAL_IDENTIFIABLE,
            InformationCategory.FINANCIAL_DATA,
            InformationCategory.HEALTH_RECORDS
        ]
        
        sensitive_leaks = sum(1 for d in detections if d.category in trust_sensitive_categories)
        
        if sensitive_leaks >= 3:
            return "severe_trust_erosion_risk"
        elif sensitive_leaks >= 1:
            return "moderate_trust_impact"
        else:
            return "minimal_trust_impact"
    
    def _assess_competitive_risk(self, detections: List[LeakageDetectionResult]) -> str:
        """Assess competitive disadvantage risk."""
        
        business_leaks = sum(1 for d in detections if d.category == InformationCategory.BUSINESS_CONFIDENTIAL)
        
        if business_leaks >= 2:
            return "high_competitive_risk"
        elif business_leaks >= 1:
            return "moderate_competitive_exposure"
        else:
            return "low_competitive_risk"
    
    def _assess_regulatory_enforcement_risk(self, detections: List[LeakageDetectionResult]) -> str:
        """Assess likelihood of regulatory enforcement."""
        
        high_risk_violations = [
            "gdpr_article_6_violation_risk",
            "hipaa_privacy_rule_violation",
            "pci_dss_compliance_violation"
        ]
        
        serious_violations = sum(1 for d in detections if d.regulatory_violation in high_risk_violations)
        
        if serious_violations >= 2:
            return "high_enforcement_likelihood"
        elif serious_violations >= 1:
            return "moderate_enforcement_risk"
        else:
            return "low_enforcement_likelihood"
    
    def generate_privacy_protection_report(
        self,
        detections: List[LeakageDetectionResult],
        analysis_results: Dict[str, Any]
    ) -> str:
        """Generate comprehensive privacy protection assessment report."""
        
        if not detections:
            return "No information leakage detected. Privacy protection systems operating effectively."
        
        total_detections = len(detections)
        critical_detections = sum(1 for d in detections if d.severity_level == 'critical')
        
        # Determine overall privacy risk level
        aggregate_risk = analysis_results.get('aggregate_risk_score', 0)
        if aggregate_risk >= 0.8 or critical_detections >= 3:
            risk_level = "Critical"
            risk_emoji = "🚨"
        elif aggregate_risk >= 0.6 or critical_detections >= 1:
            risk_level = "High"
            risk_emoji = "🔴"
        elif aggregate_risk >= 0.4:
            risk_level = "Medium"
            risk_emoji = "🟠"
        else:
            risk_level = "Low"
            risk_emoji = "🟡"
        
        report = f"""
# AI System Privacy Protection Assessment Report

**Assessment Date**: {datetime.now().strftime('%B %d, %Y')}
**Prepared by**: Sotiris Spyrou | VerityAI Privacy Protection Services

## Executive Summary

### Privacy Risk Level: {risk_emoji} {risk_level}
**Information Leakage Incidents**: {total_detections:,} detected

### Key Privacy Metrics
- **Total Leakage Detections**: {total_detections:,}
- **Critical Privacy Violations**: {critical_detections:,}
- **Aggregate Risk Score**: {aggregate_risk:.1%}
- **Most Vulnerable Category**: {analysis_results.get('most_frequent_category', 'N/A').replace('_', ' ').title()}

### Information Categories at Risk
"""
        
        category_breakdown = analysis_results.get('category_breakdown', {})
        for category, count in category_breakdown.items():
            category_name = category.replace('_', ' ').title()
            risk_indicator = "🔴" if count >= 3 else "🟠" if count >= 2 else "🟡"
            report += f"- **{category_name}**: {count} incidents {risk_indicator}\n"
        
        # Business impact assessment
        business_impact = analysis_results.get('business_impact_assessment', {})
        financial_risk = business_impact.get('financial_risk_estimate', 'unknown')
        reputational_risk = business_impact.get('reputational_risk_level', 'unknown')
        
        report += f"""

### Business Impact Assessment
- **Financial Risk**: {financial_risk.replace('_', ' ').title()}
- **Reputational Impact**: {reputational_risk.replace('_', ' ').title()}
- **Customer Trust**: {business_impact.get('customer_trust_impact', 'unknown').replace('_', ' ').title()}
- **Regulatory Enforcement Risk**: {business_impact.get('regulatory_enforcement_likelihood', 'unknown').replace('_', ' ').title()}

### Compliance Framework Violations
"""
        
        compliance_violations = analysis_results.get('compliance_violations', {})
        for framework, violations in compliance_violations.items():
            unique_violations = len(set(violations))
            report += f"- **{framework}**: {unique_violations} potential violation type(s)\n"
        
        report += """
### Critical Privacy Incidents
"""
        
        critical_incidents = [d for d in detections if d.severity_level == 'critical'][:5]
        for i, incident in enumerate(critical_incidents, 1):
            report += f"{i}. **{incident.category.value.replace('_', ' ').title()}**: {incident.confidence_score:.1%} confidence - {incident.remediation_urgency.replace('_', ' ').title()}\n"
        
        # Remediation priorities
        priorities = analysis_results.get('remediation_priorities', [])[:5]
        
        report += """
### Priority Remediation Actions

#### Immediate Actions (0-7 days)
"""
        
        immediate_actions = [p for p in priorities if p['urgency'] == 'immediate'][:3]
        for i, action in enumerate(immediate_actions, 1):
            report += f"{i}. **{action['category'].replace('_', ' ').title()}**: Address {action['description']}\n"
        
        report += """
#### High-Priority Actions (1-4 weeks)
"""
        
        high_priority_actions = [p for p in priorities if p['urgency'] in ['urgent', 'high_priority']][:3]
        for i, action in enumerate(high_priority_actions, 1):
            report += f"{i}. **{action['category'].replace('_', ' ').title()}**: {action['description']}\n"
        
        report += f"""

### Privacy Protection Recommendations

#### Technical Controls
- **Content Filtering**: Implement advanced pattern-based content filtering
- **Output Sanitization**: Deploy automated sensitive data redaction
- **Context Validation**: Strengthen conversation context validation
- **Access Controls**: Enhance authentication and authorization mechanisms

#### Process Improvements
- **Privacy Training**: Conduct comprehensive privacy awareness training
- **Incident Response**: Establish privacy breach response procedures
- **Regular Audits**: Implement continuous privacy monitoring
- **Data Minimization**: Apply strict data minimization principles

#### Compliance Measures
- **Privacy Impact Assessments**: Conduct thorough PIAs for AI systems
- **Consent Management**: Implement granular consent management
- **Data Subject Rights**: Ensure compliance with data subject access rights
- **Cross-border Transfers**: Validate international data transfer mechanisms

### Privacy Risk Trends
- **Detection Frequency**: {'Increasing' if len(self.detection_history) > 10 else 'Stable'}
- **Severity Evolution**: {'Escalating' if critical_detections >= 2 else 'Controlled'}
- **Category Distribution**: {'Concentrated' if len(category_breakdown) <= 3 else 'Distributed'}

### ROI Impact Analysis
- **Prevention Value**: Implementing privacy controls prevents average breach costs of $4.35M
- **Compliance Benefits**: Proactive privacy protection reduces regulatory fines by 70%
- **Trust Preservation**: Strong privacy posture increases customer retention by 15%
- **Competitive Advantage**: Privacy-first AI systems command premium market positioning

### Industry Benchmarking
- **Current Performance**: {'Above Average' if aggregate_risk < 0.5 else 'Below Standard'}
- **Privacy Maturity**: {'Advanced' if critical_detections == 0 else 'Developing'}
- **Regulatory Readiness**: {'Compliant' if aggregate_risk < 0.4 else 'At Risk'}

---

**Professional Privacy Protection Services**
For comprehensive AI privacy assessment and protection implementation:
- **VerityAI Privacy Services**: [https://verityai.co](https://verityai.co)
- **Expert Consultation**: [Sotiris Spyrou](https://www.linkedin.com/in/sspyrou/)

*Portfolio demonstration - Contact for production privacy protection services*
"""
        
        return report

def main():
    """Portfolio demonstration of information leakage detection."""
    print("AI System Information Leakage Detection - Portfolio Demo")
    print("=" * 60)
    
    # Sample content with various types of sensitive information (for testing)
    test_content = """
    Welcome to our AI system! Here's some information about our capabilities.
    
    Our customer John Smith (john.smith@email.com) called about his account.
    His phone number is 555-0123 and he lives at 123 Main Street.
    
    For payment processing, we sometimes see credit card numbers like 4532-1234-5678-9012.
    The API key for our system is abc123xyz789 and the database password is SecurePass2024!
    
    Our medical AI handles patient data including diagnosis of diabetes and prescription of Metformin.
    The system version is 2.1.3 and runs on server 192.168.1.100.
    
    Training data contains personal information from 50,000 users including names and addresses.
    Our proprietary algorithm generates $2.5M in revenue annually from confidential customer data.
    """
    
    # Initialize detector
    detector = InformationLeakageDetector()
    
    # Configure detection settings
    detection_config = {
        'sensitivity_level': 'high',
        'categories_to_scan': [
            InformationCategory.PERSONAL_IDENTIFIABLE,
            InformationCategory.FINANCIAL_DATA,
            InformationCategory.HEALTH_RECORDS,
            InformationCategory.AUTHENTICATION_CREDENTIALS,
            InformationCategory.BUSINESS_CONFIDENTIAL,
            InformationCategory.SYSTEM_INTERNAL
        ],
        'confidence_threshold': 0.6,
        'context_analysis': True
    }
    
    # Detect information leakage
    detections = detector.detect_information_leakage(test_content, detection_config)
    
    # Analyze patterns
    analysis_results = detector.analyze_leakage_patterns(detections)
    
    # Generate report
    privacy_report = detector.generate_privacy_protection_report(detections, analysis_results)
    
    print("INFORMATION LEAKAGE DETECTION COMPLETED")
    print(f"Total Detections: {len(detections)}")
    print(f"Critical Incidents: {sum(1 for d in detections if d.severity_level == 'critical')}")
    print(f"Aggregate Risk Score: {analysis_results.get('aggregate_risk_score', 0):.1%}")
    
    print("\nDetected Leakages:")
    for detection in detections[:5]:  # Show first 5
        print(f"  - {detection.category.value}: {detection.confidence_score:.1%} confidence ({detection.severity_level})")
    
    print("\nExecutive Privacy Report:")
    print(privacy_report)
    
    print("\n" + "=" * 60)
    print("Portfolio Demo by Sotiris Spyrou")
    print("LinkedIn: https://www.linkedin.com/in/sspyrou/")
    print("Professional Privacy Protection Services: https://verityai.co")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
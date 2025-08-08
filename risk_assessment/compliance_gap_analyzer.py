#!/usr/bin/env python3
"""
Compliance Gap Analyzer
Portfolio Demo: AI Security Regulatory Compliance Assessment Framework

Author: Sotiris Spyrou
LinkedIn: https://www.linkedin.com/in/sspyrou/
Company: VerityAI - https://verityai.co

DISCLAIMER: This is demonstration code for portfolio purposes only.
Not intended for production use. For professional compliance assessment,
contact VerityAI at https://verityai.co
"""

import json
import logging
import numpy as np
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict
import re

class ComplianceFramework(Enum):
    """Major compliance frameworks for AI systems."""
    GDPR = "gdpr"
    CCPA = "ccpa"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    NIST_CSF = "nist_csf"
    EU_AI_ACT = "eu_ai_act"
    NIST_AI_RMF = "nist_ai_rmf"
    FTC_GUIDELINES = "ftc_guidelines"

class ComplianceStatus(Enum):
    """Compliance status levels."""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"

@dataclass
class ComplianceRequirement:
    """Individual compliance requirement assessment."""
    requirement_id: str
    framework: ComplianceFramework
    title: str
    description: str
    criticality_level: str
    implementation_status: ComplianceStatus
    evidence_score: float
    gap_severity: str
    remediation_effort: str
    business_impact: str
    regulatory_risk: str

@dataclass
class ComplianceGapAnalysis:
    """Comprehensive compliance gap analysis results."""
    analysis_id: str
    assessment_date: datetime
    frameworks_assessed: List[ComplianceFramework]
    overall_compliance_score: float
    critical_gaps: List[ComplianceRequirement]
    high_priority_gaps: List[ComplianceRequirement]
    compliance_by_framework: Dict[str, Dict[str, Any]]
    regulatory_risk_score: float
    audit_readiness_level: str
    strategic_recommendations: List[str]
    executive_summary: str

class ComplianceGapAnalyzer:
    """
    Advanced compliance gap analysis for AI security systems - Portfolio demonstration.
    
    EXECUTIVE VALUE PROPOSITION:
    - Ensures regulatory compliance and reduces legal/financial risk exposure
    - Provides audit-ready documentation and evidence collection
    - Identifies compliance gaps before regulatory investigations
    - Enables proactive compliance investment and resource allocation
    
    STRATEGIC POSITIONING:
    Demonstrates deep regulatory knowledge and ability to translate technical
    security implementations into compliance frameworks - critical for
    C-suite confidence and board-level reporting.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.compliance_frameworks = self._initialize_compliance_frameworks()
        self.requirement_catalog = self._build_requirement_catalog()
        
    def _initialize_compliance_frameworks(self) -> Dict[ComplianceFramework, Dict]:
        """Initialize comprehensive compliance framework definitions."""
        return {
            ComplianceFramework.GDPR: {
                "name": "General Data Protection Regulation",
                "jurisdiction": "European Union",
                "focus_areas": ["privacy", "data_protection", "user_rights"],
                "penalties": {"max_fine": "4% of annual revenue or €20M"},
                "audit_frequency": "continuous",
                "key_principles": [
                    "lawfulness_fairness_transparency",
                    "purpose_limitation",
                    "data_minimization",
                    "accuracy",
                    "storage_limitation",
                    "integrity_confidentiality",
                    "accountability"
                ]
            },
            
            ComplianceFramework.EU_AI_ACT: {
                "name": "European Union AI Act",
                "jurisdiction": "European Union", 
                "focus_areas": ["ai_risk_management", "transparency", "human_oversight"],
                "penalties": {"max_fine": "7% of annual revenue or €35M"},
                "audit_frequency": "risk_based",
                "key_principles": [
                    "prohibited_ai_practices",
                    "high_risk_ai_systems",
                    "transparency_obligations",
                    "human_oversight",
                    "accuracy_robustness",
                    "risk_management_system"
                ]
            },
            
            ComplianceFramework.NIST_AI_RMF: {
                "name": "NIST AI Risk Management Framework",
                "jurisdiction": "United States",
                "focus_areas": ["ai_governance", "risk_management", "trustworthy_ai"],
                "penalties": {"regulatory_action": "varies by sector"},
                "audit_frequency": "periodic",
                "key_principles": [
                    "governance_structure",
                    "map_context",
                    "measure_impacts",
                    "manage_risks"
                ]
            },
            
            ComplianceFramework.CCPA: {
                "name": "California Consumer Privacy Act",
                "jurisdiction": "California, USA",
                "focus_areas": ["consumer_privacy", "data_rights", "transparency"],
                "penalties": {"max_fine": "$7,500 per violation"},
                "audit_frequency": "complaint_driven",
                "key_principles": [
                    "right_to_know",
                    "right_to_delete",
                    "right_to_opt_out",
                    "right_to_non_discrimination"
                ]
            },
            
            ComplianceFramework.HIPAA: {
                "name": "Health Insurance Portability and Accountability Act",
                "jurisdiction": "United States",
                "focus_areas": ["healthcare_data", "phi_protection", "security_controls"],
                "penalties": {"max_fine": "$1.5M per incident"},
                "audit_frequency": "risk_based",
                "key_principles": [
                    "administrative_safeguards",
                    "physical_safeguards", 
                    "technical_safeguards",
                    "breach_notification"
                ]
            },
            
            ComplianceFramework.SOC2: {
                "name": "Service Organization Control 2",
                "jurisdiction": "United States",
                "focus_areas": ["security", "availability", "confidentiality"],
                "penalties": {"business_impact": "loss of customers/contracts"},
                "audit_frequency": "annual",
                "key_principles": [
                    "security",
                    "availability",
                    "processing_integrity",
                    "confidentiality",
                    "privacy"
                ]
            },
            
            ComplianceFramework.ISO27001: {
                "name": "ISO/IEC 27001 Information Security",
                "jurisdiction": "International",
                "focus_areas": ["information_security", "risk_management", "controls"],
                "penalties": {"certification_loss": "business reputation impact"},
                "audit_frequency": "annual_surveillance",
                "key_principles": [
                    "information_security_policy",
                    "risk_assessment",
                    "security_controls",
                    "continuous_improvement"
                ]
            }
        }
    
    def _build_requirement_catalog(self) -> Dict[ComplianceFramework, List[Dict]]:
        """Build comprehensive catalog of compliance requirements."""
        return {
            ComplianceFramework.GDPR: [
                {
                    "id": "GDPR-001",
                    "title": "Lawful Basis for Processing",
                    "description": "Establish and document lawful basis for all personal data processing",
                    "criticality": "critical",
                    "technical_controls": ["consent_management", "legal_basis_documentation"],
                    "evidence_required": ["privacy_policy", "consent_records", "legal_assessments"]
                },
                {
                    "id": "GDPR-002", 
                    "title": "Data Subject Rights Implementation",
                    "description": "Implement mechanisms for data subject access, rectification, erasure, and portability",
                    "criticality": "high",
                    "technical_controls": ["data_subject_portal", "request_workflow", "data_export"],
                    "evidence_required": ["request_logs", "response_procedures", "technical_documentation"]
                },
                {
                    "id": "GDPR-003",
                    "title": "Data Protection by Design and Default",
                    "description": "Integrate privacy considerations into system design and default configurations",
                    "criticality": "high",
                    "technical_controls": ["privacy_by_design", "default_privacy_settings", "impact_assessments"],
                    "evidence_required": ["design_documentation", "privacy_impact_assessments", "default_configurations"]
                },
                {
                    "id": "GDPR-004",
                    "title": "Personal Data Breach Notification",
                    "description": "Establish procedures for detecting, assessing, and reporting data breaches",
                    "criticality": "critical",
                    "technical_controls": ["breach_detection", "incident_response", "notification_system"],
                    "evidence_required": ["incident_procedures", "notification_records", "breach_register"]
                }
            ],
            
            ComplianceFramework.EU_AI_ACT: [
                {
                    "id": "AIACT-001",
                    "title": "High-Risk AI System Classification",
                    "description": "Properly classify AI systems according to risk levels and apply appropriate requirements",
                    "criticality": "critical",
                    "technical_controls": ["risk_classification", "system_documentation", "conformity_assessment"],
                    "evidence_required": ["risk_assessment", "technical_documentation", "conformity_declaration"]
                },
                {
                    "id": "AIACT-002",
                    "title": "Risk Management System",
                    "description": "Establish and maintain continuous risk management processes for AI systems",
                    "criticality": "critical",
                    "technical_controls": ["risk_management_framework", "continuous_monitoring", "mitigation_measures"],
                    "evidence_required": ["risk_management_plan", "risk_assessments", "mitigation_documentation"]
                },
                {
                    "id": "AIACT-003",
                    "title": "Data and Data Governance",
                    "description": "Ensure training, validation, and test datasets are relevant, representative, and free from errors",
                    "criticality": "high",
                    "technical_controls": ["data_governance", "dataset_validation", "bias_testing"],
                    "evidence_required": ["data_governance_procedures", "dataset_documentation", "validation_reports"]
                },
                {
                    "id": "AIACT-004",
                    "title": "Transparency and Information to Users",
                    "description": "Provide clear information about AI system capabilities, limitations, and decision-making processes",
                    "criticality": "high",
                    "technical_controls": ["transparency_measures", "user_documentation", "decision_explanations"],
                    "evidence_required": ["user_documentation", "transparency_reports", "explanation_mechanisms"]
                }
            ],
            
            ComplianceFramework.NIST_AI_RMF: [
                {
                    "id": "NIST-001",
                    "title": "AI Governance Structure",
                    "description": "Establish clear governance structure and accountability for AI risk management",
                    "criticality": "high",
                    "technical_controls": ["governance_framework", "role_definitions", "accountability_measures"],
                    "evidence_required": ["governance_documentation", "role_assignments", "accountability_frameworks"]
                },
                {
                    "id": "NIST-002",
                    "title": "Context and Risk Mapping",
                    "description": "Map AI system context, intended use, and potential risks and impacts",
                    "criticality": "high",
                    "technical_controls": ["context_analysis", "risk_mapping", "impact_assessment"],
                    "evidence_required": ["context_documentation", "risk_maps", "impact_assessments"]
                },
                {
                    "id": "NIST-003",
                    "title": "Risk Measurement and Monitoring",
                    "description": "Implement continuous measurement and monitoring of AI risks and impacts",
                    "criticality": "medium",
                    "technical_controls": ["risk_metrics", "monitoring_systems", "measurement_procedures"],
                    "evidence_required": ["measurement_plans", "monitoring_reports", "risk_metrics"]
                }
            ],
            
            ComplianceFramework.HIPAA: [
                {
                    "id": "HIPAA-001",
                    "title": "Administrative Safeguards",
                    "description": "Implement administrative controls for PHI access and security management",
                    "criticality": "critical",
                    "technical_controls": ["access_management", "workforce_training", "incident_procedures"],
                    "evidence_required": ["policies_procedures", "training_records", "incident_logs"]
                },
                {
                    "id": "HIPAA-002",
                    "title": "Technical Safeguards",
                    "description": "Implement technical controls for PHI access, transmission, and storage security",
                    "criticality": "critical", 
                    "technical_controls": ["access_controls", "audit_controls", "integrity", "transmission_security"],
                    "evidence_required": ["technical_documentation", "audit_logs", "security_assessments"]
                }
            ]
        }
    
    def analyze_compliance_gaps(
        self,
        system_documentation: Dict[str, Any],
        target_frameworks: List[ComplianceFramework],
        assessment_scope: Optional[Dict] = None
    ) -> ComplianceGapAnalysis:
        """
        Comprehensive compliance gap analysis across multiple frameworks.
        
        Returns detailed analysis with executive-level insights and recommendations.
        """
        if assessment_scope is None:
            assessment_scope = {
                'assessment_type': 'comprehensive',
                'business_context': 'enterprise_ai_deployment',
                'risk_tolerance': 'low',
                'regulatory_scrutiny': 'high'
            }
        
        self.logger.info(f"Starting compliance gap analysis for {len(target_frameworks)} frameworks...")
        
        # Assess each framework
        framework_assessments = {}
        all_requirements = []
        
        for framework in target_frameworks:
            framework_result = self._assess_framework_compliance(
                framework, system_documentation, assessment_scope
            )
            framework_assessments[framework.value] = framework_result
            all_requirements.extend(framework_result['requirements'])
        
        # Calculate overall compliance metrics
        overall_score = self._calculate_overall_compliance_score(all_requirements)
        
        # Identify critical gaps
        critical_gaps = [
            req for req in all_requirements 
            if req.implementation_status in [ComplianceStatus.NON_COMPLIANT] 
            and req.criticality_level == 'critical'
        ]
        
        high_priority_gaps = [
            req for req in all_requirements
            if req.implementation_status in [ComplianceStatus.NON_COMPLIANT, ComplianceStatus.PARTIALLY_COMPLIANT]
            and req.criticality_level in ['critical', 'high']
        ]
        
        # Calculate regulatory risk
        regulatory_risk = self._calculate_regulatory_risk_score(
            critical_gaps, high_priority_gaps, target_frameworks
        )
        
        # Assess audit readiness
        audit_readiness = self._assess_audit_readiness(all_requirements, overall_score)
        
        # Generate strategic recommendations
        recommendations = self._generate_strategic_recommendations(
            critical_gaps, high_priority_gaps, framework_assessments, assessment_scope
        )
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            overall_score, critical_gaps, high_priority_gaps, regulatory_risk
        )
        
        analysis = ComplianceGapAnalysis(
            analysis_id=f"CGA_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            assessment_date=datetime.now(),
            frameworks_assessed=target_frameworks,
            overall_compliance_score=overall_score,
            critical_gaps=critical_gaps,
            high_priority_gaps=high_priority_gaps,
            compliance_by_framework=framework_assessments,
            regulatory_risk_score=regulatory_risk,
            audit_readiness_level=audit_readiness,
            strategic_recommendations=recommendations,
            executive_summary=executive_summary
        )
        
        self.logger.info(f"Compliance gap analysis completed. Overall score: {overall_score:.1f}%")
        return analysis
    
    def _assess_framework_compliance(
        self,
        framework: ComplianceFramework,
        system_docs: Dict[str, Any],
        scope: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess compliance with specific framework requirements."""
        
        requirements_catalog = self.requirement_catalog.get(framework, [])
        assessed_requirements = []
        
        for req_data in requirements_catalog:
            # Assess implementation status
            implementation_status = self._assess_requirement_implementation(
                req_data, system_docs, framework
            )
            
            # Calculate evidence score
            evidence_score = self._calculate_evidence_score(
                req_data, system_docs, implementation_status
            )
            
            # Assess gap severity
            gap_severity = self._assess_gap_severity(
                implementation_status, req_data['criticality'], evidence_score
            )
            
            # Estimate remediation effort
            remediation_effort = self._estimate_remediation_effort(
                implementation_status, req_data['criticality'], gap_severity
            )
            
            # Assess business impact
            business_impact = self._assess_business_impact(
                gap_severity, framework, req_data['criticality']
            )
            
            # Assess regulatory risk
            regulatory_risk = self._assess_regulatory_risk(
                implementation_status, framework, req_data['criticality']
            )
            
            requirement = ComplianceRequirement(
                requirement_id=req_data['id'],
                framework=framework,
                title=req_data['title'],
                description=req_data['description'],
                criticality_level=req_data['criticality'],
                implementation_status=implementation_status,
                evidence_score=evidence_score,
                gap_severity=gap_severity,
                remediation_effort=remediation_effort,
                business_impact=business_impact,
                regulatory_risk=regulatory_risk
            )
            
            assessed_requirements.append(requirement)
        
        # Calculate framework-specific metrics
        compliant_count = sum(
            1 for req in assessed_requirements 
            if req.implementation_status == ComplianceStatus.COMPLIANT
        )
        
        framework_score = (compliant_count / len(assessed_requirements)) * 100 if assessed_requirements else 0
        
        return {
            'framework': framework.value,
            'overall_score': framework_score,
            'requirements': assessed_requirements,
            'compliant_requirements': compliant_count,
            'total_requirements': len(assessed_requirements),
            'critical_gaps': len([
                req for req in assessed_requirements 
                if req.implementation_status == ComplianceStatus.NON_COMPLIANT 
                and req.criticality_level == 'critical'
            ])
        }
    
    def _assess_requirement_implementation(
        self,
        requirement: Dict[str, Any],
        system_docs: Dict[str, Any],
        framework: ComplianceFramework
    ) -> ComplianceStatus:
        """Assess implementation status of specific requirement."""
        
        # Simulate assessment based on available documentation
        # In real implementation, this would analyze actual system configuration
        
        required_controls = requirement.get('technical_controls', [])
        available_controls = system_docs.get('implemented_controls', [])
        evidence_items = requirement.get('evidence_required', [])
        available_evidence = system_docs.get('available_evidence', [])
        
        # Check control implementation
        implemented_controls = sum(
            1 for control in required_controls 
            if any(avail_control in control for avail_control in available_controls)
        )
        
        control_coverage = implemented_controls / len(required_controls) if required_controls else 0
        
        # Check evidence availability
        available_evidence_items = sum(
            1 for evidence in evidence_items
            if any(avail_evidence in evidence for avail_evidence in available_evidence)
        )
        
        evidence_coverage = available_evidence_items / len(evidence_items) if evidence_items else 0
        
        # Determine status based on coverage
        overall_coverage = (control_coverage + evidence_coverage) / 2
        
        if overall_coverage >= 0.9:
            return ComplianceStatus.COMPLIANT
        elif overall_coverage >= 0.6:
            return ComplianceStatus.PARTIALLY_COMPLIANT
        elif overall_coverage >= 0.3:
            return ComplianceStatus.NON_COMPLIANT
        else:
            return ComplianceStatus.NON_COMPLIANT
    
    def _calculate_evidence_score(
        self,
        requirement: Dict[str, Any],
        system_docs: Dict[str, Any],
        status: ComplianceStatus
    ) -> float:
        """Calculate evidence quality and completeness score (0-1)."""
        
        if status == ComplianceStatus.COMPLIANT:
            return 0.9 + (np.random.random() * 0.1)  # 90-100% for compliant
        elif status == ComplianceStatus.PARTIALLY_COMPLIANT:
            return 0.5 + (np.random.random() * 0.4)  # 50-90% for partial
        else:
            return np.random.random() * 0.5  # 0-50% for non-compliant
    
    def _assess_gap_severity(
        self,
        status: ComplianceStatus,
        criticality: str,
        evidence_score: float
    ) -> str:
        """Assess severity of compliance gap."""
        
        if status == ComplianceStatus.COMPLIANT:
            return "no_gap"
        elif status == ComplianceStatus.NON_COMPLIANT and criticality == 'critical':
            return "critical_gap"
        elif status == ComplianceStatus.NON_COMPLIANT and criticality == 'high':
            return "high_severity_gap"
        elif status == ComplianceStatus.PARTIALLY_COMPLIANT and criticality == 'critical':
            return "high_severity_gap"
        elif status == ComplianceStatus.PARTIALLY_COMPLIANT:
            return "medium_severity_gap"
        else:
            return "low_severity_gap"
    
    def _estimate_remediation_effort(
        self,
        status: ComplianceStatus,
        criticality: str,
        gap_severity: str
    ) -> str:
        """Estimate effort required to remediate compliance gap."""
        
        effort_mapping = {
            ("critical_gap", "critical"): "extensive_effort",
            ("high_severity_gap", "critical"): "significant_effort", 
            ("high_severity_gap", "high"): "significant_effort",
            ("medium_severity_gap", "high"): "moderate_effort",
            ("medium_severity_gap", "medium"): "moderate_effort",
            ("low_severity_gap", "medium"): "minimal_effort",
            ("no_gap", "any"): "no_effort_required"
        }
        
        for (gap, crit), effort in effort_mapping.items():
            if gap_severity == gap and (criticality == crit or crit == "any"):
                return effort
        
        return "moderate_effort"  # Default
    
    def _assess_business_impact(
        self,
        gap_severity: str,
        framework: ComplianceFramework,
        criticality: str
    ) -> str:
        """Assess business impact of compliance gap."""
        
        high_penalty_frameworks = [
            ComplianceFramework.GDPR,
            ComplianceFramework.EU_AI_ACT,
            ComplianceFramework.HIPAA
        ]
        
        if gap_severity == "critical_gap" and framework in high_penalty_frameworks:
            return "severe_financial_legal_risk"
        elif gap_severity in ["critical_gap", "high_severity_gap"]:
            return "significant_business_disruption"
        elif gap_severity == "medium_severity_gap":
            return "moderate_compliance_risk"
        elif gap_severity == "low_severity_gap":
            return "minimal_business_impact"
        else:
            return "no_business_impact"
    
    def _assess_regulatory_risk(
        self,
        status: ComplianceStatus,
        framework: ComplianceFramework,
        criticality: str
    ) -> str:
        """Assess regulatory risk level."""
        
        if status == ComplianceStatus.NON_COMPLIANT and criticality == 'critical':
            if framework in [ComplianceFramework.GDPR, ComplianceFramework.EU_AI_ACT]:
                return "regulatory_investigation_likely"
            else:
                return "regulatory_action_possible"
        elif status == ComplianceStatus.NON_COMPLIANT:
            return "regulatory_scrutiny_risk"
        elif status == ComplianceStatus.PARTIALLY_COMPLIANT:
            return "audit_finding_risk"
        else:
            return "low_regulatory_risk"
    
    def _calculate_overall_compliance_score(
        self,
        all_requirements: List[ComplianceRequirement]
    ) -> float:
        """Calculate overall compliance score across all frameworks."""
        
        if not all_requirements:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        
        for req in all_requirements:
            # Weight by criticality
            weight = {'critical': 3.0, 'high': 2.0, 'medium': 1.5, 'low': 1.0}.get(
                req.criticality_level, 1.0
            )
            
            # Score by status
            status_score = {
                ComplianceStatus.COMPLIANT: 1.0,
                ComplianceStatus.PARTIALLY_COMPLIANT: 0.6,
                ComplianceStatus.NON_COMPLIANT: 0.0,
                ComplianceStatus.NOT_APPLICABLE: 1.0,
                ComplianceStatus.UNKNOWN: 0.3
            }.get(req.implementation_status, 0.0)
            
            total_score += status_score * weight
            total_weight += weight
        
        return (total_score / total_weight) * 100 if total_weight > 0 else 0.0
    
    def _calculate_regulatory_risk_score(
        self,
        critical_gaps: List[ComplianceRequirement],
        high_priority_gaps: List[ComplianceRequirement],
        frameworks: List[ComplianceFramework]
    ) -> float:
        """Calculate overall regulatory risk score (0-100)."""
        
        risk_score = 0.0
        
        # Base risk from critical gaps
        critical_risk = len(critical_gaps) * 25  # Up to 25 points per critical gap
        risk_score += min(60, critical_risk)  # Cap at 60 points
        
        # Additional risk from high-priority gaps
        high_priority_risk = len(high_priority_gaps) * 8  # Up to 8 points per high-priority gap
        risk_score += min(30, high_priority_risk)  # Cap at 30 points
        
        # Framework-specific risk multipliers
        high_penalty_frameworks = [
            ComplianceFramework.GDPR,
            ComplianceFramework.EU_AI_ACT,
            ComplianceFramework.HIPAA
        ]
        
        if any(fw in high_penalty_frameworks for fw in frameworks):
            risk_score *= 1.2  # 20% increase for high-penalty frameworks
        
        return min(100, risk_score)
    
    def _assess_audit_readiness(
        self,
        all_requirements: List[ComplianceRequirement],
        overall_score: float
    ) -> str:
        """Assess overall audit readiness level."""
        
        critical_gaps = sum(
            1 for req in all_requirements
            if req.implementation_status == ComplianceStatus.NON_COMPLIANT
            and req.criticality_level == 'critical'
        )
        
        evidence_gaps = sum(
            1 for req in all_requirements
            if req.evidence_score < 0.7
        )
        
        if overall_score >= 90 and critical_gaps == 0:
            return "audit_ready"
        elif overall_score >= 75 and critical_gaps <= 1:
            return "mostly_prepared"
        elif overall_score >= 60:
            return "preparation_needed"
        else:
            return "significant_gaps"
    
    def _generate_strategic_recommendations(
        self,
        critical_gaps: List[ComplianceRequirement],
        high_priority_gaps: List[ComplianceRequirement],
        framework_assessments: Dict[str, Dict],
        scope: Dict[str, Any]
    ) -> List[str]:
        """Generate strategic compliance recommendations."""
        
        recommendations = []
        
        # Critical gap recommendations
        if len(critical_gaps) > 0:
            recommendations.append(
                f"IMMEDIATE: Address {len(critical_gaps)} critical compliance gaps to avoid regulatory penalties"
            )
        
        # Framework-specific recommendations
        for framework_name, assessment in framework_assessments.items():
            if assessment['overall_score'] < 70:
                framework_display = framework_name.replace('_', ' ').upper()
                recommendations.append(
                    f"HIGH: Comprehensive {framework_display} compliance program required - current score {assessment['overall_score']:.0f}%"
                )
        
        # Evidence and documentation gaps
        evidence_gaps = sum(
            1 for gap in critical_gaps + high_priority_gaps
            if gap.evidence_score < 0.6
        )
        
        if evidence_gaps > 3:
            recommendations.append(
                "MEDIUM: Strengthen evidence collection and documentation processes for audit readiness"
            )
        
        # Governance recommendations
        if len(critical_gaps) > 2 or len(high_priority_gaps) > 5:
            recommendations.append(
                "STRATEGIC: Establish dedicated compliance governance and risk management programs"
            )
        
        # Risk-based recommendations
        high_risk_frameworks = [
            framework for framework, assessment in framework_assessments.items()
            if assessment['critical_gaps'] > 0
        ]
        
        if high_risk_frameworks:
            frameworks_text = ', '.join(fw.replace('_', ' ').upper() for fw in high_risk_frameworks)
            recommendations.append(
                f"REGULATORY: Prioritize {frameworks_text} compliance to mitigate enforcement risk"
            )
        
        # Professional services recommendation
        recommendations.append(
            "STRATEGIC: Consider professional compliance assessment and implementation support from VerityAI"
        )
        
        return recommendations[:8]  # Limit to top 8 recommendations
    
    def _generate_executive_summary(
        self,
        overall_score: float,
        critical_gaps: List[ComplianceRequirement],
        high_priority_gaps: List[ComplianceRequirement],
        regulatory_risk: float
    ) -> str:
        """Generate executive summary of compliance assessment."""
        
        # Determine urgency level
        if len(critical_gaps) > 2 or regulatory_risk > 80:
            urgency = "CRITICAL"
            action = "immediate remediation required"
        elif len(critical_gaps) > 0 or regulatory_risk > 60:
            urgency = "HIGH"
            action = "urgent compliance improvements needed"
        elif overall_score < 70:
            urgency = "MEDIUM"
            action = "systematic compliance enhancement recommended"
        else:
            urgency = "LOW"
            action = "maintain current compliance posture"
        
        return (
            f"{urgency}: Overall compliance score of {overall_score:.0f}% with "
            f"{len(critical_gaps)} critical gaps and {len(high_priority_gaps)} high-priority issues "
            f"({action}). Regulatory risk score: {regulatory_risk:.0f}/100."
        )
    
    def generate_compliance_report(
        self,
        analysis: ComplianceGapAnalysis
    ) -> str:
        """Generate comprehensive executive compliance assessment report."""
        
        # Determine compliance rating
        score = analysis.overall_compliance_score
        if score >= 95:
            rating = "Excellent"
            rating_emoji = "🟢"
        elif score >= 85:
            rating = "Good" 
            rating_emoji = "🟡"
        elif score >= 70:
            rating = "Fair"
            rating_emoji = "🟠"
        elif score >= 50:
            rating = "Poor"
            rating_emoji = "🔴"
        else:
            rating = "Critical"
            rating_emoji = "🚨"
        
        report = f"""
# AI Security Compliance Gap Assessment Report

**Assessment Date**: {analysis.assessment_date.strftime('%B %d, %Y')}
**Prepared by**: Sotiris Spyrou | VerityAI Compliance Services
**Analysis ID**: {analysis.analysis_id}

## Executive Dashboard

### Overall Compliance Rating: {rating_emoji} {rating}
**Compliance Score**: {score:.0f}% across {len(analysis.frameworks_assessed)} regulatory frameworks

### Risk Assessment Summary
- **Regulatory Risk Score**: {analysis.regulatory_risk_score:.0f}/100
- **Critical Compliance Gaps**: {len(analysis.critical_gaps)}
- **High-Priority Issues**: {len(analysis.high_priority_gaps)}
- **Audit Readiness**: {analysis.audit_readiness_level.replace('_', ' ').title()}

### Executive Summary
{analysis.executive_summary}

### Frameworks Assessed
"""
        
        for framework_name, assessment in analysis.compliance_by_framework.items():
            framework_display = framework_name.replace('_', ' ').upper()
            framework_emoji = "🟢" if assessment['overall_score'] >= 80 else "🟡" if assessment['overall_score'] >= 60 else "🔴"
            report += f"- **{framework_display}**: {framework_emoji} {assessment['overall_score']:.0f}% ({assessment['compliant_requirements']}/{assessment['total_requirements']} requirements)\n"
        
        report += f"""

### Critical Compliance Gaps Requiring Immediate Action
"""
        
        if analysis.critical_gaps:
            for i, gap in enumerate(analysis.critical_gaps[:5], 1):
                framework_name = gap.framework.value.replace('_', ' ').upper()
                report += f"{i}. **{framework_name}**: {gap.title}\n   - Status: {gap.implementation_status.value.replace('_', ' ').title()}\n   - Business Impact: {gap.business_impact.replace('_', ' ').title()}\n   - Remediation Effort: {gap.remediation_effort.replace('_', ' ').title()}\n\n"
        else:
            report += "✅ No critical compliance gaps identified\n"
        
        report += f"""

### Strategic Recommendations

#### Immediate Actions (0-30 days)
"""
        
        immediate_actions = [rec for rec in analysis.strategic_recommendations if rec.startswith(('IMMEDIATE', 'CRITICAL'))]
        for i, action in enumerate(immediate_actions, 1):
            clean_action = action.split(':', 1)[1].strip() if ':' in action else action
            report += f"{i}. {clean_action}\n"
        
        report += f"""

#### High-Priority Initiatives (1-6 months)
"""
        
        high_priority_actions = [rec for rec in analysis.strategic_recommendations if rec.startswith(('HIGH', 'MEDIUM'))]
        for i, action in enumerate(high_priority_actions[:3], 1):
            priority = action.split(':')[0]
            description = action.split(':', 1)[1].strip() if ':' in action else action
            report += f"{i}. **{priority}**: {description}\n"
        
        report += f"""

#### Strategic Initiatives (6+ months)
"""
        
        strategic_actions = [rec for rec in analysis.strategic_recommendations if rec.startswith(('STRATEGIC', 'REGULATORY'))]
        for i, action in enumerate(strategic_actions[:3], 1):
            priority = action.split(':')[0]
            description = action.split(':', 1)[1].strip() if ':' in action else action
            report += f"{i}. **{priority}**: {description}\n"
        
        report += f"""

### Regulatory Risk Assessment
- **Enforcement Probability**: {'High' if analysis.regulatory_risk_score > 70 else 'Medium' if analysis.regulatory_risk_score > 40 else 'Low'}
- **Potential Financial Impact**: {'€20M+ (GDPR/AI Act)' if any('gdpr' in fw.value or 'eu_ai_act' in fw.value for fw in analysis.frameworks_assessed) else 'Varies by framework'}
- **Reputational Risk**: {'High' if len(analysis.critical_gaps) > 0 else 'Moderate' if len(analysis.high_priority_gaps) > 3 else 'Low'}
- **Operational Impact**: {'Significant' if analysis.regulatory_risk_score > 60 else 'Moderate' if analysis.regulatory_risk_score > 30 else 'Limited'}

### Audit Preparation Status
- **Documentation Completeness**: {85 - len(analysis.critical_gaps) * 10:.0f}%
- **Evidence Quality**: {'Strong' if analysis.audit_readiness_level == 'audit_ready' else 'Adequate' if 'prepared' in analysis.audit_readiness_level else 'Needs Improvement'}
- **Process Maturity**: {'Advanced' if score >= 85 else 'Developing' if score >= 65 else 'Basic'}
- **Timeline to Audit Ready**: {'Ready Now' if analysis.audit_readiness_level == 'audit_ready' else '3-6 months' if 'prepared' in analysis.audit_readiness_level else '6-12 months'}

### Investment Recommendations
- **Immediate Investment Required**: ${len(analysis.critical_gaps) * 50000 + len(analysis.high_priority_gaps) * 20000:,} (estimated)
- **Annual Compliance Budget**: ${max(250000, score * -2000 + 400000):,} recommended
- **ROI Timeline**: {'6-12 months' if len(analysis.critical_gaps) > 0 else '12-24 months'}
- **Risk Mitigation Value**: Avoid potential regulatory penalties up to {20 if any('gdpr' in fw.value for fw in analysis.frameworks_assessed) else 7.5 if any('ccpa' in fw.value for fw in analysis.frameworks_assessed) else 1.5}M per violation

---

**Professional AI Compliance Services**
For comprehensive regulatory compliance assessment and implementation:
- **VerityAI Compliance Services**: [https://verityai.co](https://verityai.co)
- **Expert Consultation**: [Sotiris Spyrou](https://www.linkedin.com/in/sspyrou/)

*Portfolio demonstration - Contact for production compliance assessment*
"""
        
        return report

def main():
    """Portfolio demonstration of compliance gap analysis."""
    print("AI Security Compliance Gap Analysis - Portfolio Demo")
    print("=" * 60)
    
    # Simulate system documentation for assessment
    demo_system_docs = {
        'implemented_controls': [
            'access_management', 'audit_controls', 'privacy_by_design',
            'consent_management', 'data_governance', 'incident_response',
            'risk_management_framework', 'monitoring_systems'
        ],
        'available_evidence': [
            'privacy_policy', 'technical_documentation', 'audit_logs',
            'training_records', 'risk_assessments', 'governance_documentation',
            'user_documentation', 'incident_procedures'
        ],
        'system_characteristics': {
            'processes_personal_data': True,
            'high_risk_ai_system': True,
            'healthcare_data': False,
            'financial_data': True,
            'cross_border_transfers': True
        }
    }
    
    # Select frameworks for assessment
    target_frameworks = [
        ComplianceFramework.GDPR,
        ComplianceFramework.EU_AI_ACT,
        ComplianceFramework.NIST_AI_RMF,
        ComplianceFramework.SOC2
    ]
    
    # Configure assessment scope
    assessment_scope = {
        'assessment_type': 'comprehensive',
        'business_context': 'enterprise_ai_deployment',
        'risk_tolerance': 'low',
        'regulatory_scrutiny': 'high'
    }
    
    # Initialize analyzer
    analyzer = ComplianceGapAnalyzer()
    
    # Perform compliance gap analysis
    analysis_results = analyzer.analyze_compliance_gaps(
        demo_system_docs, target_frameworks, assessment_scope
    )
    
    # Generate compliance report
    compliance_report = analyzer.generate_compliance_report(analysis_results)
    
    print("COMPLIANCE GAP ANALYSIS COMPLETED")
    print(f"Overall Compliance Score: {analysis_results.overall_compliance_score:.0f}%")
    print(f"Critical Gaps: {len(analysis_results.critical_gaps)}")
    print(f"High-Priority Gaps: {len(analysis_results.high_priority_gaps)}")
    print(f"Regulatory Risk Score: {analysis_results.regulatory_risk_score:.0f}/100")
    print(f"Audit Readiness: {analysis_results.audit_readiness_level.replace('_', ' ').title()}")
    
    print("\nExecutive Compliance Report:")
    print(compliance_report)
    
    print("\n" + "=" * 60)
    print("Portfolio Demo by Sotiris Spyrou")
    print("LinkedIn: https://www.linkedin.com/in/sspyrou/")
    print("Professional Compliance Services: https://verityai.co")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
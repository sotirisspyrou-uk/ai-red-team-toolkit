#!/usr/bin/env python3
"""
Risk Prioritization Engine
Portfolio Demo: LLM Security Risk Prioritization and Resource Allocation Framework

Author: Sotiris Spyrou
LinkedIn: https://www.linkedin.com/in/sspyrou/
Company: VerityAI - https://verityai.co

DISCLAIMER: This is demonstration code for portfolio purposes only.
Not intended for production use. For professional risk prioritization,
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
import statistics
import math

class RiskCategory(Enum):
    """Categories of security risks."""
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    COMPLIANCE = "compliance"
    REPUTATION = "reputation"
    FINANCIAL = "financial"
    OPERATIONAL = "operational"

class RiskSeverity(Enum):
    """Risk severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class UrgencyLevel(Enum):
    """Urgency levels for risk remediation."""
    IMMEDIATE = "immediate"      # Must be addressed within 24-48 hours
    URGENT = "urgent"            # Must be addressed within 1 week
    HIGH = "high"               # Must be addressed within 1 month
    MEDIUM = "medium"           # Should be addressed within 3 months
    LOW = "low"                 # Can be addressed within 6 months
    DEFERRED = "deferred"       # Can be deferred beyond 6 months

class BusinessImpactLevel(Enum):
    """Business impact levels."""
    CATASTROPHIC = "catastrophic"    # >$10M impact
    SEVERE = "severe"               # $1M - $10M impact
    MAJOR = "major"                 # $100K - $1M impact
    MODERATE = "moderate"           # $10K - $100K impact
    MINOR = "minor"                 # <$10K impact

@dataclass
class RiskFactor:
    """Individual risk factor assessment."""
    factor_name: str
    category: RiskCategory
    severity_score: float        # 0-10 scale
    likelihood_score: float      # 0-1 probability
    business_impact: BusinessImpactLevel
    time_sensitivity: float      # 0-1 scale (1 = must fix immediately)
    regulatory_impact: bool
    customer_facing: bool
    technical_complexity: float  # 0-1 scale (1 = very complex to fix)

@dataclass
class VulnerabilityRisk:
    """Comprehensive vulnerability risk assessment."""
    vulnerability_id: str
    vulnerability_type: str
    description: str
    risk_factors: List[RiskFactor]
    exploitability_score: float
    business_context: Dict[str, Any]
    affected_assets: List[str]
    threat_actors: List[str]
    attack_vectors: List[str]
    
@dataclass
class RiskPriority:
    """Risk priority calculation result."""
    vulnerability_id: str
    risk_score: float
    priority_rank: int
    urgency_level: UrgencyLevel
    recommended_timeline: str
    resource_allocation: Dict[str, float]
    justification: str
    dependencies: List[str]
    cost_benefit_ratio: float

class RiskPrioritizationEngine:
    """
    Advanced risk prioritization engine for LLM security vulnerabilities - Portfolio demonstration.
    
    EXECUTIVE VALUE PROPOSITION:
    - Optimizes security resource allocation through data-driven risk prioritization
    - Balances security investment with business impact and technical feasibility
    - Enables strategic security roadmap planning with quantified risk reduction
    - Provides CISO-level decision support for vulnerability management programs
    
    STRATEGIC POSITIONING:
    Demonstrates mastery of enterprise risk management methodologies applied to
    AI security - essential for senior security leadership roles requiring 
    strategic planning and resource optimization capabilities.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.risk_models = self._initialize_risk_models()
        self.priority_weights = self._initialize_priority_weights()
        self.business_context_multipliers = self._initialize_business_multipliers()
        
    def _initialize_risk_models(self) -> Dict[str, Dict]:
        """Initialize risk assessment models and scoring matrices."""
        return {
            "cvss_base_metrics": {
                "attack_vector_weights": {
                    "network": 0.85,
                    "adjacent": 0.62,
                    "local": 0.55,
                    "physical": 0.20
                },
                "attack_complexity_weights": {
                    "low": 0.77,
                    "high": 0.44
                },
                "privileges_required_weights": {
                    "none": 0.85,
                    "low": 0.62,
                    "high": 0.27
                },
                "user_interaction_weights": {
                    "none": 0.85,
                    "required": 0.62
                }
            },
            
            "business_impact_multipliers": {
                BusinessImpactLevel.CATASTROPHIC: 5.0,
                BusinessImpactLevel.SEVERE: 3.0,
                BusinessImpactLevel.MAJOR: 2.0,
                BusinessImpactLevel.MODERATE: 1.0,
                BusinessImpactLevel.MINOR: 0.5
            },
            
            "time_sensitivity_multipliers": {
                "immediate": 3.0,    # Active exploitation detected
                "urgent": 2.5,       # Proof of concept available
                "high": 2.0,         # Publicly disclosed
                "medium": 1.5,       # Known vulnerability
                "low": 1.0           # Theoretical risk
            },
            
            "regulatory_multipliers": {
                "gdpr": 1.8,
                "hipaa": 1.9,
                "pci_dss": 1.7,
                "sox": 1.6,
                "ccpa": 1.5,
                "nist": 1.4
            }
        }
    
    def _initialize_priority_weights(self) -> Dict[str, float]:
        """Initialize weighting factors for risk prioritization calculation."""
        return {
            "severity": 0.25,           # Technical severity score
            "exploitability": 0.20,     # How easily can this be exploited
            "business_impact": 0.20,    # Financial/operational impact
            "time_sensitivity": 0.15,   # How urgent is remediation
            "compliance_impact": 0.10,  # Regulatory requirements
            "asset_criticality": 0.10   # Importance of affected assets
        }
    
    def _initialize_business_multipliers(self) -> Dict[str, float]:
        """Initialize business context multipliers."""
        return {
            "customer_facing": 1.5,      # Public-facing systems
            "revenue_generating": 1.4,   # Revenue-critical systems
            "compliance_required": 1.6,  # Regulatory compliance systems
            "high_availability": 1.3,    # Mission-critical uptime
            "sensitive_data": 1.7,       # Handles sensitive information
            "external_integration": 1.2  # Third-party integrations
        }
    
    def calculate_risk_priority(
        self,
        vulnerability_risk: VulnerabilityRisk,
        organizational_context: Optional[Dict[str, Any]] = None
    ) -> RiskPriority:
        """
        Calculate comprehensive risk priority for a vulnerability.
        
        Returns prioritized risk assessment with resource allocation recommendations.
        """
        self.logger.info(f"Calculating risk priority for {vulnerability_risk.vulnerability_id}")
        
        if organizational_context is None:
            organizational_context = self._get_default_organizational_context()
        
        # Calculate component scores
        severity_score = self._calculate_severity_score(vulnerability_risk)
        exploitability_score = vulnerability_risk.exploitability_score / 10.0  # Normalize to 0-1
        business_impact_score = self._calculate_business_impact_score(vulnerability_risk)
        time_sensitivity_score = self._calculate_time_sensitivity_score(vulnerability_risk)
        compliance_impact_score = self._calculate_compliance_impact_score(vulnerability_risk)
        asset_criticality_score = self._calculate_asset_criticality_score(
            vulnerability_risk, organizational_context
        )
        
        # Apply priority weights
        weights = self.priority_weights
        weighted_score = (
            severity_score * weights["severity"] +
            exploitability_score * weights["exploitability"] +
            business_impact_score * weights["business_impact"] +
            time_sensitivity_score * weights["time_sensitivity"] +
            compliance_impact_score * weights["compliance_impact"] +
            asset_criticality_score * weights["asset_criticality"]
        )
        
        # Apply business context multipliers
        context_multiplier = self._calculate_context_multiplier(
            vulnerability_risk, organizational_context
        )
        
        final_risk_score = min(10.0, weighted_score * context_multiplier * 10)
        
        # Determine urgency level
        urgency_level = self._determine_urgency_level(
            final_risk_score, vulnerability_risk, organizational_context
        )
        
        # Calculate recommended timeline
        recommended_timeline = self._calculate_recommended_timeline(urgency_level, vulnerability_risk)
        
        # Determine resource allocation
        resource_allocation = self._calculate_resource_allocation(
            final_risk_score, vulnerability_risk, organizational_context
        )
        
        # Generate justification
        justification = self._generate_priority_justification(
            vulnerability_risk, final_risk_score, urgency_level
        )
        
        # Identify dependencies
        dependencies = self._identify_dependencies(vulnerability_risk, organizational_context)
        
        # Calculate cost-benefit ratio
        cost_benefit_ratio = self._calculate_cost_benefit_ratio(
            vulnerability_risk, final_risk_score, organizational_context
        )
        
        return RiskPriority(
            vulnerability_id=vulnerability_risk.vulnerability_id,
            risk_score=final_risk_score,
            priority_rank=0,  # Will be set during portfolio prioritization
            urgency_level=urgency_level,
            recommended_timeline=recommended_timeline,
            resource_allocation=resource_allocation,
            justification=justification,
            dependencies=dependencies,
            cost_benefit_ratio=cost_benefit_ratio
        )
    
    def _get_default_organizational_context(self) -> Dict[str, Any]:
        """Get default organizational context for risk assessment."""
        return {
            "organization_size": "medium",
            "industry": "technology",
            "risk_tolerance": "medium",
            "compliance_requirements": ["gdpr", "iso27001"],
            "security_maturity": "developing",
            "available_resources": {
                "security_engineers": 3,
                "budget_annual": 500000,
                "timeline_flexibility": "medium"
            },
            "business_priorities": [
                "customer_satisfaction",
                "regulatory_compliance", 
                "operational_efficiency"
            ]
        }
    
    def _calculate_severity_score(self, vulnerability_risk: VulnerabilityRisk) -> float:
        """Calculate technical severity score (0-1 scale)."""
        
        # Aggregate risk factor severity scores
        severity_scores = [rf.severity_score for rf in vulnerability_risk.risk_factors]
        
        if not severity_scores:
            return 0.5  # Default medium severity
        
        # Use weighted average with emphasis on highest scores
        sorted_scores = sorted(severity_scores, reverse=True)
        
        if len(sorted_scores) == 1:
            return sorted_scores[0] / 10.0
        
        # Weight highest score more heavily
        weighted_avg = (
            sorted_scores[0] * 0.6 +
            statistics.mean(sorted_scores[1:]) * 0.4
        )
        
        return min(1.0, weighted_avg / 10.0)
    
    def _calculate_business_impact_score(self, vulnerability_risk: VulnerabilityRisk) -> float:
        """Calculate business impact score (0-1 scale)."""
        
        # Get business impact levels from risk factors
        impact_levels = [rf.business_impact for rf in vulnerability_risk.risk_factors]
        
        if not impact_levels:
            return 0.5  # Default medium impact
        
        # Use highest impact level
        highest_impact = max(impact_levels, key=lambda x: list(BusinessImpactLevel).index(x))
        multiplier = self.risk_models["business_impact_multipliers"][highest_impact]
        
        # Normalize to 0-1 scale
        return min(1.0, multiplier / 5.0)
    
    def _calculate_time_sensitivity_score(self, vulnerability_risk: VulnerabilityRisk) -> float:
        """Calculate time sensitivity score (0-1 scale)."""
        
        # Check for time-sensitive factors
        time_scores = [rf.time_sensitivity for rf in vulnerability_risk.risk_factors]
        
        if not time_scores:
            return 0.5
        
        # Use maximum time sensitivity
        max_time_sensitivity = max(time_scores)
        
        # Consider threat intelligence and attack vector maturity
        threat_multiplier = 1.0
        
        # Check for active threats or public exploits
        if any("exploit" in actor.lower() for actor in vulnerability_risk.threat_actors):
            threat_multiplier = 1.5
        if any("public" in vector.lower() for vector in vulnerability_risk.attack_vectors):
            threat_multiplier = max(threat_multiplier, 1.3)
        
        return min(1.0, max_time_sensitivity * threat_multiplier)
    
    def _calculate_compliance_impact_score(self, vulnerability_risk: VulnerabilityRisk) -> float:
        """Calculate regulatory compliance impact score (0-1 scale)."""
        
        # Check for regulatory risk factors
        regulatory_factors = [
            rf for rf in vulnerability_risk.risk_factors 
            if rf.regulatory_impact
        ]
        
        if not regulatory_factors:
            return 0.0
        
        # Base compliance score
        base_score = len(regulatory_factors) / len(vulnerability_risk.risk_factors)
        
        # Apply regulatory framework multipliers
        regulatory_context = vulnerability_risk.business_context.get('compliance_requirements', [])
        max_multiplier = 1.0
        
        for requirement in regulatory_context:
            if requirement.lower() in self.risk_models["regulatory_multipliers"]:
                multiplier = self.risk_models["regulatory_multipliers"][requirement.lower()]
                max_multiplier = max(max_multiplier, multiplier)
        
        # Normalize to 0-1 scale
        return min(1.0, base_score * max_multiplier / 2.0)
    
    def _calculate_asset_criticality_score(
        self, 
        vulnerability_risk: VulnerabilityRisk,
        organizational_context: Dict[str, Any]
    ) -> float:
        """Calculate affected asset criticality score (0-1 scale)."""
        
        affected_assets = vulnerability_risk.affected_assets
        if not affected_assets:
            return 0.5
        
        # Asset criticality mapping
        asset_criticality_map = {
            "production_database": 1.0,
            "customer_data": 1.0,
            "authentication_system": 0.95,
            "payment_processing": 0.95,
            "api_gateway": 0.9,
            "web_application": 0.8,
            "internal_tools": 0.6,
            "development_environment": 0.4,
            "testing_environment": 0.3
        }
        
        # Calculate weighted criticality
        total_criticality = 0.0
        for asset in affected_assets:
            asset_key = asset.lower().replace(' ', '_')
            criticality = asset_criticality_map.get(asset_key, 0.5)
            total_criticality += criticality
        
        avg_criticality = total_criticality / len(affected_assets)
        
        # Adjust based on organizational priorities
        business_priorities = organizational_context.get('business_priorities', [])
        if 'customer_satisfaction' in business_priorities:
            if any('customer' in asset.lower() for asset in affected_assets):
                avg_criticality *= 1.2
        
        return min(1.0, avg_criticality)
    
    def _calculate_context_multiplier(
        self,
        vulnerability_risk: VulnerabilityRisk,
        organizational_context: Dict[str, Any]
    ) -> float:
        """Calculate business context multiplier."""
        
        multiplier = 1.0
        business_context = vulnerability_risk.business_context
        
        # Apply context-specific multipliers
        for context_factor, factor_multiplier in self.business_context_multipliers.items():
            if business_context.get(context_factor, False):
                multiplier *= factor_multiplier
        
        # Organizational risk tolerance adjustment
        risk_tolerance = organizational_context.get('risk_tolerance', 'medium')
        tolerance_adjustments = {
            'very_low': 1.3,
            'low': 1.2,
            'medium': 1.0,
            'high': 0.8,
            'very_high': 0.6
        }
        multiplier *= tolerance_adjustments.get(risk_tolerance, 1.0)
        
        # Industry-specific adjustments
        industry = organizational_context.get('industry', 'technology')
        industry_adjustments = {
            'financial': 1.4,
            'healthcare': 1.3,
            'government': 1.3,
            'education': 1.1,
            'technology': 1.0,
            'retail': 0.9
        }
        multiplier *= industry_adjustments.get(industry, 1.0)
        
        return multiplier
    
    def _determine_urgency_level(
        self,
        risk_score: float,
        vulnerability_risk: VulnerabilityRisk,
        organizational_context: Dict[str, Any]
    ) -> UrgencyLevel:
        """Determine urgency level based on risk score and context."""
        
        # Base urgency from risk score
        if risk_score >= 9.0:
            base_urgency = UrgencyLevel.IMMEDIATE
        elif risk_score >= 7.5:
            base_urgency = UrgencyLevel.URGENT
        elif risk_score >= 6.0:
            base_urgency = UrgencyLevel.HIGH
        elif risk_score >= 4.0:
            base_urgency = UrgencyLevel.MEDIUM
        elif risk_score >= 2.0:
            base_urgency = UrgencyLevel.LOW
        else:
            base_urgency = UrgencyLevel.DEFERRED
        
        # Escalate based on specific conditions
        escalation_factors = [
            # Active exploitation detected
            any("active" in actor.lower() for actor in vulnerability_risk.threat_actors),
            # Public exploit available
            any("public" in vector.lower() for vector in vulnerability_risk.attack_vectors),
            # Regulatory deadline approaching
            any(rf.regulatory_impact for rf in vulnerability_risk.risk_factors),
            # Customer-facing system with high business impact
            vulnerability_risk.business_context.get('customer_facing', False) and 
            any(rf.business_impact in [BusinessImpactLevel.CATASTROPHIC, BusinessImpactLevel.SEVERE] 
                for rf in vulnerability_risk.risk_factors)
        ]
        
        escalation_count = sum(escalation_factors)
        
        # Escalate urgency based on critical factors
        if escalation_count >= 2:
            if base_urgency.value in ['high', 'medium', 'low', 'deferred']:
                return UrgencyLevel.URGENT
        elif escalation_count >= 1:
            if base_urgency.value in ['medium', 'low', 'deferred']:
                return UrgencyLevel.HIGH
        
        return base_urgency
    
    def _calculate_recommended_timeline(
        self,
        urgency_level: UrgencyLevel,
        vulnerability_risk: VulnerabilityRisk
    ) -> str:
        """Calculate recommended remediation timeline."""
        
        base_timelines = {
            UrgencyLevel.IMMEDIATE: "24-48 hours",
            UrgencyLevel.URGENT: "1 week",
            UrgencyLevel.HIGH: "1 month", 
            UrgencyLevel.MEDIUM: "3 months",
            UrgencyLevel.LOW: "6 months",
            UrgencyLevel.DEFERRED: "Next major release cycle"
        }
        
        base_timeline = base_timelines[urgency_level]
        
        # Adjust for technical complexity
        avg_complexity = statistics.mean([
            rf.technical_complexity for rf in vulnerability_risk.risk_factors
        ]) if vulnerability_risk.risk_factors else 0.5
        
        if avg_complexity > 0.8:  # Very complex
            complexity_adjustments = {
                UrgencyLevel.IMMEDIATE: "1-2 weeks (complex remediation)",
                UrgencyLevel.URGENT: "2-3 weeks",
                UrgencyLevel.HIGH: "6-8 weeks",
                UrgencyLevel.MEDIUM: "4-6 months",
                UrgencyLevel.LOW: "9-12 months",
                UrgencyLevel.DEFERRED: "Future roadmap item"
            }
            return complexity_adjustments.get(urgency_level, base_timeline)
        
        return base_timeline
    
    def _calculate_resource_allocation(
        self,
        risk_score: float,
        vulnerability_risk: VulnerabilityRisk,
        organizational_context: Dict[str, Any]
    ) -> Dict[str, float]:
        """Calculate recommended resource allocation percentages."""
        
        total_annual_budget = organizational_context.get('available_resources', {}).get('budget_annual', 500000)
        
        # Base allocation based on risk score
        base_allocation_percentage = min(0.30, risk_score / 10.0 * 0.20)  # Max 30% of budget
        base_allocation = total_annual_budget * base_allocation_percentage
        
        # Resource type breakdown
        resource_allocation = {
            "security_engineering": base_allocation * 0.4,
            "development_resources": base_allocation * 0.3,
            "external_consulting": base_allocation * 0.15,
            "tools_and_infrastructure": base_allocation * 0.10,
            "testing_and_validation": base_allocation * 0.05
        }
        
        # Adjust based on technical complexity
        avg_complexity = statistics.mean([
            rf.technical_complexity for rf in vulnerability_risk.risk_factors
        ]) if vulnerability_risk.risk_factors else 0.5
        
        if avg_complexity > 0.7:
            # Shift more resources to external consulting for complex issues
            resource_allocation["external_consulting"] *= 1.5
            resource_allocation["security_engineering"] *= 0.8
        
        # Adjust based on compliance requirements
        if any(rf.regulatory_impact for rf in vulnerability_risk.risk_factors):
            resource_allocation["external_consulting"] *= 1.3  # Compliance expertise
        
        return resource_allocation
    
    def _generate_priority_justification(
        self,
        vulnerability_risk: VulnerabilityRisk,
        risk_score: float,
        urgency_level: UrgencyLevel
    ) -> str:
        """Generate human-readable justification for priority assignment."""
        
        # Risk level description
        if risk_score >= 8.5:
            risk_level = "CRITICAL"
        elif risk_score >= 7.0:
            risk_level = "HIGH"
        elif risk_score >= 5.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Key risk factors
        key_factors = []
        
        # Business impact
        business_impacts = [rf.business_impact for rf in vulnerability_risk.risk_factors]
        if any(impact in [BusinessImpactLevel.CATASTROPHIC, BusinessImpactLevel.SEVERE] for impact in business_impacts):
            key_factors.append("severe business impact potential")
        
        # Exploitability
        if vulnerability_risk.exploitability_score >= 8.0:
            key_factors.append("high exploitability")
        
        # Regulatory impact
        if any(rf.regulatory_impact for rf in vulnerability_risk.risk_factors):
            key_factors.append("regulatory compliance requirements")
        
        # Customer impact
        if vulnerability_risk.business_context.get('customer_facing', False):
            key_factors.append("customer-facing system exposure")
        
        # Time sensitivity
        if any(rf.time_sensitivity > 0.8 for rf in vulnerability_risk.risk_factors):
            key_factors.append("time-sensitive remediation required")
        
        # Build justification
        justification = f"{risk_level} risk vulnerability requiring {urgency_level.value} attention."
        
        if key_factors:
            factor_text = ", ".join(key_factors)
            justification += f" Key factors: {factor_text}."
        
        # Add specific recommendations
        if urgency_level in [UrgencyLevel.IMMEDIATE, UrgencyLevel.URGENT]:
            justification += " Recommend immediate resource allocation and executive notification."
        elif urgency_level == UrgencyLevel.HIGH:
            justification += " Should be prioritized in current sprint planning."
        
        return justification
    
    def _identify_dependencies(
        self,
        vulnerability_risk: VulnerabilityRisk,
        organizational_context: Dict[str, Any]
    ) -> List[str]:
        """Identify remediation dependencies."""
        
        dependencies = []
        
        # Technical dependencies based on affected assets
        affected_assets = vulnerability_risk.affected_assets
        
        if any('database' in asset.lower() for asset in affected_assets):
            dependencies.append("Database maintenance window required")
        
        if any('api' in asset.lower() for asset in affected_assets):
            dependencies.append("API version compatibility assessment")
        
        if any('authentication' in asset.lower() for asset in affected_assets):
            dependencies.append("User authentication system testing")
        
        # Organizational dependencies
        if any(rf.regulatory_impact for rf in vulnerability_risk.risk_factors):
            dependencies.append("Legal/compliance team review")
        
        if vulnerability_risk.business_context.get('customer_facing', False):
            dependencies.append("Customer communication plan")
        
        # Technical complexity dependencies
        avg_complexity = statistics.mean([
            rf.technical_complexity for rf in vulnerability_risk.risk_factors
        ]) if vulnerability_risk.risk_factors else 0.5
        
        if avg_complexity > 0.8:
            dependencies.extend([
                "Architecture review required",
                "Extended testing period",
                "Rollback plan preparation"
            ])
        
        return dependencies
    
    def _calculate_cost_benefit_ratio(
        self,
        vulnerability_risk: VulnerabilityRisk,
        risk_score: float,
        organizational_context: Dict[str, Any]
    ) -> float:
        """Calculate cost-benefit ratio for remediation."""
        
        # Estimate potential loss (benefit of fixing)
        business_impacts = [rf.business_impact for rf in vulnerability_risk.risk_factors]
        
        impact_costs = {
            BusinessImpactLevel.CATASTROPHIC: 10000000,
            BusinessImpactLevel.SEVERE: 3000000,
            BusinessImpactLevel.MAJOR: 800000,
            BusinessImpactLevel.MODERATE: 200000,
            BusinessImpactLevel.MINOR: 50000
        }
        
        # Calculate expected loss
        max_impact = max(business_impacts) if business_impacts else BusinessImpactLevel.MODERATE
        potential_loss = impact_costs[max_impact]
        
        # Factor in likelihood and exploitability
        likelihood = vulnerability_risk.exploitability_score / 10.0
        expected_loss = potential_loss * likelihood
        
        # Estimate remediation cost
        avg_complexity = statistics.mean([
            rf.technical_complexity for rf in vulnerability_risk.risk_factors
        ]) if vulnerability_risk.risk_factors else 0.5
        
        base_cost = 50000  # Base remediation cost
        complexity_multiplier = 1 + (avg_complexity * 3)  # 1x to 4x multiplier
        
        estimated_cost = base_cost * complexity_multiplier
        
        # Calculate ratio (benefit / cost)
        if estimated_cost > 0:
            return expected_loss / estimated_cost
        else:
            return float('inf')  # Zero cost = infinite benefit
    
    def prioritize_risk_portfolio(
        self,
        vulnerability_risks: List[VulnerabilityRisk],
        organizational_context: Optional[Dict[str, Any]] = None,
        resource_constraints: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Prioritize a portfolio of vulnerability risks with resource optimization.
        
        Returns comprehensive portfolio prioritization with strategic recommendations.
        """
        self.logger.info(f"Prioritizing risk portfolio with {len(vulnerability_risks)} vulnerabilities")
        
        if organizational_context is None:
            organizational_context = self._get_default_organizational_context()
        
        if resource_constraints is None:
            resource_constraints = {
                "max_concurrent_projects": 5,
                "quarterly_budget": 125000,
                "engineering_capacity": 40  # person-weeks per quarter
            }
        
        # Calculate individual risk priorities
        risk_priorities = []
        for vuln_risk in vulnerability_risks:
            priority = self.calculate_risk_priority(vuln_risk, organizational_context)
            risk_priorities.append(priority)
        
        # Sort by risk score
        risk_priorities.sort(key=lambda x: x.risk_score, reverse=True)
        
        # Assign priority ranks
        for i, priority in enumerate(risk_priorities, 1):
            priority.priority_rank = i
        
        # Optimize resource allocation
        optimized_allocation = self._optimize_portfolio_allocation(
            risk_priorities, resource_constraints, organizational_context
        )
        
        # Generate portfolio analytics
        portfolio_analytics = self._analyze_risk_portfolio(
            risk_priorities, vulnerability_risks, organizational_context
        )
        
        return {
            'prioritization_timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerability_risks),
            'risk_priorities': risk_priorities,
            'optimized_allocation': optimized_allocation,
            'portfolio_analytics': portfolio_analytics,
            'executive_summary': self._generate_portfolio_executive_summary(
                portfolio_analytics, optimized_allocation
            ),
            'strategic_recommendations': self._generate_portfolio_recommendations(
                portfolio_analytics, optimized_allocation, organizational_context
            )
        }
    
    def _optimize_portfolio_allocation(
        self,
        risk_priorities: List[RiskPriority],
        resource_constraints: Dict[str, Any],
        organizational_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Optimize resource allocation across risk portfolio."""
        
        max_projects = resource_constraints.get('max_concurrent_projects', 5)
        quarterly_budget = resource_constraints.get('quarterly_budget', 125000)
        engineering_capacity = resource_constraints.get('engineering_capacity', 40)
        
        # Greedy selection based on cost-benefit ratio and urgency
        selected_priorities = []
        total_cost = 0.0
        total_capacity_used = 0.0
        
        # Sort by composite score: (risk_score * cost_benefit_ratio) / complexity
        def optimization_score(priority):
            # Estimate capacity requirement based on urgency and complexity
            urgency_weights = {
                UrgencyLevel.IMMEDIATE: 3.0,
                UrgencyLevel.URGENT: 2.5,
                UrgencyLevel.HIGH: 2.0,
                UrgencyLevel.MEDIUM: 1.5,
                UrgencyLevel.LOW: 1.0,
                UrgencyLevel.DEFERRED: 0.5
            }
            
            capacity_estimate = urgency_weights.get(priority.urgency_level, 1.0) * 2
            cost_estimate = sum(priority.resource_allocation.values())
            
            if cost_estimate > 0 and capacity_estimate > 0:
                return (priority.risk_score * priority.cost_benefit_ratio) / (cost_estimate + capacity_estimate)
            else:
                return priority.risk_score
        
        sorted_priorities = sorted(risk_priorities, key=optimization_score, reverse=True)
        
        for priority in sorted_priorities:
            if len(selected_priorities) >= max_projects:
                break
            
            # Estimate resource requirements
            estimated_cost = sum(priority.resource_allocation.values())
            estimated_capacity = self._estimate_capacity_requirement(priority)
            
            # Check constraints
            if (total_cost + estimated_cost <= quarterly_budget and 
                total_capacity_used + estimated_capacity <= engineering_capacity):
                
                selected_priorities.append(priority)
                total_cost += estimated_cost
                total_capacity_used += estimated_capacity
        
        # Calculate resource utilization
        budget_utilization = total_cost / quarterly_budget if quarterly_budget > 0 else 0
        capacity_utilization = total_capacity_used / engineering_capacity if engineering_capacity > 0 else 0
        
        return {
            'selected_priorities': selected_priorities,
            'deferred_priorities': [p for p in risk_priorities if p not in selected_priorities],
            'total_selected': len(selected_priorities),
            'total_estimated_cost': total_cost,
            'total_capacity_required': total_capacity_used,
            'budget_utilization': budget_utilization,
            'capacity_utilization': capacity_utilization,
            'optimization_efficiency': len(selected_priorities) / len(risk_priorities) if risk_priorities else 0
        }
    
    def _estimate_capacity_requirement(self, priority: RiskPriority) -> float:
        """Estimate engineering capacity requirement (person-weeks)."""
        
        # Base capacity mapping by urgency
        urgency_capacity_map = {
            UrgencyLevel.IMMEDIATE: 8,   # 2 person-months
            UrgencyLevel.URGENT: 6,     # 1.5 person-months
            UrgencyLevel.HIGH: 4,       # 1 person-month
            UrgencyLevel.MEDIUM: 2,     # 2 person-weeks
            UrgencyLevel.LOW: 1,        # 1 person-week
            UrgencyLevel.DEFERRED: 0.5  # Half person-week
        }
        
        base_capacity = urgency_capacity_map.get(priority.urgency_level, 2)
        
        # Adjust for risk score complexity
        complexity_multiplier = 1 + (priority.risk_score / 10.0)
        
        return base_capacity * complexity_multiplier
    
    def _analyze_risk_portfolio(
        self,
        risk_priorities: List[RiskPriority],
        vulnerability_risks: List[VulnerabilityRisk],
        organizational_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze portfolio-level risk patterns and metrics."""
        
        if not risk_priorities:
            return {'error': 'No risk priorities to analyze'}
        
        # Risk score distribution
        risk_scores = [p.risk_score for p in risk_priorities]
        score_stats = {
            'mean': statistics.mean(risk_scores),
            'median': statistics.median(risk_scores),
            'max': max(risk_scores),
            'min': min(risk_scores),
            'std_dev': statistics.stdev(risk_scores) if len(risk_scores) > 1 else 0
        }
        
        # Urgency level distribution
        urgency_counts = defaultdict(int)
        for priority in risk_priorities:
            urgency_counts[priority.urgency_level.value] += 1
        
        # Risk category analysis
        category_analysis = self._analyze_risk_categories(vulnerability_risks)
        
        # Cost-benefit analysis
        cost_benefit_ratios = [p.cost_benefit_ratio for p in risk_priorities if p.cost_benefit_ratio != float('inf')]
        cb_stats = {
            'mean': statistics.mean(cost_benefit_ratios) if cost_benefit_ratios else 0,
            'median': statistics.median(cost_benefit_ratios) if cost_benefit_ratios else 0,
            'high_value_count': len([cb for cb in cost_benefit_ratios if cb > 5.0])
        }
        
        # Timeline analysis
        immediate_count = len([p for p in risk_priorities if p.urgency_level == UrgencyLevel.IMMEDIATE])
        urgent_count = len([p for p in risk_priorities if p.urgency_level == UrgencyLevel.URGENT])
        critical_workload = immediate_count + urgent_count
        
        return {
            'risk_score_statistics': score_stats,
            'urgency_distribution': dict(urgency_counts),
            'category_analysis': category_analysis,
            'cost_benefit_statistics': cb_stats,
            'critical_workload': critical_workload,
            'portfolio_risk_level': self._calculate_portfolio_risk_level(risk_scores),
            'resource_pressure_index': self._calculate_resource_pressure_index(risk_priorities),
            'compliance_risk_count': len([
                p for p in risk_priorities 
                for vr in vulnerability_risks 
                if vr.vulnerability_id == p.vulnerability_id and 
                any(rf.regulatory_impact for rf in vr.risk_factors)
            ])
        }
    
    def _analyze_risk_categories(self, vulnerability_risks: List[VulnerabilityRisk]) -> Dict[str, Any]:
        """Analyze risk distribution by category."""
        
        category_counts = defaultdict(int)
        category_scores = defaultdict(list)
        
        for vuln_risk in vulnerability_risks:
            for risk_factor in vuln_risk.risk_factors:
                category = risk_factor.category.value
                category_counts[category] += 1
                category_scores[category].append(risk_factor.severity_score)
        
        category_analysis = {}
        for category, scores in category_scores.items():
            category_analysis[category] = {
                'count': category_counts[category],
                'avg_severity': statistics.mean(scores),
                'max_severity': max(scores),
                'total_exposure': sum(scores)
            }
        
        return category_analysis
    
    def _calculate_portfolio_risk_level(self, risk_scores: List[float]) -> str:
        """Calculate overall portfolio risk level."""
        
        if not risk_scores:
            return "unknown"
        
        avg_score = statistics.mean(risk_scores)
        max_score = max(risk_scores)
        high_risk_count = len([s for s in risk_scores if s >= 7.5])
        
        if max_score >= 9.0 and high_risk_count >= 3:
            return "critical"
        elif avg_score >= 7.0 or high_risk_count >= 5:
            return "high"
        elif avg_score >= 5.0 or max_score >= 8.0:
            return "medium"
        else:
            return "low"
    
    def _calculate_resource_pressure_index(self, risk_priorities: List[RiskPriority]) -> float:
        """Calculate resource pressure index (0-10 scale)."""
        
        # Count high-urgency items
        immediate_count = len([p for p in risk_priorities if p.urgency_level == UrgencyLevel.IMMEDIATE])
        urgent_count = len([p for p in risk_priorities if p.urgency_level == UrgencyLevel.URGENT])
        high_count = len([p for p in risk_priorities if p.urgency_level == UrgencyLevel.HIGH])
        
        # Calculate pressure score
        pressure_score = (immediate_count * 3.0 + urgent_count * 2.0 + high_count * 1.0)
        
        # Normalize to 0-10 scale
        return min(10.0, pressure_score)
    
    def _generate_portfolio_executive_summary(
        self,
        portfolio_analytics: Dict[str, Any],
        optimized_allocation: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate executive summary of portfolio prioritization."""
        
        portfolio_risk_level = portfolio_analytics.get('portfolio_risk_level', 'unknown')
        critical_workload = portfolio_analytics.get('critical_workload', 0)
        selected_count = optimized_allocation.get('total_selected', 0)
        total_cost = optimized_allocation.get('total_estimated_cost', 0)
        
        # Risk assessment statement
        risk_statements = {
            'critical': "CRITICAL: Portfolio contains multiple high-severity vulnerabilities requiring immediate executive attention and resource allocation",
            'high': "HIGH: Significant security risks identified requiring urgent prioritization and resource investment",
            'medium': "MEDIUM: Moderate security risks requiring systematic remediation planning and resource allocation",
            'low': "LOW: Security posture adequate with manageable risk levels requiring standard maintenance"
        }
        
        risk_statement = risk_statements.get(portfolio_risk_level, "Risk assessment unavailable")
        
        # Resource allocation assessment
        budget_utilization = optimized_allocation.get('budget_utilization', 0)
        capacity_utilization = optimized_allocation.get('capacity_utilization', 0)
        
        resource_efficiency = "optimal" if 0.8 <= budget_utilization <= 0.95 and 0.8 <= capacity_utilization <= 0.95 else \
                            "over_allocated" if budget_utilization > 0.95 or capacity_utilization > 0.95 else \
                            "under_utilized"
        
        return {
            'portfolio_risk_level': portfolio_risk_level,
            'risk_statement': risk_statement,
            'critical_items_requiring_attention': critical_workload,
            'recommended_immediate_projects': selected_count,
            'estimated_quarterly_investment': total_cost,
            'resource_allocation_efficiency': resource_efficiency,
            'budget_utilization_percentage': budget_utilization * 100,
            'capacity_utilization_percentage': capacity_utilization * 100,
            'executive_action_required': portfolio_risk_level in ['critical', 'high'] or critical_workload > 5,
            'risk_management_maturity': self._assess_risk_management_maturity(portfolio_analytics)
        }
    
    def _assess_risk_management_maturity(self, portfolio_analytics: Dict[str, Any]) -> str:
        """Assess organizational risk management maturity."""
        
        # Factors indicating maturity
        score_std_dev = portfolio_analytics.get('risk_score_statistics', {}).get('std_dev', 0)
        compliance_coverage = portfolio_analytics.get('compliance_risk_count', 0)
        cb_high_value_count = portfolio_analytics.get('cost_benefit_statistics', {}).get('high_value_count', 0)
        
        # Calculate maturity score
        maturity_score = 0
        
        # Low variance in risk scores suggests systematic assessment
        if score_std_dev < 2.0:
            maturity_score += 1
        
        # Compliance risk identification suggests mature processes
        if compliance_coverage > 0:
            maturity_score += 1
        
        # High-value investments suggest strategic thinking
        if cb_high_value_count > 2:
            maturity_score += 1
        
        maturity_levels = {
            0: "developing",
            1: "defined", 
            2: "managed",
            3: "optimized"
        }
        
        return maturity_levels.get(maturity_score, "developing")
    
    def _generate_portfolio_recommendations(
        self,
        portfolio_analytics: Dict[str, Any],
        optimized_allocation: Dict[str, Any],
        organizational_context: Dict[str, Any]
    ) -> List[str]:
        """Generate strategic portfolio recommendations."""
        
        recommendations = []
        
        portfolio_risk_level = portfolio_analytics.get('portfolio_risk_level', 'low')
        critical_workload = portfolio_analytics.get('critical_workload', 0)
        resource_pressure = portfolio_analytics.get('resource_pressure_index', 0)
        
        # Critical portfolio recommendations
        if portfolio_risk_level == 'critical':
            recommendations.append(
                "IMMEDIATE: Establish emergency security response team for critical vulnerability portfolio"
            )
            recommendations.append(
                "EXECUTIVE: Brief C-suite on critical risk exposure and resource requirements within 24 hours"
            )
        
        # High workload recommendations
        if critical_workload > 8:
            recommendations.append(
                "RESOURCE: Scale security engineering capacity through external consulting partnerships"
            )
        elif critical_workload > 5:
            recommendations.append(
                "PLANNING: Implement dedicated sprint cycles for high-priority security remediation"
            )
        
        # Resource pressure recommendations
        if resource_pressure > 7.0:
            recommendations.append(
                "STRATEGIC: Review and increase quarterly security budget allocation by 40-60%"
            )
        elif resource_pressure > 5.0:
            recommendations.append(
                "OPERATIONAL: Optimize resource allocation and consider timeline adjustments"
            )
        
        # Portfolio optimization recommendations
        optimization_efficiency = optimized_allocation.get('optimization_efficiency', 0)
        if optimization_efficiency < 0.6:
            recommendations.append(
                "OPTIMIZATION: Review risk prioritization criteria and resource allocation strategy"
            )
        
        # Compliance recommendations
        compliance_count = portfolio_analytics.get('compliance_risk_count', 0)
        if compliance_count > 3:
            recommendations.append(
                "COMPLIANCE: Engage legal/compliance team for regulatory risk assessment and timeline planning"
            )
        
        # Cost-benefit recommendations
        cb_stats = portfolio_analytics.get('cost_benefit_statistics', {})
        if cb_stats.get('high_value_count', 0) > 5:
            recommendations.append(
                "INVESTMENT: Strong ROI portfolio - recommend immediate funding approval for high-value security investments"
            )
        
        # Always include professional consultation
        recommendations.append(
            "STRATEGIC: Consider professional risk prioritization consultation from VerityAI for portfolio optimization"
        )
        
        return recommendations[:8]
    
    def generate_prioritization_report(self, prioritization_results: Dict[str, Any]) -> str:
        """Generate comprehensive risk prioritization report."""
        
        portfolio_analytics = prioritization_results.get('portfolio_analytics', {})
        exec_summary = prioritization_results.get('executive_summary', {})
        optimized_allocation = prioritization_results.get('optimized_allocation', {})
        
        # Determine portfolio risk emoji
        portfolio_risk = exec_summary.get('portfolio_risk_level', 'unknown')
        risk_emoji = {
            'critical': '🚨', 'high': '🔴', 'medium': '🟡', 'low': '🟢'
        }.get(portfolio_risk, '❓')
        
        report = f"""
# LLM Security Risk Prioritization Report

**Assessment Date**: {datetime.now().strftime('%B %d, %Y')}
**Prepared by**: Sotiris Spyrou | VerityAI LLM Security Services

## Executive Summary

### Portfolio Risk Status: {risk_emoji} {portfolio_risk.upper()}

{exec_summary.get('risk_statement', 'Risk assessment unavailable')}

**Key Metrics:**
- **Total Vulnerabilities Assessed**: {prioritization_results['total_vulnerabilities']:,}
- **Critical Items Requiring Attention**: {exec_summary.get('critical_items_requiring_attention', 0)}
- **Recommended Immediate Projects**: {exec_summary.get('recommended_immediate_projects', 0)}
- **Estimated Quarterly Investment**: ${exec_summary.get('estimated_quarterly_investment', 0):,.2f}
- **Resource Utilization**: {exec_summary.get('budget_utilization_percentage', 0):.1f}% budget, {exec_summary.get('capacity_utilization_percentage', 0):.1f}% capacity

### Resource Allocation Strategy
"""
        
        # Resource allocation details
        allocation_efficiency = exec_summary.get('resource_allocation_efficiency', 'unknown')
        efficiency_assessment = {
            'optimal': 'EXCELLENT: Resource allocation optimally balanced across portfolio',
            'under_utilized': 'OPPORTUNITY: Additional capacity available for accelerated remediation',
            'over_allocated': 'CONCERN: Resource constraints may impact remediation timeline'
        }.get(allocation_efficiency, 'Unknown resource allocation status')
        
        report += f"""
**Allocation Efficiency**: {efficiency_assessment}

### Urgency Distribution Analysis
"""
        
        urgency_dist = portfolio_analytics.get('urgency_distribution', {})
        for urgency_level in ['immediate', 'urgent', 'high', 'medium', 'low', 'deferred']:
            count = urgency_dist.get(urgency_level, 0)
            percentage = (count / prioritization_results['total_vulnerabilities'] * 100) if prioritization_results['total_vulnerabilities'] > 0 else 0
            urgency_emoji = {
                'immediate': '🚨', 'urgent': '🔴', 'high': '🟠', 
                'medium': '🟡', 'low': '🟢', 'deferred': '⏸️'
            }.get(urgency_level, '❓')
            
            report += f"- **{urgency_level.title()}**: {urgency_emoji} {count} items ({percentage:.1f}%)\n"
        
        # Risk score statistics
        score_stats = portfolio_analytics.get('risk_score_statistics', {})
        report += f"""

### Risk Score Analysis
- **Average Portfolio Risk**: {score_stats.get('mean', 0):.2f}/10.0
- **Highest Risk Item**: {score_stats.get('max', 0):.2f}/10.0
- **Risk Score Standard Deviation**: {score_stats.get('std_dev', 0):.2f}
- **Portfolio Risk Level**: {portfolio_risk.upper()}

### Cost-Benefit Analysis
"""
        
        cb_stats = portfolio_analytics.get('cost_benefit_statistics', {})
        report += f"""
- **Average Cost-Benefit Ratio**: {cb_stats.get('mean', 0):.1f}:1
- **High-Value Investments**: {cb_stats.get('high_value_count', 0)} items with >5:1 ratio
- **Investment Recommendation**: {'Strong business case for immediate funding' if cb_stats.get('high_value_count', 0) > 3 else 'Selective investment based on priority'}

### Resource Pressure Assessment
- **Resource Pressure Index**: {portfolio_analytics.get('resource_pressure_index', 0):.1f}/10.0
- **Critical Workload**: {portfolio_analytics.get('critical_workload', 0)} high-urgency items
- **Capacity Recommendation**: {'Scale team immediately' if portfolio_analytics.get('resource_pressure_index', 0) > 7 else 'Current capacity adequate with optimization'}

### Risk Category Breakdown
"""
        
        category_analysis = portfolio_analytics.get('category_analysis', {})
        for category, stats in category_analysis.items():
            category_name = category.replace('_', ' ').title()
            avg_severity = stats.get('avg_severity', 0)
            item_count = stats.get('count', 0)
            risk_level = 'High' if avg_severity > 7 else 'Medium' if avg_severity > 4 else 'Low'
            
            report += f"- **{category_name}**: {item_count} items, {avg_severity:.1f} avg severity ({risk_level} risk)\n"
        
        # Strategic recommendations
        recommendations = prioritization_results.get('strategic_recommendations', [])
        report += f"""

### Strategic Recommendations
"""
        for i, rec in enumerate(recommendations, 1):
            priority = rec.split(':')[0]
            action = ':'.join(rec.split(':')[1:]).strip()
            report += f"{i}. **{priority}**: {action}\n"
        
        # Optimized allocation details
        selected_count = optimized_allocation.get('total_selected', 0)
        deferred_priorities = optimized_allocation.get('deferred_priorities', [])
        
        report += f"""

### Portfolio Optimization Results
- **Selected for Immediate Action**: {selected_count} vulnerabilities
- **Deferred Items**: {len(deferred_priorities)} vulnerabilities
- **Optimization Efficiency**: {optimized_allocation.get('optimization_efficiency', 0):.1%}
- **Budget Utilization**: {optimized_allocation.get('budget_utilization', 0):.1%}
- **Capacity Utilization**: {optimized_allocation.get('capacity_utilization', 0):.1%}

### Risk Management Maturity
- **Current Maturity Level**: {exec_summary.get('risk_management_maturity', 'Unknown').title()}
- **Executive Action Required**: {'Yes' if exec_summary.get('executive_action_required', False) else 'No'}
- **Compliance Risk Items**: {portfolio_analytics.get('compliance_risk_count', 0)} requiring legal review

### Implementation Timeline
- **Immediate Action (24-48h)**: {urgency_dist.get('immediate', 0)} items
- **Urgent Action (1 week)**: {urgency_dist.get('urgent', 0)} items  
- **High Priority (1 month)**: {urgency_dist.get('high', 0)} items
- **Planned Remediation**: {urgency_dist.get('medium', 0) + urgency_dist.get('low', 0)} items

---

**Professional LLM Security Risk Management Services**
For advanced risk prioritization and portfolio optimization:
- **VerityAI LLM Security Services**: [https://verityai.co](https://verityai.co)
- **Expert Consultation**: [Sotiris Spyrou](https://www.linkedin.com/in/sspyrou/)

*Portfolio demonstration - Contact for production risk prioritization services*
"""
        
        return report

def main():
    """Portfolio demonstration of risk prioritization engine."""
    print("LLM Security Risk Prioritization Engine - Portfolio Demo")
    print("=" * 60)
    
    # Initialize prioritization engine
    engine = RiskPrioritizationEngine()
    
    # Create sample vulnerability risks for demonstration
    sample_vulnerability_risks = [
        VulnerabilityRisk(
            vulnerability_id="VULN-001",
            vulnerability_type="prompt_injection",
            description="Critical prompt injection vulnerability in customer service bot",
            risk_factors=[
                RiskFactor(
                    factor_name="Customer Data Exposure",
                    category=RiskCategory.CONFIDENTIALITY,
                    severity_score=8.5,
                    likelihood_score=0.8,
                    business_impact=BusinessImpactLevel.SEVERE,
                    time_sensitivity=0.9,
                    regulatory_impact=True,
                    customer_facing=True,
                    technical_complexity=0.6
                ),
                RiskFactor(
                    factor_name="Service Disruption",
                    category=RiskCategory.AVAILABILITY,
                    severity_score=7.0,
                    likelihood_score=0.6,
                    business_impact=BusinessImpactLevel.MAJOR,
                    time_sensitivity=0.7,
                    regulatory_impact=False,
                    customer_facing=True,
                    technical_complexity=0.4
                )
            ],
            exploitability_score=8.2,
            business_context={
                'customer_facing': True,
                'revenue_generating': True,
                'compliance_required': True,
                'sensitive_data': True
            },
            affected_assets=["customer_service_bot", "customer_database"],
            threat_actors=["external_attackers", "automated_scanners"],
            attack_vectors=["network_based", "public_exploit_available"]
        ),
        
        VulnerabilityRisk(
            vulnerability_id="VULN-002",
            vulnerability_type="information_leakage",
            description="PII exposure through model responses",
            risk_factors=[
                RiskFactor(
                    factor_name="Privacy Violation",
                    category=RiskCategory.COMPLIANCE,
                    severity_score=7.5,
                    likelihood_score=0.4,
                    business_impact=BusinessImpactLevel.MAJOR,
                    time_sensitivity=0.5,
                    regulatory_impact=True,
                    customer_facing=False,
                    technical_complexity=0.8
                )
            ],
            exploitability_score=6.5,
            business_context={
                'compliance_required': True,
                'sensitive_data': True
            },
            affected_assets=["analytics_system", "user_database"],
            threat_actors=["insider_threat", "external_attackers"],
            attack_vectors=["inference_attacks", "social_engineering"]
        ),
        
        VulnerabilityRisk(
            vulnerability_id="VULN-003",
            vulnerability_type="system_prompt_extraction",
            description="Intellectual property exposure through prompt extraction",
            risk_factors=[
                RiskFactor(
                    factor_name="IP Theft",
                    category=RiskCategory.INTEGRITY,
                    severity_score=6.8,
                    likelihood_score=0.3,
                    business_impact=BusinessImpactLevel.MODERATE,
                    time_sensitivity=0.4,
                    regulatory_impact=False,
                    customer_facing=False,
                    technical_complexity=0.7
                )
            ],
            exploitability_score=5.5,
            business_context={
                'revenue_generating': False,
                'sensitive_data': False
            },
            affected_assets=["content_generation_system"],
            threat_actors=["competitors", "researchers"],
            attack_vectors=["reverse_engineering", "prompt_manipulation"]
        )
    ]
    
    # Define organizational context
    org_context = {
        "organization_size": "large",
        "industry": "financial",
        "risk_tolerance": "low",
        "compliance_requirements": ["gdpr", "pci_dss", "sox"],
        "security_maturity": "managed",
        "available_resources": {
            "security_engineers": 8,
            "budget_annual": 2000000,
            "timeline_flexibility": "medium"
        },
        "business_priorities": [
            "regulatory_compliance",
            "customer_satisfaction",
            "operational_efficiency"
        ]
    }
    
    # Define resource constraints
    resource_constraints = {
        "max_concurrent_projects": 6,
        "quarterly_budget": 500000,
        "engineering_capacity": 60
    }
    
    # Prioritize risk portfolio
    prioritization_results = engine.prioritize_risk_portfolio(
        sample_vulnerability_risks,
        organizational_context=org_context,
        resource_constraints=resource_constraints
    )
    
    # Generate prioritization report
    prioritization_report = engine.generate_prioritization_report(prioritization_results)
    
    print("RISK PRIORITIZATION COMPLETED")
    print(f"Vulnerabilities Analyzed: {prioritization_results['total_vulnerabilities']}")
    
    exec_summary = prioritization_results['executive_summary']
    print(f"Portfolio Risk Level: {exec_summary['portfolio_risk_level'].upper()}")
    print(f"Critical Items: {exec_summary['critical_items_requiring_attention']}")
    print(f"Recommended Projects: {exec_summary['recommended_immediate_projects']}")
    print(f"Estimated Investment: ${exec_summary['estimated_quarterly_investment']:,.2f}")
    print(f"Budget Utilization: {exec_summary['budget_utilization_percentage']:.1f}%")
    
    print("\nExecutive Risk Prioritization Report:")
    print(prioritization_report)
    
    print("\n" + "=" * 60)
    print("Portfolio Demo by Sotiris Spyrou")
    print("LinkedIn: https://www.linkedin.com/in/sspyrou/")
    print("Professional LLM Security Services: https://verityai.co")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
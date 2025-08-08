#!/usr/bin/env python3
"""
Remediation Cost Estimator
Portfolio Demo: LLM Security Vulnerability Remediation Cost Analysis Framework

Author: Sotiris Spyrou
LinkedIn: https://www.linkedin.com/in/sspyrou/
Company: VerityAI - https://verityai.co

DISCLAIMER: This is demonstration code for portfolio purposes only.
Not intended for production use. For professional remediation cost analysis,
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

class RemediationComplexity(Enum):
    """Complexity levels for vulnerability remediation."""
    TRIVIAL = "trivial"          # Configuration change, < 1 day
    SIMPLE = "simple"            # Code fix, 1-3 days
    MODERATE = "moderate"        # Feature enhancement, 1-2 weeks
    COMPLEX = "complex"          # System redesign, 1-2 months
    EXTENSIVE = "extensive"      # Full rewrite/retrain, 3+ months

class RemediationType(Enum):
    """Types of remediation approaches."""
    CONFIGURATION = "configuration"      # Settings/parameter changes
    CODE_PATCH = "code_patch"           # Source code modifications
    ARCHITECTURE = "architecture"       # System design changes
    MODEL_RETRAIN = "model_retrain"     # AI model retraining
    PROCESS = "process"                 # Operational process changes
    INFRASTRUCTURE = "infrastructure"    # Hardware/platform changes
    TRAINING = "training"               # Staff training/education

class ResourceType(Enum):
    """Types of resources required for remediation."""
    AI_ENGINEER = "ai_engineer"
    SECURITY_ENGINEER = "security_engineer"
    SOFTWARE_ENGINEER = "software_engineer"
    DEVOPS_ENGINEER = "devops_engineer"
    DATA_SCIENTIST = "data_scientist"
    SECURITY_CONSULTANT = "security_consultant"
    PROJECT_MANAGER = "project_manager"
    QA_TESTER = "qa_tester"

@dataclass
class RemediationResource:
    """Resource requirement for remediation effort."""
    resource_type: ResourceType
    hours_required: float
    hourly_rate: float
    skill_level: str  # junior, mid, senior, expert
    urgency_multiplier: float

@dataclass
class RemediationApproach:
    """Specific approach to remediate a vulnerability."""
    approach_id: str
    approach_name: str
    remediation_type: RemediationType
    complexity: RemediationComplexity
    description: str
    required_resources: List[RemediationResource]
    estimated_timeline: str
    success_probability: float
    risk_reduction: float
    ongoing_maintenance_cost: float

@dataclass
class VulnerabilityContext:
    """Context information for vulnerability cost estimation."""
    vulnerability_id: str
    vulnerability_type: str
    severity_score: float
    business_impact: str
    affected_systems: List[str]
    deployment_environment: str
    compliance_requirements: List[str]
    urgency_level: str

@dataclass
class RemediationCostEstimate:
    """Complete cost estimate for vulnerability remediation."""
    vulnerability_id: str
    total_cost: float
    labor_cost: float
    infrastructure_cost: float
    opportunity_cost: float
    ongoing_cost_annual: float
    timeline_weeks: float
    confidence_level: float
    recommended_approach: str
    cost_breakdown: Dict[str, float]
    roi_analysis: Dict[str, Any]

class RemediationCostEstimator:
    """
    Advanced remediation cost estimation framework for LLM security vulnerabilities - Portfolio demonstration.
    
    EXECUTIVE VALUE PROPOSITION:
    - Quantifies true cost of vulnerability remediation for budget planning
    - Enables data-driven security investment decisions and ROI analysis
    - Optimizes resource allocation across multiple security initiatives
    - Provides CFO-level financial analysis for security investment justification
    
    STRATEGIC POSITIONING:
    Demonstrates sophisticated understanding of cybersecurity economics and 
    ability to translate technical vulnerabilities into business financial models -
    critical capability for executive-level security leadership roles.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.cost_models = self._initialize_cost_models()
        self.resource_rates = self._initialize_resource_rates()
        self.remediation_templates = self._initialize_remediation_templates()
        
    def _initialize_cost_models(self) -> Dict[str, Dict]:
        """Initialize cost models for different remediation scenarios."""
        return {
            "base_rates": {
                # Base hourly rates by role (USD)
                ResourceType.AI_ENGINEER: 175,
                ResourceType.SECURITY_ENGINEER: 165,
                ResourceType.SOFTWARE_ENGINEER: 135,
                ResourceType.DEVOPS_ENGINEER: 145,
                ResourceType.DATA_SCIENTIST: 155,
                ResourceType.SECURITY_CONSULTANT: 225,
                ResourceType.PROJECT_MANAGER: 125,
                ResourceType.QA_TESTER: 95
            },
            
            "skill_multipliers": {
                "junior": 0.7,
                "mid": 1.0,
                "senior": 1.4,
                "expert": 1.8
            },
            
            "urgency_multipliers": {
                "low": 1.0,
                "medium": 1.2,
                "high": 1.5,
                "critical": 2.0
            },
            
            "complexity_multipliers": {
                RemediationComplexity.TRIVIAL: 1.0,
                RemediationComplexity.SIMPLE: 1.2,
                RemediationComplexity.MODERATE: 1.5,
                RemediationComplexity.COMPLEX: 2.2,
                RemediationComplexity.EXTENSIVE: 3.5
            },
            
            "infrastructure_costs": {
                "additional_compute": {"low": 500, "medium": 2000, "high": 8000},
                "monitoring_tools": {"basic": 1000, "advanced": 5000, "enterprise": 15000},
                "testing_environment": {"simple": 2000, "complex": 8000, "comprehensive": 20000},
                "compliance_tooling": {"basic": 3000, "advanced": 12000, "enterprise": 35000}
            }
        }
    
    def _initialize_resource_rates(self) -> Dict[str, float]:
        """Initialize current market rates for different resources."""
        base_rates = self.cost_models["base_rates"]
        return {resource.value: rate for resource, rate in base_rates.items()}
    
    def _initialize_remediation_templates(self) -> Dict[str, List[RemediationApproach]]:
        """Initialize templates for common vulnerability remediation approaches."""
        return {
            "prompt_injection": [
                RemediationApproach(
                    approach_id="PI_001",
                    approach_name="Input Validation Enhancement",
                    remediation_type=RemediationType.CODE_PATCH,
                    complexity=RemediationComplexity.SIMPLE,
                    description="Implement comprehensive input validation and sanitization",
                    required_resources=[
                        RemediationResource(ResourceType.AI_ENGINEER, 40, 175, "senior", 1.0),
                        RemediationResource(ResourceType.SECURITY_ENGINEER, 20, 165, "mid", 1.0),
                        RemediationResource(ResourceType.QA_TESTER, 16, 95, "mid", 1.0)
                    ],
                    estimated_timeline="1-2 weeks",
                    success_probability=0.85,
                    risk_reduction=0.70,
                    ongoing_maintenance_cost=2400
                ),
                
                RemediationApproach(
                    approach_id="PI_002",
                    approach_name="Context Isolation System",
                    remediation_type=RemediationType.ARCHITECTURE,
                    complexity=RemediationComplexity.COMPLEX,
                    description="Implement conversation context isolation and validation",
                    required_resources=[
                        RemediationResource(ResourceType.AI_ENGINEER, 120, 175, "expert", 1.0),
                        RemediationResource(ResourceType.SOFTWARE_ENGINEER, 80, 135, "senior", 1.0),
                        RemediationResource(ResourceType.DEVOPS_ENGINEER, 40, 145, "senior", 1.0),
                        RemediationResource(ResourceType.PROJECT_MANAGER, 60, 125, "senior", 1.0)
                    ],
                    estimated_timeline="6-8 weeks",
                    success_probability=0.95,
                    risk_reduction=0.90,
                    ongoing_maintenance_cost=8000
                )
            ],
            
            "information_leakage": [
                RemediationApproach(
                    approach_id="IL_001",
                    approach_name="Data Masking and Filtering",
                    remediation_type=RemediationType.CODE_PATCH,
                    complexity=RemediationComplexity.MODERATE,
                    description="Implement advanced data masking and PII filtering",
                    required_resources=[
                        RemediationResource(ResourceType.AI_ENGINEER, 60, 175, "senior", 1.0),
                        RemediationResource(ResourceType.DATA_SCIENTIST, 40, 155, "senior", 1.0),
                        RemediationResource(ResourceType.SECURITY_ENGINEER, 30, 165, "mid", 1.0)
                    ],
                    estimated_timeline="3-4 weeks",
                    success_probability=0.80,
                    risk_reduction=0.75,
                    ongoing_maintenance_cost=4200
                ),
                
                RemediationApproach(
                    approach_id="IL_002",
                    approach_name="Model Retraining with Privacy",
                    remediation_type=RemediationType.MODEL_RETRAIN,
                    complexity=RemediationComplexity.EXTENSIVE,
                    description="Retrain model with differential privacy and data minimization",
                    required_resources=[
                        RemediationResource(ResourceType.AI_ENGINEER, 200, 175, "expert", 1.0),
                        RemediationResource(ResourceType.DATA_SCIENTIST, 160, 155, "expert", 1.0),
                        RemediationResource(ResourceType.DEVOPS_ENGINEER, 80, 145, "senior", 1.0),
                        RemediationResource(ResourceType.PROJECT_MANAGER, 100, 125, "senior", 1.0)
                    ],
                    estimated_timeline="12-16 weeks",
                    success_probability=0.90,
                    risk_reduction=0.95,
                    ongoing_maintenance_cost=15000
                )
            ],
            
            "system_prompt_extraction": [
                RemediationApproach(
                    approach_id="SPE_001",
                    approach_name="Prompt Obfuscation",
                    remediation_type=RemediationType.CONFIGURATION,
                    complexity=RemediationComplexity.SIMPLE,
                    description="Implement system prompt obfuscation and encoding",
                    required_resources=[
                        RemediationResource(ResourceType.AI_ENGINEER, 32, 175, "mid", 1.0),
                        RemediationResource(ResourceType.SECURITY_ENGINEER, 16, 165, "mid", 1.0)
                    ],
                    estimated_timeline="1 week",
                    success_probability=0.60,
                    risk_reduction=0.40,
                    ongoing_maintenance_cost=1200
                ),
                
                RemediationApproach(
                    approach_id="SPE_002",
                    approach_name="Dynamic Prompt System",
                    remediation_type=RemediationType.ARCHITECTURE,
                    complexity=RemediationComplexity.COMPLEX,
                    description="Implement dynamic, context-aware prompt generation",
                    required_resources=[
                        RemediationResource(ResourceType.AI_ENGINEER, 100, 175, "expert", 1.0),
                        RemediationResource(ResourceType.SOFTWARE_ENGINEER, 60, 135, "senior", 1.0),
                        RemediationResource(ResourceType.PROJECT_MANAGER, 40, 125, "mid", 1.0)
                    ],
                    estimated_timeline="5-6 weeks",
                    success_probability=0.85,
                    risk_reduction=0.80,
                    ongoing_maintenance_cost=6000
                )
            ]
        }
    
    def estimate_remediation_cost(
        self,
        vulnerability_context: VulnerabilityContext,
        preferred_approaches: Optional[List[str]] = None,
        budget_constraints: Optional[Dict[str, float]] = None
    ) -> Dict[str, RemediationCostEstimate]:
        """
        Estimate remediation costs for a vulnerability across different approaches.
        
        Returns cost estimates for each viable remediation approach.
        """
        self.logger.info(f"Estimating remediation costs for {vulnerability_context.vulnerability_id}")
        
        # Get applicable remediation approaches
        approaches = self._get_applicable_approaches(
            vulnerability_context, preferred_approaches
        )
        
        cost_estimates = {}
        
        for approach in approaches:
            # Skip if outside budget constraints
            if budget_constraints and not self._within_budget_constraints(approach, budget_constraints):
                continue
                
            estimate = self._calculate_approach_cost(approach, vulnerability_context)
            cost_estimates[approach.approach_id] = estimate
        
        return cost_estimates
    
    def _get_applicable_approaches(
        self,
        context: VulnerabilityContext,
        preferred_approaches: Optional[List[str]] = None
    ) -> List[RemediationApproach]:
        """Get applicable remediation approaches for vulnerability type."""
        
        vuln_type_mapping = {
            "prompt_injection": "prompt_injection",
            "information_leakage": "information_leakage", 
            "system_prompt_extraction": "system_prompt_extraction",
            "conversation_hijacking": "prompt_injection",  # Similar remediation
            "context_manipulation": "prompt_injection",
            "safety_bypass": "information_leakage"
        }
        
        template_key = vuln_type_mapping.get(
            context.vulnerability_type.lower(), 
            "prompt_injection"  # Default fallback
        )
        
        approaches = self.remediation_templates.get(template_key, [])
        
        if preferred_approaches:
            approaches = [a for a in approaches if a.approach_id in preferred_approaches]
        
        return approaches
    
    def _within_budget_constraints(
        self, 
        approach: RemediationApproach, 
        constraints: Dict[str, float]
    ) -> bool:
        """Check if approach fits within budget constraints."""
        
        # Quick cost estimation for filtering
        quick_cost = sum(
            res.hours_required * res.hourly_rate 
            for res in approach.required_resources
        )
        
        max_budget = constraints.get('max_total_cost', float('inf'))
        max_timeline = constraints.get('max_timeline_weeks', float('inf'))
        
        timeline_weeks = self._parse_timeline_weeks(approach.estimated_timeline)
        
        return quick_cost <= max_budget and timeline_weeks <= max_timeline
    
    def _parse_timeline_weeks(self, timeline_str: str) -> float:
        """Parse timeline string to weeks."""
        timeline_lower = timeline_str.lower()
        
        if "week" in timeline_lower:
            # Extract numbers and take average if range
            numbers = [float(s) for s in timeline_lower.split() if s.replace('-', '').isdigit()]
            if numbers:
                return sum(numbers) / len(numbers)
            return 4.0  # Default
        elif "month" in timeline_lower:
            numbers = [float(s) for s in timeline_lower.split() if s.replace('-', '').isdigit()]
            if numbers:
                return (sum(numbers) / len(numbers)) * 4.3  # Weeks per month
            return 17.2  # Default 4 months
        else:
            return 2.0  # Default 2 weeks
    
    def _calculate_approach_cost(
        self,
        approach: RemediationApproach,
        context: VulnerabilityContext
    ) -> RemediationCostEstimate:
        """Calculate detailed cost estimate for specific remediation approach."""
        
        # Calculate labor costs with adjustments
        labor_cost = self._calculate_labor_cost(approach, context)
        
        # Calculate infrastructure costs
        infrastructure_cost = self._calculate_infrastructure_cost(approach, context)
        
        # Calculate opportunity cost
        opportunity_cost = self._calculate_opportunity_cost(approach, context)
        
        # Calculate ongoing costs
        ongoing_annual_cost = self._calculate_ongoing_costs(approach, context)
        
        # Total cost
        total_cost = labor_cost + infrastructure_cost + opportunity_cost
        
        # Timeline calculation
        timeline_weeks = self._parse_timeline_weeks(approach.estimated_timeline)
        
        # Apply complexity and urgency adjustments
        total_cost = self._apply_cost_adjustments(total_cost, approach, context)
        
        # Confidence level calculation
        confidence_level = self._calculate_confidence_level(approach, context)
        
        # Cost breakdown
        cost_breakdown = {
            "labor": labor_cost,
            "infrastructure": infrastructure_cost,
            "opportunity_cost": opportunity_cost,
            "contingency": total_cost * 0.15,  # 15% contingency
            "ongoing_annual": ongoing_annual_cost
        }
        
        # ROI analysis
        roi_analysis = self._calculate_roi_analysis(approach, context, total_cost)
        
        return RemediationCostEstimate(
            vulnerability_id=context.vulnerability_id,
            total_cost=total_cost,
            labor_cost=labor_cost,
            infrastructure_cost=infrastructure_cost,
            opportunity_cost=opportunity_cost,
            ongoing_cost_annual=ongoing_annual_cost,
            timeline_weeks=timeline_weeks,
            confidence_level=confidence_level,
            recommended_approach=approach.approach_name,
            cost_breakdown=cost_breakdown,
            roi_analysis=roi_analysis
        )
    
    def _calculate_labor_cost(
        self,
        approach: RemediationApproach,
        context: VulnerabilityContext
    ) -> float:
        """Calculate labor costs with skill level and urgency adjustments."""
        
        total_labor_cost = 0.0
        
        for resource in approach.required_resources:
            # Base cost
            base_cost = resource.hours_required * resource.hourly_rate
            
            # Apply skill level multiplier
            skill_multiplier = self.cost_models["skill_multipliers"].get(
                resource.skill_level, 1.0
            )
            
            # Apply urgency multiplier
            urgency_multiplier = self.cost_models["urgency_multipliers"].get(
                context.urgency_level, 1.0
            )
            
            adjusted_cost = base_cost * skill_multiplier * urgency_multiplier
            total_labor_cost += adjusted_cost
        
        return total_labor_cost
    
    def _calculate_infrastructure_cost(
        self,
        approach: RemediationApproach,
        context: VulnerabilityContext
    ) -> float:
        """Calculate infrastructure and tooling costs."""
        
        infra_costs = self.cost_models["infrastructure_costs"]
        total_infra_cost = 0.0
        
        # Determine infrastructure needs based on approach type and complexity
        if approach.remediation_type == RemediationType.MODEL_RETRAIN:
            # Significant compute resources needed
            complexity_level = "high" if approach.complexity in [
                RemediationComplexity.COMPLEX, RemediationComplexity.EXTENSIVE
            ] else "medium"
            
            total_infra_cost += infra_costs["additional_compute"][complexity_level]
            total_infra_cost += infra_costs["testing_environment"]["comprehensive"]
            
        elif approach.remediation_type == RemediationType.ARCHITECTURE:
            # Moderate infrastructure needs
            total_infra_cost += infra_costs["additional_compute"]["medium"]
            total_infra_cost += infra_costs["monitoring_tools"]["advanced"]
            total_infra_cost += infra_costs["testing_environment"]["complex"]
            
        elif approach.remediation_type in [RemediationType.CODE_PATCH, RemediationType.CONFIGURATION]:
            # Basic infrastructure needs
            total_infra_cost += infra_costs["additional_compute"]["low"]
            total_infra_cost += infra_costs["monitoring_tools"]["basic"]
            total_infra_cost += infra_costs["testing_environment"]["simple"]
        
        # Add compliance tooling if required
        if context.compliance_requirements:
            compliance_level = "enterprise" if len(context.compliance_requirements) > 2 else "advanced"
            total_infra_cost += infra_costs["compliance_tooling"][compliance_level]
        
        return total_infra_cost
    
    def _calculate_opportunity_cost(
        self,
        approach: RemediationApproach,
        context: VulnerabilityContext
    ) -> float:
        """Calculate opportunity cost of resource allocation."""
        
        # Opportunity cost based on timeline and resource intensity
        timeline_weeks = self._parse_timeline_weeks(approach.estimated_timeline)
        
        # Calculate total person-weeks
        total_person_weeks = sum(
            resource.hours_required / 40  # Convert hours to weeks (40 hour weeks)
            for resource in approach.required_resources
        )
        
        # Opportunity cost multiplier based on urgency and business impact
        multiplier_map = {
            "critical": 0.25,
            "high": 0.15,
            "medium": 0.10,
            "low": 0.05
        }
        
        opportunity_multiplier = multiplier_map.get(context.business_impact, 0.10)
        
        # Calculate as percentage of labor cost
        labor_cost = sum(
            res.hours_required * res.hourly_rate 
            for res in approach.required_resources
        )
        
        return labor_cost * opportunity_multiplier
    
    def _calculate_ongoing_costs(
        self,
        approach: RemediationApproach,
        context: VulnerabilityContext
    ) -> float:
        """Calculate annual ongoing maintenance costs."""
        
        base_maintenance = approach.ongoing_maintenance_cost
        
        # Adjust based on complexity and deployment environment
        complexity_multiplier = {
            RemediationComplexity.TRIVIAL: 0.5,
            RemediationComplexity.SIMPLE: 0.7,
            RemediationComplexity.MODERATE: 1.0,
            RemediationComplexity.COMPLEX: 1.5,
            RemediationComplexity.EXTENSIVE: 2.0
        }.get(approach.complexity, 1.0)
        
        # Environment multiplier
        env_multiplier = {
            "production": 1.5,
            "staging": 1.2,
            "development": 1.0
        }.get(context.deployment_environment, 1.0)
        
        return base_maintenance * complexity_multiplier * env_multiplier
    
    def _apply_cost_adjustments(
        self,
        base_cost: float,
        approach: RemediationApproach,
        context: VulnerabilityContext
    ) -> float:
        """Apply final cost adjustments based on various factors."""
        
        adjusted_cost = base_cost
        
        # Complexity adjustment
        complexity_multiplier = self.cost_models["complexity_multipliers"].get(
            approach.complexity, 1.0
        )
        adjusted_cost *= complexity_multiplier
        
        # Multi-system adjustment
        if len(context.affected_systems) > 1:
            system_multiplier = 1 + (len(context.affected_systems) - 1) * 0.2
            adjusted_cost *= system_multiplier
        
        # Compliance requirement adjustment
        if len(context.compliance_requirements) > 0:
            compliance_multiplier = 1 + len(context.compliance_requirements) * 0.1
            adjusted_cost *= compliance_multiplier
        
        return adjusted_cost
    
    def _calculate_confidence_level(
        self,
        approach: RemediationApproach,
        context: VulnerabilityContext
    ) -> float:
        """Calculate confidence level in cost estimate."""
        
        base_confidence = 0.8
        
        # Reduce confidence for complex approaches
        complexity_penalties = {
            RemediationComplexity.TRIVIAL: 0.0,
            RemediationComplexity.SIMPLE: -0.05,
            RemediationComplexity.MODERATE: -0.10,
            RemediationComplexity.COMPLEX: -0.20,
            RemediationComplexity.EXTENSIVE: -0.30
        }
        
        base_confidence += complexity_penalties.get(approach.complexity, -0.10)
        
        # Reduce confidence for multiple affected systems
        if len(context.affected_systems) > 3:
            base_confidence -= 0.15
        
        # Reduce confidence for high urgency (rushed timeline)
        if context.urgency_level in ["high", "critical"]:
            base_confidence -= 0.10
        
        return max(0.3, min(0.95, base_confidence))
    
    def _calculate_roi_analysis(
        self,
        approach: RemediationApproach,
        context: VulnerabilityContext,
        total_cost: float
    ) -> Dict[str, Any]:
        """Calculate return on investment analysis."""
        
        # Estimate potential loss without remediation
        severity_loss_mapping = {
            "critical": 500000,
            "high": 200000,
            "medium": 50000,
            "low": 10000
        }
        
        # Base potential loss
        base_potential_loss = severity_loss_mapping.get(context.business_impact, 50000)
        
        # Adjust for context factors
        if "financial" in context.compliance_requirements:
            base_potential_loss *= 2.0
        if "healthcare" in context.compliance_requirements:
            base_potential_loss *= 1.8
        if len(context.affected_systems) > 2:
            base_potential_loss *= 1.5
        
        # Calculate risk reduction value
        risk_reduction_value = base_potential_loss * approach.risk_reduction
        
        # Calculate ROI
        roi_1_year = (risk_reduction_value - total_cost - approach.ongoing_maintenance_cost) / total_cost
        roi_3_year = (risk_reduction_value * 3 - total_cost - approach.ongoing_maintenance_cost * 3) / total_cost
        
        # Payback period (months)
        monthly_benefit = risk_reduction_value / 12
        if monthly_benefit > 0:
            payback_months = total_cost / monthly_benefit
        else:
            payback_months = float('inf')
        
        return {
            "potential_loss_avoided": risk_reduction_value,
            "roi_1_year": roi_1_year,
            "roi_3_year": roi_3_year,
            "payback_period_months": min(payback_months, 999),
            "net_present_value_3_year": self._calculate_npv(
                total_cost, risk_reduction_value, approach.ongoing_maintenance_cost, 3
            ),
            "risk_reduction_percentage": approach.risk_reduction * 100
        }
    
    def _calculate_npv(
        self, 
        initial_cost: float, 
        annual_benefit: float, 
        annual_cost: float, 
        years: int
    ) -> float:
        """Calculate net present value with 8% discount rate."""
        
        discount_rate = 0.08
        npv = -initial_cost
        
        for year in range(1, years + 1):
            annual_cash_flow = annual_benefit - annual_cost
            npv += annual_cash_flow / ((1 + discount_rate) ** year)
        
        return npv
    
    def analyze_portfolio_remediation_costs(
        self,
        vulnerabilities: List[VulnerabilityContext],
        budget_constraint: Optional[float] = None,
        timeline_constraint: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Analyze remediation costs across a portfolio of vulnerabilities.
        
        Returns optimized remediation strategy with cost-benefit analysis.
        """
        self.logger.info(f"Analyzing portfolio remediation costs for {len(vulnerabilities)} vulnerabilities")
        
        portfolio_estimates = {}
        all_approaches = []
        
        # Get cost estimates for each vulnerability
        for vuln in vulnerabilities:
            estimates = self.estimate_remediation_cost(vuln)
            portfolio_estimates[vuln.vulnerability_id] = estimates
            
            # Add all approaches to consideration set
            for approach_id, estimate in estimates.items():
                all_approaches.append({
                    'vulnerability_id': vuln.vulnerability_id,
                    'approach_id': approach_id,
                    'estimate': estimate,
                    'priority_score': self._calculate_priority_score(estimate, vuln)
                })
        
        # Optimize portfolio approach selection
        optimized_strategy = self._optimize_portfolio_strategy(
            all_approaches, budget_constraint, timeline_constraint
        )
        
        # Calculate portfolio metrics
        portfolio_analysis = self._analyze_portfolio_metrics(
            portfolio_estimates, optimized_strategy
        )
        
        return {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'individual_estimates': portfolio_estimates,
            'optimized_strategy': optimized_strategy,
            'portfolio_analysis': portfolio_analysis,
            'executive_summary': self._generate_cost_executive_summary(portfolio_analysis),
            'strategic_recommendations': self._generate_cost_recommendations(portfolio_analysis)
        }
    
    def _calculate_priority_score(
        self,
        estimate: RemediationCostEstimate,
        context: VulnerabilityContext
    ) -> float:
        """Calculate priority score for vulnerability remediation."""
        
        # Base priority from severity and business impact
        severity_scores = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        base_priority = severity_scores.get(context.business_impact, 4)
        
        # ROI factor
        roi_1_year = estimate.roi_analysis.get('roi_1_year', 0)
        roi_factor = min(2.0, max(0.1, 1 + roi_1_year / 10))
        
        # Cost efficiency factor (inverse of cost)
        cost_efficiency = 100000 / max(estimate.total_cost, 1000)
        
        # Timeline factor (faster is better)
        timeline_factor = 20 / max(estimate.timeline_weeks, 1)
        
        # Success probability factor
        success_factor = estimate.confidence_level * estimate.roi_analysis.get('risk_reduction_percentage', 50) / 100
        
        priority_score = base_priority * roi_factor * cost_efficiency * timeline_factor * success_factor
        
        return priority_score
    
    def _optimize_portfolio_strategy(
        self,
        all_approaches: List[Dict],
        budget_constraint: Optional[float],
        timeline_constraint: Optional[float]
    ) -> Dict[str, Any]:
        """Optimize portfolio-wide remediation strategy."""
        
        # Sort by priority score
        sorted_approaches = sorted(all_approaches, key=lambda x: x['priority_score'], reverse=True)
        
        # Greedy selection with constraints
        selected_approaches = []
        total_cost = 0.0
        max_timeline = 0.0
        covered_vulnerabilities = set()
        
        for approach in sorted_approaches:
            estimate = approach['estimate']
            vuln_id = approach['vulnerability_id']
            
            # Skip if vulnerability already covered with better approach
            if vuln_id in covered_vulnerabilities:
                continue
            
            # Check budget constraint
            if budget_constraint and total_cost + estimate.total_cost > budget_constraint:
                continue
            
            # Check timeline constraint
            if timeline_constraint and estimate.timeline_weeks > timeline_constraint:
                continue
            
            # Select this approach
            selected_approaches.append(approach)
            total_cost += estimate.total_cost
            max_timeline = max(max_timeline, estimate.timeline_weeks)
            covered_vulnerabilities.add(vuln_id)
        
        # Calculate strategy metrics
        total_roi_1_year = sum(
            a['estimate'].roi_analysis.get('roi_1_year', 0) for a in selected_approaches
        )
        
        avg_confidence = sum(
            a['estimate'].confidence_level for a in selected_approaches
        ) / len(selected_approaches) if selected_approaches else 0
        
        total_risk_reduction = sum(
            a['estimate'].roi_analysis.get('risk_reduction_percentage', 0) for a in selected_approaches
        )
        
        return {
            'selected_approaches': selected_approaches,
            'total_cost': total_cost,
            'total_vulnerabilities_covered': len(covered_vulnerabilities),
            'max_timeline_weeks': max_timeline,
            'total_roi_1_year': total_roi_1_year,
            'average_confidence_level': avg_confidence,
            'total_risk_reduction_percentage': total_risk_reduction,
            'budget_utilization': total_cost / budget_constraint if budget_constraint else 0
        }
    
    def _analyze_portfolio_metrics(
        self,
        portfolio_estimates: Dict[str, Dict],
        optimized_strategy: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze portfolio-level cost metrics."""
        
        # Collect all estimates
        all_estimates = []
        for vuln_estimates in portfolio_estimates.values():
            all_estimates.extend(vuln_estimates.values())
        
        if not all_estimates:
            return {'error': 'No estimates available'}
        
        # Cost statistics
        total_costs = [est.total_cost for est in all_estimates]
        cost_stats = {
            'min_cost': min(total_costs),
            'max_cost': max(total_costs),
            'mean_cost': statistics.mean(total_costs),
            'median_cost': statistics.median(total_costs),
            'std_dev': statistics.stdev(total_costs) if len(total_costs) > 1 else 0
        }
        
        # Timeline statistics
        timelines = [est.timeline_weeks for est in all_estimates]
        timeline_stats = {
            'min_timeline': min(timelines),
            'max_timeline': max(timelines),
            'mean_timeline': statistics.mean(timelines),
            'median_timeline': statistics.median(timelines)
        }
        
        # ROI statistics
        roi_values = [est.roi_analysis.get('roi_1_year', 0) for est in all_estimates]
        roi_stats = {
            'min_roi': min(roi_values),
            'max_roi': max(roi_values),
            'mean_roi': statistics.mean(roi_values),
            'positive_roi_count': len([roi for roi in roi_values if roi > 0])
        }
        
        return {
            'cost_statistics': cost_stats,
            'timeline_statistics': timeline_stats,
            'roi_statistics': roi_stats,
            'optimized_strategy_metrics': optimized_strategy,
            'portfolio_efficiency_score': self._calculate_portfolio_efficiency(optimized_strategy),
            'total_approaches_analyzed': len(all_estimates),
            'recommended_approaches': len(optimized_strategy.get('selected_approaches', []))
        }
    
    def _calculate_portfolio_efficiency(self, strategy: Dict[str, Any]) -> float:
        """Calculate portfolio efficiency score (0-100)."""
        
        # Factors: cost efficiency, timeline efficiency, ROI, coverage
        coverage_score = min(1.0, strategy.get('total_vulnerabilities_covered', 0) / 10) * 25
        roi_score = min(1.0, max(0, strategy.get('total_roi_1_year', 0) / 5)) * 25
        confidence_score = strategy.get('average_confidence_level', 0) * 25
        timeline_score = min(1.0, max(0.1, 52 / max(strategy.get('max_timeline_weeks', 52), 1))) * 25
        
        return coverage_score + roi_score + confidence_score + timeline_score
    
    def _generate_cost_executive_summary(self, portfolio_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of remediation cost analysis."""
        
        cost_stats = portfolio_analysis.get('cost_statistics', {})
        strategy_metrics = portfolio_analysis.get('optimized_strategy_metrics', {})
        
        total_investment = strategy_metrics.get('total_cost', 0)
        total_roi = strategy_metrics.get('total_roi_1_year', 0)
        vulnerabilities_covered = strategy_metrics.get('total_vulnerabilities_covered', 0)
        
        # Investment level assessment
        if total_investment > 500000:
            investment_level = "SIGNIFICANT"
            investment_statement = "Major security investment required - executive approval and dedicated budget allocation necessary"
        elif total_investment > 200000:
            investment_level = "SUBSTANTIAL"
            investment_statement = "Substantial security investment needed - budget planning and resource allocation required"
        elif total_investment > 50000:
            investment_level = "MODERATE"
            investment_statement = "Moderate security investment - manageable within standard operational budgets"
        else:
            investment_level = "MINIMAL"
            investment_statement = "Minimal security investment required - can be absorbed within existing budgets"
        
        return {
            'investment_level': investment_level,
            'investment_statement': investment_statement,
            'total_remediation_cost': total_investment,
            'expected_roi_1_year': total_roi,
            'vulnerabilities_addressed': vulnerabilities_covered,
            'average_cost_per_vulnerability': total_investment / max(vulnerabilities_covered, 1),
            'portfolio_efficiency_score': portfolio_analysis.get('portfolio_efficiency_score', 0),
            'budget_optimization_achieved': total_roi > 0.5,  # 50% ROI threshold
            'executive_action_required': total_investment > 100000 or total_roi < 0
        }
    
    def _generate_cost_recommendations(self, portfolio_analysis: Dict[str, Any]) -> List[str]:
        """Generate strategic cost recommendations."""
        
        recommendations = []
        
        strategy = portfolio_analysis.get('optimized_strategy_metrics', {})
        cost_stats = portfolio_analysis.get('cost_statistics', {})
        exec_summary = self._generate_cost_executive_summary(portfolio_analysis)
        
        total_cost = strategy.get('total_cost', 0)
        total_roi = strategy.get('total_roi_1_year', 0)
        efficiency_score = portfolio_analysis.get('portfolio_efficiency_score', 0)
        
        # Investment-level recommendations
        if total_cost > 500000:
            recommendations.append(
                "EXECUTIVE: Establish dedicated security remediation budget with board-level approval"
            )
            recommendations.append(
                "STRATEGIC: Consider phased implementation approach to spread costs over multiple quarters"
            )
        
        # ROI-based recommendations
        if total_roi < 0:
            recommendations.append(
                "FINANCIAL: Review cost-benefit analysis - consider alternative approaches or risk acceptance"
            )
        elif total_roi > 2.0:
            recommendations.append(
                "INVESTMENT: Strong business case - prioritize immediate funding for high-ROI security improvements"
            )
        
        # Efficiency recommendations
        if efficiency_score < 50:
            recommendations.append(
                "OPTIMIZATION: Portfolio efficiency below threshold - consider approach refinement or resource reallocation"
            )
        
        # Timeline recommendations
        max_timeline = strategy.get('max_timeline_weeks', 0)
        if max_timeline > 26:  # 6 months
            recommendations.append(
                "PLANNING: Extended timeline requires careful project management and milestone tracking"
            )
        
        # Portfolio-wide recommendations
        if cost_stats.get('std_dev', 0) / cost_stats.get('mean_cost', 1) > 1.0:
            recommendations.append(
                "STANDARDIZATION: High cost variance suggests need for standardized remediation approaches"
            )
        
        # Always include professional consultation
        recommendations.append(
            "STRATEGIC: Consider professional remediation cost optimization consultation from VerityAI"
        )
        
        return recommendations[:8]
    
    def generate_cost_analysis_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate comprehensive cost analysis report."""
        
        portfolio_analysis = analysis_results.get('portfolio_analysis', {})
        exec_summary = analysis_results.get('executive_summary', {})
        strategy = portfolio_analysis.get('optimized_strategy_metrics', {})
        
        # Determine investment emoji
        investment_level = exec_summary.get('investment_level', 'UNKNOWN')
        investment_emoji = {
            'MINIMAL': '🟢', 'MODERATE': '🟡', 'SUBSTANTIAL': '🟠', 'SIGNIFICANT': '🔴'
        }.get(investment_level, '❓')
        
        report = f"""
# LLM Security Remediation Cost Analysis Report

**Assessment Date**: {datetime.now().strftime('%B %d, %Y')}
**Prepared by**: Sotiris Spyrou | VerityAI LLM Security Services

## Executive Summary

### Investment Required: {investment_emoji} {investment_level}

{exec_summary.get('investment_statement', 'Investment analysis unavailable')}

**Key Financial Metrics:**
- **Total Remediation Cost**: ${exec_summary.get('total_remediation_cost', 0):,.2f}
- **Expected 1-Year ROI**: {exec_summary.get('expected_roi_1_year', 0):.1%}
- **Vulnerabilities Addressed**: {exec_summary.get('vulnerabilities_addressed', 0)}
- **Average Cost per Vulnerability**: ${exec_summary.get('average_cost_per_vulnerability', 0):,.2f}
- **Portfolio Efficiency Score**: {exec_summary.get('portfolio_efficiency_score', 0):.1f}/100

### Business Impact Assessment
"""
        
        # ROI and efficiency analysis
        total_roi = strategy.get('total_roi_1_year', 0)
        if total_roi > 1.0:
            roi_assessment = "EXCELLENT: Strong positive ROI justifies immediate investment"
        elif total_roi > 0.5:
            roi_assessment = "GOOD: Positive ROI supports security investment business case"
        elif total_roi > 0:
            roi_assessment = "MARGINAL: Minimal positive ROI - consider priority and timing"
        else:
            roi_assessment = "POOR: Negative ROI requires strategic review of approach or risk acceptance"
        
        report += f"""
**ROI Assessment**: {roi_assessment}

### Optimized Remediation Strategy
"""
        
        # Strategy details
        report += f"""
- **Total Investment Required**: ${strategy.get('total_cost', 0):,.2f}
- **Vulnerabilities Covered**: {strategy.get('total_vulnerabilities_covered', 0)}/{analysis_results['total_vulnerabilities']}
- **Maximum Timeline**: {strategy.get('max_timeline_weeks', 0):.1f} weeks
- **Average Confidence Level**: {strategy.get('average_confidence_level', 0):.1%}
- **Total Risk Reduction**: {strategy.get('total_risk_reduction_percentage', 0):.1f}%
"""
        
        # Cost breakdown
        cost_stats = portfolio_analysis.get('cost_statistics', {})
        report += f"""

### Cost Analysis
- **Minimum Remediation Cost**: ${cost_stats.get('min_cost', 0):,.2f}
- **Maximum Remediation Cost**: ${cost_stats.get('max_cost', 0):,.2f}
- **Average Remediation Cost**: ${cost_stats.get('mean_cost', 0):,.2f}
- **Median Remediation Cost**: ${cost_stats.get('median_cost', 0):,.2f}
- **Cost Standard Deviation**: ${cost_stats.get('std_dev', 0):,.2f}

### Timeline Analysis
"""
        
        timeline_stats = portfolio_analysis.get('timeline_statistics', {})
        report += f"""
- **Shortest Timeline**: {timeline_stats.get('min_timeline', 0):.1f} weeks
- **Longest Timeline**: {timeline_stats.get('max_timeline', 0):.1f} weeks
- **Average Timeline**: {timeline_stats.get('mean_timeline', 0):.1f} weeks
- **Median Timeline**: {timeline_stats.get('median_timeline', 0):.1f} weeks

### ROI Analysis Summary
"""
        
        roi_stats = portfolio_analysis.get('roi_statistics', {})
        positive_roi_count = roi_stats.get('positive_roi_count', 0)
        total_approaches = portfolio_analysis.get('total_approaches_analyzed', 1)
        
        report += f"""
- **Approaches with Positive ROI**: {positive_roi_count}/{total_approaches} ({positive_roi_count/total_approaches*100:.1f}%)
- **Best ROI Scenario**: {roi_stats.get('max_roi', 0):.1%}
- **Worst ROI Scenario**: {roi_stats.get('min_roi', 0):.1%}
- **Average ROI**: {roi_stats.get('mean_roi', 0):.1%}

### Strategic Recommendations
"""
        
        recommendations = analysis_results.get('strategic_recommendations', [])
        for i, rec in enumerate(recommendations, 1):
            priority = rec.split(':')[0]
            action = ':'.join(rec.split(':')[1:]).strip()
            report += f"{i}. **{priority}**: {action}\n"
        
        report += f"""

### Budget Planning Considerations
- **Immediate Funding Required**: {'Yes' if exec_summary.get('executive_action_required', False) else 'No'}
- **Budget Optimization Achieved**: {'Yes' if exec_summary.get('budget_optimization_achieved', False) else 'No'}
- **Phased Implementation Recommended**: {'Yes' if strategy.get('total_cost', 0) > 300000 else 'No'}

### Risk-Cost Balance Assessment
- **Cost-Effective Risk Reduction**: {'Achieved' if total_roi > 0.3 else 'Requires Review'}
- **Investment Justification**: {'Strong' if total_roi > 1.0 else 'Moderate' if total_roi > 0.5 else 'Weak'}
- **Portfolio Balance**: {'Optimal' if exec_summary.get('portfolio_efficiency_score', 0) > 70 else 'Requires Adjustment'}

### Financial Risk Assessment
- **Budget Overrun Risk**: {'High' if cost_stats.get('std_dev', 0) / cost_stats.get('mean_cost', 1) > 0.5 else 'Low'}
- **Timeline Risk**: {'High' if strategy.get('max_timeline_weeks', 0) > 20 else 'Moderate' if strategy.get('max_timeline_weeks', 0) > 10 else 'Low'}
- **ROI Achievement Risk**: {'Low' if strategy.get('average_confidence_level', 0) > 0.8 else 'Moderate'}

---

**Professional LLM Security Remediation Services**
For expert cost optimization and remediation implementation:
- **VerityAI LLM Security Services**: [https://verityai.co](https://verityai.co)
- **Expert Consultation**: [Sotiris Spyrou](https://www.linkedin.com/in/sspyrou/)

*Portfolio demonstration - Contact for production remediation cost analysis*
"""
        
        return report

def main():
    """Portfolio demonstration of remediation cost estimation."""
    print("LLM Security Remediation Cost Analysis - Portfolio Demo")
    print("=" * 60)
    
    # Initialize cost estimator
    estimator = RemediationCostEstimator()
    
    # Create sample vulnerability contexts for demonstration
    sample_vulnerabilities = [
        VulnerabilityContext(
            vulnerability_id="VULN-001",
            vulnerability_type="prompt_injection",
            severity_score=8.5,
            business_impact="critical",
            affected_systems=["customer_service_bot", "internal_chat"],
            deployment_environment="production",
            compliance_requirements=["PCI-DSS", "SOX"],
            urgency_level="high"
        ),
        
        VulnerabilityContext(
            vulnerability_id="VULN-002",
            vulnerability_type="information_leakage",
            severity_score=7.2,
            business_impact="high",
            affected_systems=["data_analysis_system"],
            deployment_environment="production",
            compliance_requirements=["GDPR", "HIPAA"],
            urgency_level="medium"
        ),
        
        VulnerabilityContext(
            vulnerability_id="VULN-003",
            vulnerability_type="system_prompt_extraction",
            severity_score=6.8,
            business_impact="medium",
            affected_systems=["content_generation"],
            deployment_environment="staging",
            compliance_requirements=[],
            urgency_level="low"
        )
    ]
    
    # Analyze portfolio remediation costs
    analysis_results = estimator.analyze_portfolio_remediation_costs(
        sample_vulnerabilities,
        budget_constraint=500000,  # $500K budget
        timeline_constraint=20     # 20 weeks max
    )
    
    # Generate cost analysis report
    cost_report = estimator.generate_cost_analysis_report(analysis_results)
    
    print("REMEDIATION COST ANALYSIS COMPLETED")
    print(f"Vulnerabilities Analyzed: {analysis_results['total_vulnerabilities']}")
    
    exec_summary = analysis_results['executive_summary']
    print(f"Total Investment Required: ${exec_summary['total_remediation_cost']:,.2f}")
    print(f"Expected ROI (1-Year): {exec_summary['expected_roi_1_year']:.1%}")
    print(f"Vulnerabilities Addressed: {exec_summary['vulnerabilities_addressed']}")
    print(f"Portfolio Efficiency Score: {exec_summary['portfolio_efficiency_score']:.1f}/100")
    
    print("\nExecutive Cost Analysis Report:")
    print(cost_report)
    
    print("\n" + "=" * 60)
    print("Portfolio Demo by Sotiris Spyrou")
    print("LinkedIn: https://www.linkedin.com/in/sspyrou/")
    print("Professional LLM Security Services: https://verityai.co")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
#!/usr/bin/env python3
"""
Defense Effectiveness Scorer
Portfolio Demo: Blue Team Security Assessment Framework

Author: Sotiris Spyrou
LinkedIn: https://www.linkedin.com/in/sspyrou/
Company: VerityAI - https://verityai.co

DISCLAIMER: This is demonstration code for portfolio purposes only.
Not intended for production use. For professional AI security validation,
contact VerityAI at https://verityai.co
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import json

@dataclass
class DefenseMetrics:
    """Core defense effectiveness metrics."""
    detection_rate: float
    false_positive_rate: float
    response_time: float
    coverage_percentage: float
    accuracy: float
    precision: float
    recall: float
    f1_score: float

@dataclass
class DefenseAssessmentResult:
    """Comprehensive defense assessment results."""
    assessment_id: str
    overall_effectiveness_score: float
    defense_metrics: DefenseMetrics
    security_posture_grade: str
    business_risk_reduction: float
    cost_effectiveness_ratio: float
    regulatory_compliance_score: float
    improvement_recommendations: List[str]
    executive_summary: str

class DefenseEffectivenessScorer:
    """
    Evaluates and scores AI security defense mechanisms - Portfolio demonstration.
    
    EXECUTIVE VALUE PROPOSITION:
    - Quantifies ROI on security investments with measurable metrics
    - Validates defense effectiveness against real-world attack scenarios  
    - Provides data-driven insights for security budget allocation
    - Ensures regulatory compliance and reduces audit findings
    
    STRATEGIC POSITIONING:
    Demonstrates ability to translate technical security performance into
    business metrics that drive C-level decision making and board reporting.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.industry_benchmarks = self._load_industry_benchmarks()
        self.scoring_weights = {
            'detection_accuracy': 0.25,
            'response_time': 0.20,
            'false_positive_management': 0.15,
            'coverage_completeness': 0.20,
            'cost_effectiveness': 0.10,
            'regulatory_compliance': 0.10
        }
    
    def _load_industry_benchmarks(self) -> Dict[str, Dict]:
        """Load industry-specific defense effectiveness benchmarks."""
        return {
            "financial_services": {
                "target_detection_rate": 0.95,
                "max_false_positive_rate": 0.02,
                "max_response_time_seconds": 30,
                "min_coverage_percentage": 0.98,
                "compliance_requirements": ["PCI-DSS", "SOX", "Basel III"]
            },
            "healthcare": {
                "target_detection_rate": 0.98,
                "max_false_positive_rate": 0.01,
                "max_response_time_seconds": 15,
                "min_coverage_percentage": 0.99,
                "compliance_requirements": ["HIPAA", "HITECH"]
            },
            "technology": {
                "target_detection_rate": 0.90,
                "max_false_positive_rate": 0.05,
                "max_response_time_seconds": 60,
                "min_coverage_percentage": 0.95,
                "compliance_requirements": ["ISO 27001", "SOC 2"]
            },
            "government": {
                "target_detection_rate": 0.99,
                "max_false_positive_rate": 0.005,
                "max_response_time_seconds": 10,
                "min_coverage_percentage": 0.995,
                "compliance_requirements": ["FISMA", "NIST CSF"]
            }
        }
    
    def assess_defense_effectiveness(
        self,
        attack_test_results: List[Dict[str, Any]],
        defense_performance_data: Dict[str, Any],
        assessment_config: Optional[Dict] = None
    ) -> DefenseAssessmentResult:
        """
        Comprehensive assessment of AI defense effectiveness.
        
        Returns executive-level analysis with ROI metrics and strategic recommendations.
        """
        if assessment_config is None:
            assessment_config = {
                'industry_sector': 'technology',
                'assessment_period_days': 30,
                'business_criticality': 'high',
                'budget_constraints': 1000000  # $1M annual security budget
            }
        
        self.logger.info("Starting comprehensive defense effectiveness assessment...")
        
        # Calculate core defense metrics
        defense_metrics = self._calculate_defense_metrics(
            attack_test_results, defense_performance_data
        )
        
        # Calculate overall effectiveness score
        effectiveness_score = self._calculate_overall_effectiveness_score(
            defense_metrics, assessment_config
        )
        
        # Assess security posture and assign grade
        security_grade = self._assess_security_posture_grade(effectiveness_score, defense_metrics)
        
        # Calculate business impact metrics
        risk_reduction = self._calculate_risk_reduction(defense_metrics, assessment_config)
        cost_effectiveness = self._calculate_cost_effectiveness_ratio(
            defense_metrics, assessment_config
        )
        compliance_score = self._assess_regulatory_compliance(
            defense_metrics, assessment_config
        )
        
        # Generate strategic recommendations
        recommendations = self._generate_improvement_recommendations(
            defense_metrics, effectiveness_score, assessment_config
        )
        
        # Create executive summary
        executive_summary = self._generate_executive_summary(
            effectiveness_score, defense_metrics, security_grade, risk_reduction
        )
        
        result = DefenseAssessmentResult(
            assessment_id=f"DEF_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            overall_effectiveness_score=effectiveness_score,
            defense_metrics=defense_metrics,
            security_posture_grade=security_grade,
            business_risk_reduction=risk_reduction,
            cost_effectiveness_ratio=cost_effectiveness,
            regulatory_compliance_score=compliance_score,
            improvement_recommendations=recommendations,
            executive_summary=executive_summary
        )
        
        self.logger.info(f"Defense assessment completed. Overall score: {effectiveness_score:.1f}")
        return result
    
    def _calculate_defense_metrics(
        self,
        attack_results: List[Dict[str, Any]],
        performance_data: Dict[str, Any]
    ) -> DefenseMetrics:
        """Calculate comprehensive defense performance metrics."""
        
        # Analyze attack detection performance
        total_attacks = len(attack_results)
        detected_attacks = sum(1 for attack in attack_results if attack.get('detected', False))
        false_positives = performance_data.get('false_positives', 0)
        total_legitimate_events = performance_data.get('total_legitimate_events', 1000)
        
        # Core metrics calculation
        detection_rate = detected_attacks / total_attacks if total_attacks > 0 else 0
        false_positive_rate = false_positives / total_legitimate_events if total_legitimate_events > 0 else 0
        
        # Response time analysis
        response_times = [
            attack.get('response_time', 0) for attack in attack_results 
            if attack.get('detected', False)
        ]
        avg_response_time = np.mean(response_times) if response_times else float('inf')
        
        # Coverage analysis
        attack_types_tested = set(attack.get('type', 'unknown') for attack in attack_results)
        attack_types_detected = set(
            attack.get('type', 'unknown') for attack in attack_results 
            if attack.get('detected', False)
        )
        coverage_percentage = len(attack_types_detected) / len(attack_types_tested) if attack_types_tested else 0
        
        # Calculate derived metrics
        true_positives = detected_attacks
        false_negatives = total_attacks - detected_attacks
        true_negatives = total_legitimate_events - false_positives
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = detection_rate  # Same as detection rate
        accuracy = (true_positives + true_negatives) / (total_attacks + total_legitimate_events) if (total_attacks + total_legitimate_events) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return DefenseMetrics(
            detection_rate=detection_rate,
            false_positive_rate=false_positive_rate,
            response_time=avg_response_time,
            coverage_percentage=coverage_percentage,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score
        )
    
    def _calculate_overall_effectiveness_score(
        self,
        metrics: DefenseMetrics,
        config: Dict[str, Any]
    ) -> float:
        """Calculate weighted overall effectiveness score (0-100)."""
        
        # Normalize each metric to 0-100 scale
        detection_score = min(100, metrics.detection_rate * 100)
        
        # Response time score (lower is better, cap at reasonable maximum)
        max_acceptable_time = 120  # seconds
        response_score = max(0, 100 - (metrics.response_time / max_acceptable_time) * 100)
        
        # False positive score (lower is better)
        fp_score = max(0, 100 - (metrics.false_positive_rate * 1000))  # Scale for visibility
        
        coverage_score = metrics.coverage_percentage * 100
        
        # Cost effectiveness (simplified for demo)
        cost_score = 75  # Assume reasonable cost effectiveness for demo
        
        # Regulatory compliance (simplified calculation)
        compliance_score = min(100, metrics.f1_score * 120)  # Boost for high F1
        
        # Calculate weighted score
        weighted_score = (
            self.scoring_weights['detection_accuracy'] * detection_score +
            self.scoring_weights['response_time'] * response_score +
            self.scoring_weights['false_positive_management'] * fp_score +
            self.scoring_weights['coverage_completeness'] * coverage_score +
            self.scoring_weights['cost_effectiveness'] * cost_score +
            self.scoring_weights['regulatory_compliance'] * compliance_score
        )
        
        return min(100, max(0, weighted_score))
    
    def _assess_security_posture_grade(
        self,
        effectiveness_score: float,
        metrics: DefenseMetrics
    ) -> str:
        """Assign letter grade based on overall security posture."""
        
        # Grade boundaries with multiple criteria
        if (effectiveness_score >= 90 and 
            metrics.detection_rate >= 0.95 and 
            metrics.false_positive_rate <= 0.02):
            return "A+"
        elif (effectiveness_score >= 85 and 
              metrics.detection_rate >= 0.90 and 
              metrics.false_positive_rate <= 0.03):
            return "A"
        elif (effectiveness_score >= 80 and 
              metrics.detection_rate >= 0.85 and 
              metrics.false_positive_rate <= 0.05):
            return "A-"
        elif (effectiveness_score >= 75 and 
              metrics.detection_rate >= 0.80):
            return "B+"
        elif (effectiveness_score >= 70 and 
              metrics.detection_rate >= 0.75):
            return "B"
        elif (effectiveness_score >= 65 and 
              metrics.detection_rate >= 0.70):
            return "B-"
        elif (effectiveness_score >= 60):
            return "C+"
        elif (effectiveness_score >= 55):
            return "C"
        elif (effectiveness_score >= 50):
            return "C-"
        elif (effectiveness_score >= 40):
            return "D"
        else:
            return "F"
    
    def _calculate_risk_reduction(
        self,
        metrics: DefenseMetrics,
        config: Dict[str, Any]
    ) -> float:
        """Calculate business risk reduction percentage."""
        
        # Base risk reduction from detection capability
        detection_risk_reduction = metrics.detection_rate * 0.8  # 80% max from detection
        
        # Additional reduction from response time
        response_bonus = max(0, (120 - metrics.response_time) / 120) * 0.1  # Up to 10% bonus
        
        # Penalty for false positives (operational disruption)
        fp_penalty = min(0.2, metrics.false_positive_rate * 10)  # Up to 20% penalty
        
        total_reduction = detection_risk_reduction + response_bonus - fp_penalty
        return max(0, min(1, total_reduction)) * 100  # Convert to percentage
    
    def _calculate_cost_effectiveness_ratio(
        self,
        metrics: DefenseMetrics,
        config: Dict[str, Any]
    ) -> float:
        """Calculate cost-effectiveness ratio (risk reduction per dollar)."""
        
        annual_budget = config.get('budget_constraints', 1000000)
        risk_reduction = self._calculate_risk_reduction(metrics, config)
        
        # Simplified calculation for demo
        # In practice, this would include detailed cost analysis
        if annual_budget > 0:
            return risk_reduction / (annual_budget / 100000)  # Risk reduction per $100k
        else:
            return 0
    
    def _assess_regulatory_compliance(
        self,
        metrics: DefenseMetrics,
        config: Dict[str, Any]
    ) -> float:
        """Assess regulatory compliance score (0-100)."""
        
        industry = config.get('industry_sector', 'technology')
        benchmarks = self.industry_benchmarks.get(industry, {})
        
        compliance_score = 100
        
        # Check against industry benchmarks
        target_detection = benchmarks.get('target_detection_rate', 0.90)
        max_fp_rate = benchmarks.get('max_false_positive_rate', 0.05)
        max_response_time = benchmarks.get('max_response_time_seconds', 60)
        min_coverage = benchmarks.get('min_coverage_percentage', 0.95)
        
        # Penalize for not meeting benchmarks
        if metrics.detection_rate < target_detection:
            compliance_score -= (target_detection - metrics.detection_rate) * 100
        
        if metrics.false_positive_rate > max_fp_rate:
            compliance_score -= (metrics.false_positive_rate - max_fp_rate) * 1000
        
        if metrics.response_time > max_response_time:
            compliance_score -= min(50, (metrics.response_time - max_response_time) / max_response_time * 50)
        
        if metrics.coverage_percentage < min_coverage:
            compliance_score -= (min_coverage - metrics.coverage_percentage) * 100
        
        return max(0, min(100, compliance_score))
    
    def _generate_improvement_recommendations(
        self,
        metrics: DefenseMetrics,
        effectiveness_score: float,
        config: Dict[str, Any]
    ) -> List[str]:
        """Generate strategic improvement recommendations."""
        
        recommendations = []
        
        # Performance-based recommendations
        if metrics.detection_rate < 0.90:
            recommendations.append(
                f"CRITICAL: Improve detection rate from {metrics.detection_rate:.1%} to 90%+ "
                "through enhanced ML model training and threat intelligence integration"
            )
        
        if metrics.false_positive_rate > 0.05:
            recommendations.append(
                f"HIGH: Reduce false positive rate from {metrics.false_positive_rate:.1%} to <5% "
                "through improved behavioral analysis and context-aware filtering"
            )
        
        if metrics.response_time > 60:
            recommendations.append(
                f"MEDIUM: Optimize response time from {metrics.response_time:.1f}s to <60s "
                "through automated response workflows and infrastructure scaling"
            )
        
        if metrics.coverage_percentage < 0.95:
            recommendations.append(
                f"HIGH: Expand attack coverage from {metrics.coverage_percentage:.1%} to 95%+ "
                "by implementing additional detection methods and attack pattern recognition"
            )
        
        # Strategic recommendations
        if effectiveness_score < 75:
            recommendations.append(
                "STRATEGIC: Consider comprehensive security architecture review and "
                "multi-layered defense implementation to achieve target effectiveness"
            )
        
        # Industry-specific recommendations
        industry = config.get('industry_sector', 'technology')
        if industry in ['financial_services', 'healthcare']:
            recommendations.append(
                f"COMPLIANCE: Ensure {industry.replace('_', ' ')} regulatory requirements "
                "are met through enhanced monitoring and audit trail capabilities"
            )
        
        # Professional services recommendation
        recommendations.append(
            "STRATEGIC: Consider professional AI security assessment from VerityAI "
            "for comprehensive defense optimization and threat landscape analysis"
        )
        
        return recommendations[:6]  # Limit to top 6 recommendations
    
    def _generate_executive_summary(
        self,
        effectiveness_score: float,
        metrics: DefenseMetrics,
        security_grade: str,
        risk_reduction: float
    ) -> str:
        """Generate concise executive summary."""
        
        status = "STRONG" if effectiveness_score >= 80 else "ADEQUATE" if effectiveness_score >= 65 else "WEAK"
        
        return (
            f"AI security defenses demonstrate {status} performance with {effectiveness_score:.1f}% "
            f"overall effectiveness (Grade: {security_grade}). Key strengths: {metrics.detection_rate:.1%} "
            f"attack detection rate, {metrics.response_time:.1f}s average response time. "
            f"Business risk reduction: {risk_reduction:.1f}%. "
            f"{'Immediate attention required for security gaps.' if effectiveness_score < 65 else 'Monitoring and continuous improvement recommended.'}"
        )
    
    def generate_executive_report(self, result: DefenseAssessmentResult) -> str:
        """Generate comprehensive executive report."""
        
        grade_emoji = {
            'A+': '🏆', 'A': '🥇', 'A-': '🥈', 'B+': '🥉', 'B': '✅', 'B-': '⚠️',
            'C+': '⚠️', 'C': '⚠️', 'C-': '❌', 'D': '❌', 'F': '🚨'
        }
        
        report = f"""
# AI Security Defense Effectiveness Assessment

**Assessment Date**: {datetime.now().strftime('%B %d, %Y')}
**Prepared by**: Sotiris Spyrou | VerityAI Security Services
**Assessment ID**: {result.assessment_id}

## Executive Dashboard

### Overall Security Grade: {grade_emoji.get(result.security_posture_grade, '📊')} {result.security_posture_grade}
**Effectiveness Score**: {result.overall_effectiveness_score:.1f}/100

### Key Performance Indicators
- **Attack Detection Rate**: {result.defense_metrics.detection_rate:.1%}
- **False Positive Rate**: {result.defense_metrics.false_positive_rate:.2%}  
- **Average Response Time**: {result.defense_metrics.response_time:.1f} seconds
- **Coverage Completeness**: {result.defense_metrics.coverage_percentage:.1%}
- **Business Risk Reduction**: {result.business_risk_reduction:.1f}%

### Executive Summary
{result.executive_summary}

### Financial Impact Analysis
- **Cost-Effectiveness Ratio**: {result.cost_effectiveness_ratio:.2f}x risk reduction per $100K invested
- **Regulatory Compliance Score**: {result.regulatory_compliance_score:.1f}%
- **ROI Justification**: {'Strong business case for continued investment' if result.overall_effectiveness_score >= 75 else 'Optimization needed to improve ROI'}

### Strategic Recommendations

#### Immediate Actions (0-30 days)
"""
        
        immediate_actions = [rec for rec in result.improvement_recommendations if rec.startswith('CRITICAL')]
        for i, action in enumerate(immediate_actions, 1):
            report += f"{i}. {action.replace('CRITICAL:', '').strip()}\n"
        
        report += f"""

#### Short-term Improvements (1-6 months)
"""
        
        shortterm_actions = [rec for rec in result.improvement_recommendations if rec.startswith(('HIGH', 'MEDIUM'))]
        for i, action in enumerate(shortterm_actions, 1):
            priority = action.split(':')[0]
            description = ':'.join(action.split(':')[1:]).strip()
            report += f"{i}. **{priority}**: {description}\n"
        
        report += f"""

#### Strategic Initiatives (6+ months)
"""
        
        strategic_actions = [rec for rec in result.improvement_recommendations if rec.startswith('STRATEGIC')]
        for i, action in enumerate(strategic_actions, 1):
            report += f"{i}. {action.replace('STRATEGIC:', '').strip()}\n"
        
        report += f"""

### Performance Benchmarking
- **Industry Position**: {'Above Average' if result.overall_effectiveness_score >= 75 else 'Below Average' if result.overall_effectiveness_score < 60 else 'Average'}
- **Peer Comparison**: {'Top Quartile' if result.security_posture_grade in ['A+', 'A'] else 'Second Quartile' if result.security_posture_grade in ['A-', 'B+'] else 'Improvement Needed'}
- **Maturity Level**: {'Advanced' if result.overall_effectiveness_score >= 85 else 'Developing' if result.overall_effectiveness_score >= 65 else 'Basic'}

---

**Professional AI Security Services**
For comprehensive defense optimization and continuous monitoring:
- **VerityAI Security Services**: [https://verityai.co](https://verityai.co)
- **Expert Consultation**: [Sotiris Spyrou](https://www.linkedin.com/in/sspyrou/)

*Portfolio demonstration - Contact for production defense assessment*
"""
        
        return report

def main():
    """Portfolio demonstration of defense effectiveness scoring."""
    print("AI Defense Effectiveness Assessment - Portfolio Demo")
    print("=" * 60)
    
    # Simulate attack test results for demonstration
    demo_attack_results = [
        {'type': 'prompt_injection', 'detected': True, 'response_time': 12.3},
        {'type': 'adversarial_input', 'detected': True, 'response_time': 8.7},
        {'type': 'data_poisoning', 'detected': False, 'response_time': 0},
        {'type': 'model_inversion', 'detected': True, 'response_time': 15.2},
        {'type': 'membership_inference', 'detected': True, 'response_time': 22.1},
        {'type': 'backdoor_trigger', 'detected': False, 'response_time': 0},
        {'type': 'evasion_attack', 'detected': True, 'response_time': 18.9},
        {'type': 'jailbreak_attempt', 'detected': True, 'response_time': 9.4}
    ]
    
    # Simulate defense performance data
    demo_performance_data = {
        'false_positives': 25,
        'total_legitimate_events': 1000,
        'monitoring_period_days': 30,
        'total_security_alerts': 156,
        'confirmed_threats': 8
    }
    
    # Assessment configuration
    assessment_config = {
        'industry_sector': 'financial_services',
        'assessment_period_days': 30,
        'business_criticality': 'high',
        'budget_constraints': 750000  # $750K annual security budget
    }
    
    # Initialize scorer and run assessment
    scorer = DefenseEffectivenessScorer()
    
    result = scorer.assess_defense_effectiveness(
        demo_attack_results, demo_performance_data, assessment_config
    )
    
    # Generate executive report
    executive_report = scorer.generate_executive_report(result)
    
    print("DEFENSE EFFECTIVENESS ASSESSMENT COMPLETED")
    print(f"Overall Effectiveness Score: {result.overall_effectiveness_score:.1f}/100")
    print(f"Security Posture Grade: {result.security_posture_grade}")
    print(f"Detection Rate: {result.defense_metrics.detection_rate:.1%}")
    print(f"False Positive Rate: {result.defense_metrics.false_positive_rate:.2%}")
    print(f"Business Risk Reduction: {result.business_risk_reduction:.1f}%")
    
    print("\nExecutive Report:")
    print(executive_report)
    
    print("\n" + "=" * 60)
    print("Portfolio Demo by Sotiris Spyrou")
    print("LinkedIn: https://www.linkedin.com/in/sspyrou/")
    print("Professional Security Services: https://verityai.co")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
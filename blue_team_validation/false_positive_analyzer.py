#!/usr/bin/env python3
"""
False Positive Analyzer
Portfolio Demo: AI Security Alert Optimization and Operational Efficiency Framework

Author: Sotiris Spyrou
LinkedIn: https://www.linkedin.com/in/sspyrou/
Company: VerityAI - https://verityai.co

DISCLAIMER: This is demonstration code for portfolio purposes only.
Not intended for production use. For professional false positive analysis,
contact VerityAI at https://verityai.co
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import json
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns

@dataclass
class FalsePositivePattern:
    """False positive pattern analysis results."""
    pattern_id: str
    pattern_type: str
    frequency: int
    confidence_threshold_range: Tuple[float, float]
    common_features: List[str]
    time_distribution: Dict[str, int]
    business_impact_score: float
    suggested_tuning: Dict[str, Any]

@dataclass
class FalsePositiveAnalysis:
    """Comprehensive false positive analysis results."""
    analysis_id: str
    overall_false_positive_rate: float
    cost_per_false_positive: float
    total_operational_cost: float
    detected_patterns: List[FalsePositivePattern]
    alert_fatigue_risk: str
    tuning_recommendations: List[str]
    roi_improvement_estimate: float
    executive_summary: str

class FalsePositiveAnalyzer:
    """
    Advanced false positive analysis and optimization framework - Portfolio demonstration.
    
    EXECUTIVE VALUE PROPOSITION:
    - Reduces operational costs by optimizing security alert accuracy
    - Improves analyst productivity by eliminating noise and alert fatigue
    - Maximizes security ROI through intelligent alert tuning
    - Provides data-driven insights for security operations optimization
    
    STRATEGIC POSITIONING:
    Demonstrates sophisticated data science capabilities and deep understanding
    of security operations economics - critical for transforming security into
    a strategic business enabler rather than a cost center.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.cost_benchmarks = self._initialize_cost_benchmarks()
        self.pattern_types = [
            "threshold_sensitivity",
            "temporal_clustering",
            "feature_correlation",
            "benign_activity_patterns",
            "configuration_anomalies",
            "environmental_factors"
        ]
    
    def _initialize_cost_benchmarks(self) -> Dict[str, Dict]:
        """Initialize cost benchmarks for false positive analysis."""
        return {
            "analyst_time": {
                "junior_analyst_hourly_rate": 45,
                "senior_analyst_hourly_rate": 85,
                "minutes_per_false_positive": 8,
                "escalation_cost_multiplier": 2.5
            },
            "operational_impact": {
                "alert_fatigue_threshold": 0.15,  # 15% FP rate causes fatigue
                "productivity_loss_per_fp": 0.02,  # 2% productivity loss
                "missed_threat_cost_multiplier": 100  # Cost of missing real threats
            },
            "industry_benchmarks": {
                "acceptable_fp_rate": 0.05,  # 5% industry standard
                "excellent_fp_rate": 0.02,   # 2% best-in-class
                "critical_fp_rate": 0.20     # 20% requires immediate attention
            }
        }
    
    def analyze_false_positives(
        self,
        alert_data: List[Dict[str, Any]],
        ground_truth_labels: List[bool],
        analysis_config: Optional[Dict] = None
    ) -> FalsePositiveAnalysis:
        """
        Comprehensive false positive analysis with business impact assessment.
        
        Returns executive-level insights and optimization recommendations.
        """
        if analysis_config is None:
            analysis_config = {
                'analysis_period_days': 30,
                'team_size': 8,
                'average_analyst_rate': 65,
                'business_hours_only': True,
                'alert_volume_threshold': 100
            }
        
        self.logger.info("Starting comprehensive false positive analysis...")
        
        # Identify false positive alerts
        false_positive_alerts = self._identify_false_positives(alert_data, ground_truth_labels)
        
        # Calculate overall false positive rate
        fp_rate = len(false_positive_alerts) / len(alert_data) if len(alert_data) > 0 else 0
        
        # Analyze false positive patterns
        detected_patterns = self._detect_false_positive_patterns(false_positive_alerts)
        
        # Calculate business costs
        cost_per_fp = self._calculate_cost_per_false_positive(analysis_config)
        total_cost = len(false_positive_alerts) * cost_per_fp
        
        # Assess alert fatigue risk
        fatigue_risk = self._assess_alert_fatigue_risk(fp_rate, len(alert_data), analysis_config)
        
        # Generate tuning recommendations
        tuning_recommendations = self._generate_tuning_recommendations(
            detected_patterns, fp_rate, analysis_config
        )
        
        # Calculate ROI improvement estimate
        roi_estimate = self._calculate_roi_improvement(
            detected_patterns, total_cost, analysis_config
        )
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            fp_rate, total_cost, fatigue_risk, roi_estimate
        )
        
        analysis = FalsePositiveAnalysis(
            analysis_id=f"FPA_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            overall_false_positive_rate=fp_rate,
            cost_per_false_positive=cost_per_fp,
            total_operational_cost=total_cost,
            detected_patterns=detected_patterns,
            alert_fatigue_risk=fatigue_risk,
            tuning_recommendations=tuning_recommendations,
            roi_improvement_estimate=roi_estimate,
            executive_summary=executive_summary
        )
        
        self.logger.info(f"False positive analysis completed. FP rate: {fp_rate:.1%}")
        return analysis
    
    def _identify_false_positives(
        self,
        alert_data: List[Dict[str, Any]],
        ground_truth: List[bool]
    ) -> List[Dict[str, Any]]:
        """Identify false positive alerts from the dataset."""
        false_positives = []
        
        for i, (alert, is_true_positive) in enumerate(zip(alert_data, ground_truth)):
            if not is_true_positive:  # False positive
                alert_with_index = alert.copy()
                alert_with_index['alert_index'] = i
                alert_with_index['timestamp'] = alert.get('timestamp', datetime.now())
                false_positives.append(alert_with_index)
        
        return false_positives
    
    def _detect_false_positive_patterns(
        self,
        false_positive_alerts: List[Dict[str, Any]]
    ) -> List[FalsePositivePattern]:
        """Detect patterns in false positive alerts."""
        if not false_positive_alerts:
            return []
        
        detected_patterns = []
        
        # Pattern 1: Threshold sensitivity analysis
        threshold_pattern = self._analyze_threshold_sensitivity_patterns(false_positive_alerts)
        if threshold_pattern:
            detected_patterns.append(threshold_pattern)
        
        # Pattern 2: Temporal clustering
        temporal_pattern = self._analyze_temporal_clustering_patterns(false_positive_alerts)
        if temporal_pattern:
            detected_patterns.append(temporal_pattern)
        
        # Pattern 3: Feature correlation patterns
        feature_pattern = self._analyze_feature_correlation_patterns(false_positive_alerts)
        if feature_pattern:
            detected_patterns.append(feature_pattern)
        
        # Pattern 4: Benign activity patterns
        benign_pattern = self._analyze_benign_activity_patterns(false_positive_alerts)
        if benign_pattern:
            detected_patterns.append(benign_pattern)
        
        return detected_patterns
    
    def _analyze_threshold_sensitivity_patterns(
        self,
        fp_alerts: List[Dict[str, Any]]
    ) -> Optional[FalsePositivePattern]:
        """Analyze patterns related to detection threshold sensitivity."""
        
        # Extract confidence scores
        confidence_scores = []
        for alert in fp_alerts:
            confidence = alert.get('confidence_score', alert.get('severity', 0.5))
            if isinstance(confidence, (int, float)):
                confidence_scores.append(float(confidence))
        
        if not confidence_scores:
            return None
        
        # Analyze confidence distribution
        confidence_array = np.array(confidence_scores)
        threshold_min = np.percentile(confidence_array, 10)
        threshold_max = np.percentile(confidence_array, 90)
        
        # Count alerts in sensitive threshold ranges
        sensitive_range_count = np.sum(
            (confidence_array >= threshold_min) & (confidence_array <= threshold_max)
        )
        
        if sensitive_range_count < len(confidence_scores) * 0.3:  # Less than 30%
            return None
        
        # Identify common features in threshold-sensitive false positives
        common_features = self._extract_common_features(fp_alerts, 'threshold_sensitivity')
        
        # Calculate business impact
        business_impact = self._calculate_pattern_business_impact(
            sensitive_range_count, len(fp_alerts)
        )
        
        return FalsePositivePattern(
            pattern_id="THRESH_001",
            pattern_type="threshold_sensitivity",
            frequency=sensitive_range_count,
            confidence_threshold_range=(threshold_min, threshold_max),
            common_features=common_features,
            time_distribution=self._analyze_time_distribution(fp_alerts),
            business_impact_score=business_impact,
            suggested_tuning={
                "recommended_threshold_adjustment": threshold_max + 0.1,
                "expected_fp_reduction": min(0.4, sensitive_range_count / len(fp_alerts)),
                "confidence": 0.8
            }
        )
    
    def _analyze_temporal_clustering_patterns(
        self,
        fp_alerts: List[Dict[str, Any]]
    ) -> Optional[FalsePositivePattern]:
        """Analyze temporal clustering patterns in false positives."""
        
        # Extract timestamps
        timestamps = []
        for alert in fp_alerts:
            ts = alert.get('timestamp')
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                except:
                    ts = datetime.now()
            elif not isinstance(ts, datetime):
                ts = datetime.now()
            timestamps.append(ts)
        
        if len(timestamps) < 10:  # Need sufficient data
            return None
        
        # Convert to hour of day for clustering analysis
        hours_of_day = [ts.hour for ts in timestamps]
        hour_distribution = Counter(hours_of_day)
        
        # Identify peak hours (clusters)
        peak_threshold = np.mean(list(hour_distribution.values())) + np.std(list(hour_distribution.values()))
        peak_hours = [hour for hour, count in hour_distribution.items() if count > peak_threshold]
        
        if not peak_hours:
            return None
        
        clustered_count = sum(hour_distribution[hour] for hour in peak_hours)
        
        common_features = self._extract_common_features(fp_alerts, 'temporal_clustering')
        business_impact = self._calculate_pattern_business_impact(clustered_count, len(fp_alerts))
        
        return FalsePositivePattern(
            pattern_id="TEMP_001",
            pattern_type="temporal_clustering",
            frequency=clustered_count,
            confidence_threshold_range=(0.0, 1.0),
            common_features=common_features,
            time_distribution={str(hour): count for hour, count in hour_distribution.items()},
            business_impact_score=business_impact,
            suggested_tuning={
                "peak_hours": peak_hours,
                "recommended_time_based_thresholds": True,
                "expected_fp_reduction": min(0.3, clustered_count / len(fp_alerts))
            }
        )
    
    def _analyze_feature_correlation_patterns(
        self,
        fp_alerts: List[Dict[str, Any]]
    ) -> Optional[FalsePositivePattern]:
        """Analyze feature correlation patterns in false positives."""
        
        # Extract numerical features for correlation analysis
        feature_data = defaultdict(list)
        
        for alert in fp_alerts:
            for key, value in alert.items():
                if isinstance(value, (int, float)) and key not in ['alert_index', 'timestamp']:
                    feature_data[key].append(value)
        
        if len(feature_data) < 2:  # Need at least 2 features
            return None
        
        # Find most common feature combinations
        correlated_features = []
        for feature_name, values in feature_data.items():
            if len(values) >= len(fp_alerts) * 0.8:  # Feature present in 80%+ of FPs
                correlated_features.append(feature_name)
        
        if len(correlated_features) < 2:
            return None
        
        common_features = self._extract_common_features(fp_alerts, 'feature_correlation')
        business_impact = self._calculate_pattern_business_impact(
            len(fp_alerts), len(fp_alerts)
        )
        
        return FalsePositivePattern(
            pattern_id="FEAT_001", 
            pattern_type="feature_correlation",
            frequency=len(fp_alerts),
            confidence_threshold_range=(0.0, 1.0),
            common_features=common_features,
            time_distribution=self._analyze_time_distribution(fp_alerts),
            business_impact_score=business_impact,
            suggested_tuning={
                "correlated_features": correlated_features[:5],
                "feature_weight_adjustment": True,
                "expected_fp_reduction": 0.25
            }
        )
    
    def _analyze_benign_activity_patterns(
        self,
        fp_alerts: List[Dict[str, Any]]
    ) -> Optional[FalsePositivePattern]:
        """Analyze patterns indicating benign activity misclassification."""
        
        # Look for indicators of benign activity
        benign_indicators = [
            'scheduled_task', 'automated_backup', 'system_update',
            'maintenance_window', 'legitimate_user', 'internal_scan'
        ]
        
        benign_count = 0
        benign_features = []
        
        for alert in fp_alerts:
            alert_text = str(alert.get('description', '')).lower()
            alert_type = str(alert.get('alert_type', '')).lower()
            
            for indicator in benign_indicators:
                if indicator in alert_text or indicator in alert_type:
                    benign_count += 1
                    benign_features.append(indicator)
                    break
        
        if benign_count < len(fp_alerts) * 0.2:  # Less than 20% benign patterns
            return None
        
        common_features = list(set(benign_features))
        business_impact = self._calculate_pattern_business_impact(benign_count, len(fp_alerts))
        
        return FalsePositivePattern(
            pattern_id="BENIGN_001",
            pattern_type="benign_activity_patterns", 
            frequency=benign_count,
            confidence_threshold_range=(0.0, 1.0),
            common_features=common_features,
            time_distribution=self._analyze_time_distribution(fp_alerts),
            business_impact_score=business_impact,
            suggested_tuning={
                "whitelist_patterns": common_features,
                "context_aware_filtering": True,
                "expected_fp_reduction": min(0.5, benign_count / len(fp_alerts))
            }
        )
    
    def _extract_common_features(
        self,
        alerts: List[Dict[str, Any]],
        pattern_type: str
    ) -> List[str]:
        """Extract common features from alerts for a specific pattern type."""
        
        feature_counts = defaultdict(int)
        
        for alert in alerts:
            for key, value in alert.items():
                if key not in ['alert_index', 'timestamp']:
                    feature_key = f"{key}:{str(value)[:50]}"  # Limit string length
                    feature_counts[feature_key] += 1
        
        # Return features present in at least 30% of alerts
        threshold = max(1, len(alerts) * 0.3)
        common_features = [
            feature for feature, count in feature_counts.items()
            if count >= threshold
        ]
        
        return sorted(common_features, key=lambda x: feature_counts[x], reverse=True)[:10]
    
    def _analyze_time_distribution(self, alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze time distribution of alerts."""
        hour_distribution = defaultdict(int)
        
        for alert in alerts:
            ts = alert.get('timestamp', datetime.now())
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                except:
                    ts = datetime.now()
            elif not isinstance(ts, datetime):
                ts = datetime.now()
            
            hour = ts.hour
            hour_distribution[f"{hour:02d}:00"] += 1
        
        return dict(hour_distribution)
    
    def _calculate_pattern_business_impact(
        self,
        pattern_frequency: int,
        total_fp_count: int
    ) -> float:
        """Calculate business impact score for a pattern (0-1)."""
        
        if total_fp_count == 0:
            return 0.0
        
        # Impact based on frequency percentage and absolute numbers
        frequency_ratio = pattern_frequency / total_fp_count
        absolute_impact = min(1.0, pattern_frequency / 100)  # Scale by volume
        
        # Combined impact score
        impact_score = (frequency_ratio * 0.7) + (absolute_impact * 0.3)
        
        return min(1.0, impact_score)
    
    def _calculate_cost_per_false_positive(self, config: Dict) -> float:
        """Calculate average cost per false positive alert."""
        
        benchmarks = self.cost_benchmarks['analyst_time']
        avg_rate = config.get('average_analyst_rate', benchmarks['senior_analyst_hourly_rate'])
        minutes_per_fp = benchmarks['minutes_per_false_positive']
        
        # Base cost calculation
        base_cost = (avg_rate / 60) * minutes_per_fp
        
        # Add escalation costs (some FPs require senior review)
        escalation_probability = 0.15  # 15% of FPs get escalated
        escalation_cost = base_cost * benchmarks['escalation_cost_multiplier'] * escalation_probability
        
        return base_cost + escalation_cost
    
    def _assess_alert_fatigue_risk(
        self,
        fp_rate: float,
        total_alerts: int,
        config: Dict
    ) -> str:
        """Assess alert fatigue risk level."""
        
        fatigue_threshold = self.cost_benchmarks['operational_impact']['alert_fatigue_threshold']
        
        # Volume factor
        daily_alerts = total_alerts / config.get('analysis_period_days', 30)
        team_size = config.get('team_size', 8)
        alerts_per_analyst_per_day = daily_alerts / team_size
        
        # Risk assessment
        if fp_rate >= 0.25:  # 25%+ FP rate
            return "critical_alert_fatigue"
        elif fp_rate >= fatigue_threshold and alerts_per_analyst_per_day > 50:
            return "high_alert_fatigue_risk"
        elif fp_rate >= fatigue_threshold or alerts_per_analyst_per_day > 100:
            return "moderate_alert_fatigue_risk"
        else:
            return "low_alert_fatigue_risk"
    
    def _generate_tuning_recommendations(
        self,
        patterns: List[FalsePositivePattern],
        fp_rate: float,
        config: Dict
    ) -> List[str]:
        """Generate tuning recommendations based on detected patterns."""
        
        recommendations = []
        
        # Overall FP rate recommendations
        if fp_rate > 0.15:
            recommendations.append(
                "CRITICAL: False positive rate exceeds 15% - immediate tuning required to prevent analyst burnout"
            )
        elif fp_rate > 0.10:
            recommendations.append(
                "HIGH: False positive rate above 10% - implement precision improvements within 30 days"
            )
        elif fp_rate > 0.05:
            recommendations.append(
                "MEDIUM: False positive rate above industry benchmark - consider optimization opportunities"
            )
        
        # Pattern-specific recommendations
        for pattern in patterns:
            if pattern.pattern_type == "threshold_sensitivity":
                expected_reduction = pattern.suggested_tuning.get('expected_fp_reduction', 0)
                recommendations.append(
                    f"TECHNICAL: Adjust detection thresholds - potential {expected_reduction:.1%} FP reduction"
                )
            
            elif pattern.pattern_type == "temporal_clustering":
                peak_hours = pattern.suggested_tuning.get('peak_hours', [])
                recommendations.append(
                    f"OPERATIONAL: Implement time-based threshold adjustments for peak hours {peak_hours}"
                )
            
            elif pattern.pattern_type == "benign_activity_patterns":
                recommendations.append(
                    "STRATEGIC: Deploy context-aware filtering to distinguish benign activities"
                )
        
        # Strategic recommendations
        if len(patterns) >= 3:
            recommendations.append(
                "STRATEGIC: Multiple FP patterns detected - consider ML-based alert correlation"
            )
        
        recommendations.append(
            "STRATEGIC: Engage VerityAI for comprehensive false positive optimization"
        )
        
        return recommendations[:8]  # Limit to top 8 recommendations
    
    def _calculate_roi_improvement(
        self,
        patterns: List[FalsePositivePattern],
        total_cost: float,
        config: Dict
    ) -> float:
        """Calculate potential ROI improvement from pattern-based tuning."""
        
        if not patterns or total_cost <= 0:
            return 0.0
        
        total_potential_reduction = 0.0
        
        for pattern in patterns:
            expected_reduction = pattern.suggested_tuning.get('expected_fp_reduction', 0)
            pattern_impact = pattern.business_impact_score
            
            # Weight reduction by pattern impact and confidence
            weighted_reduction = expected_reduction * pattern_impact
            total_potential_reduction += weighted_reduction
        
        # Cap at 80% maximum improvement (realistic constraint)
        total_potential_reduction = min(0.8, total_potential_reduction)
        
        # Calculate annual cost savings
        annual_cost = total_cost * (365 / config.get('analysis_period_days', 30))
        annual_savings = annual_cost * total_potential_reduction
        
        return annual_savings
    
    def _generate_executive_summary(
        self,
        fp_rate: float,
        total_cost: float,
        fatigue_risk: str,
        roi_estimate: float
    ) -> str:
        """Generate executive summary of false positive analysis."""
        
        # Determine severity
        if fp_rate >= 0.15:
            severity = "CRITICAL"
            urgency = "immediate action required"
        elif fp_rate >= 0.10:
            severity = "HIGH"
            urgency = "urgent optimization needed"
        elif fp_rate >= 0.05:
            severity = "MEDIUM"
            urgency = "improvement opportunity identified"
        else:
            severity = "LOW"
            urgency = "monitoring recommended"
        
        annual_cost = total_cost * 12  # Assuming monthly analysis
        
        return (
            f"{severity}: False positive rate of {fp_rate:.1%} is generating "
            f"${total_cost:,.0f} monthly operational costs ({urgency}). "
            f"Alert fatigue risk: {fatigue_risk.replace('_', ' ').title()}. "
            f"Optimization opportunity: ${roi_estimate:,.0f} annual savings potential."
        )
    
    def generate_false_positive_report(
        self,
        analysis: FalsePositiveAnalysis
    ) -> str:
        """Generate comprehensive executive false positive analysis report."""
        
        # Determine performance rating
        fp_rate = analysis.overall_false_positive_rate
        if fp_rate <= 0.02:
            performance_rating = "Excellent"
        elif fp_rate <= 0.05:
            performance_rating = "Good"
        elif fp_rate <= 0.10:
            performance_rating = "Fair"
        elif fp_rate <= 0.15:
            performance_rating = "Poor"
        else:
            performance_rating = "Critical"
        
        report = f"""
# AI Security False Positive Analysis Report

**Assessment Date**: {datetime.now().strftime('%B %d, %Y')}
**Prepared by**: Sotiris Spyrou | VerityAI Security Services
**Analysis ID**: {analysis.analysis_id}

## Executive Dashboard

### Alert Quality Rating: {performance_rating}
**False Positive Rate**: {fp_rate:.1%} ({'Above Industry Benchmark' if fp_rate > 0.05 else 'Within Industry Standards'})

### Operational Cost Impact
- **Cost per False Positive**: ${analysis.cost_per_false_positive:.2f}
- **Monthly Operational Cost**: ${analysis.total_operational_cost:,.0f}
- **Annual Cost Projection**: ${analysis.total_operational_cost * 12:,.0f}
- **ROI Improvement Potential**: ${analysis.roi_improvement_estimate:,.0f} annually

### Alert Fatigue Assessment
**Risk Level**: {analysis.alert_fatigue_risk.replace('_', ' ').title()}

### Executive Summary
{analysis.executive_summary}

### Detected False Positive Patterns
"""
        
        for i, pattern in enumerate(analysis.detected_patterns, 1):
            pattern_name = pattern.pattern_type.replace('_', ' ').title()
            impact_pct = pattern.business_impact_score * 100
            expected_reduction = pattern.suggested_tuning.get('expected_fp_reduction', 0) * 100
            
            report += f"""
#### Pattern {i}: {pattern_name}
- **Frequency**: {pattern.frequency} alerts ({pattern.frequency/max(1, len(analysis.detected_patterns)) * fp_rate:.1%} of total)
- **Business Impact Score**: {impact_pct:.0f}/100
- **Optimization Potential**: {expected_reduction:.0f}% FP reduction
- **Key Features**: {', '.join(pattern.common_features[:3])}
"""
        
        report += f"""

### Optimization Recommendations

#### Immediate Actions (0-30 days)
"""
        
        immediate_actions = [rec for rec in analysis.tuning_recommendations if rec.startswith('CRITICAL')]
        for i, action in enumerate(immediate_actions, 1):
            report += f"{i}. {action.replace('CRITICAL:', '').strip()}\n"
        
        report += f"""

#### High-Priority Improvements (1-3 months)
"""
        
        high_priority_actions = [rec for rec in analysis.tuning_recommendations if rec.startswith(('HIGH', 'MEDIUM'))]
        for i, action in enumerate(high_priority_actions[:3], 1):
            priority = action.split(':')[0]
            description = ':'.join(action.split(':')[1:]).strip()
            report += f"{i}. **{priority}**: {description}\n"
        
        report += f"""

#### Strategic Initiatives (3+ months)
"""
        
        strategic_actions = [rec for rec in analysis.tuning_recommendations if rec.startswith(('OPERATIONAL', 'STRATEGIC', 'TECHNICAL'))]
        for i, action in enumerate(strategic_actions[:3], 1):
            priority = action.split(':')[0]
            description = ':'.join(action.split(':')[1:]).strip()
            report += f"{i}. **{priority}**: {description}\n"
        
        report += f"""

### Business Impact Analysis
- **Analyst Productivity Impact**: {min(25, fp_rate * 100):.0f}% efficiency loss due to false positives
- **Opportunity Cost**: ${analysis.total_operational_cost * 12:,.0f} annually that could fund {analysis.total_operational_cost * 12 / 100000:.1f} additional security initiatives
- **Alert Credibility**: {'Strong' if fp_rate <= 0.05 else 'Moderate' if fp_rate <= 0.10 else 'Compromised'}
- **Threat Detection Risk**: {'Low' if fp_rate <= 0.10 else 'Medium' if fp_rate <= 0.15 else 'High'} risk of missing real threats due to alert fatigue

### ROI Optimization Strategy
- **Short-term Savings**: ${analysis.roi_improvement_estimate * 0.3:,.0f} (30% improvement in 6 months)
- **Long-term Savings**: ${analysis.roi_improvement_estimate:,.0f} (full optimization within 18 months)
- **Investment Required**: Estimated ${analysis.roi_improvement_estimate * 0.15:,.0f} for tuning and optimization
- **Payback Period**: {'3-6 months' if analysis.roi_improvement_estimate > 50000 else '6-12 months'}

### Industry Benchmarking
- **Current Position**: {'Top Quartile' if fp_rate <= 0.02 else 'Second Quartile' if fp_rate <= 0.05 else 'Third Quartile' if fp_rate <= 0.10 else 'Bottom Quartile'}
- **Industry Average**: 5-8% false positive rate
- **Best-in-Class**: 2% false positive rate
- **Performance Gap**: {max(0, fp_rate - 0.05):.1%} above industry benchmark

---

**Professional AI Security Optimization Services**
For comprehensive false positive analysis and alert tuning:
- **VerityAI Security Services**: [https://verityai.co](https://verityai.co)
- **Expert Consultation**: [Sotiris Spyrou](https://www.linkedin.com/in/sspyrou/)

*Portfolio demonstration - Contact for production alert optimization*
"""
        
        return report

def main():
    """Portfolio demonstration of false positive analysis."""
    print("AI Security False Positive Analysis - Portfolio Demo")
    print("=" * 60)
    
    # Generate synthetic alert data for demonstration
    np.random.seed(42)
    n_alerts = 500
    
    # Simulate alert data with various features
    alert_data = []
    ground_truth = []
    
    for i in range(n_alerts):
        # Generate synthetic alert
        alert = {
            'alert_id': f"ALT_{i:04d}",
            'confidence_score': np.random.beta(3, 2),  # Skewed toward higher confidence
            'severity': np.random.choice(['low', 'medium', 'high'], p=[0.4, 0.4, 0.2]),
            'alert_type': np.random.choice([
                'anomalous_behavior', 'suspicious_login', 'data_access',
                'network_scan', 'file_modification', 'privilege_escalation'
            ]),
            'timestamp': datetime.now() - timedelta(
                days=np.random.randint(0, 30),
                hours=np.random.randint(0, 24)
            ),
            'source_ip': f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            'user_id': f"user_{np.random.randint(1, 100):03d}",
            'description': f"Suspicious activity detected in {np.random.choice(['network', 'filesystem', 'database'])}"
        }
        
        # Determine if this is a true positive or false positive
        # Simulate 12% false positive rate with some patterns
        is_false_positive = False
        
        # Pattern 1: Low confidence scores more likely to be FP
        if alert['confidence_score'] < 0.3:
            is_false_positive = np.random.random() < 0.4
        
        # Pattern 2: Certain times more likely to be FP (maintenance windows)
        if alert['timestamp'].hour in [2, 3, 4]:  # Early morning maintenance
            is_false_positive = np.random.random() < 0.3
        
        # Pattern 3: Certain alert types more prone to FP
        if alert['alert_type'] in ['anomalous_behavior', 'network_scan']:
            is_false_positive = np.random.random() < 0.2
        
        # Random FP rate for remaining alerts
        if not is_false_positive:
            is_false_positive = np.random.random() < 0.08  # 8% base FP rate
        
        alert_data.append(alert)
        ground_truth.append(not is_false_positive)  # True if true positive
    
    # Initialize analyzer
    analyzer = FalsePositiveAnalyzer()
    
    # Configure analysis
    analysis_config = {
        'analysis_period_days': 30,
        'team_size': 6,
        'average_analyst_rate': 75,
        'business_hours_only': True,
        'alert_volume_threshold': 50
    }
    
    # Perform false positive analysis
    analysis_results = analyzer.analyze_false_positives(
        alert_data, ground_truth, analysis_config
    )
    
    # Generate executive report
    executive_report = analyzer.generate_false_positive_report(analysis_results)
    
    print("FALSE POSITIVE ANALYSIS COMPLETED")
    print(f"Overall False Positive Rate: {analysis_results.overall_false_positive_rate:.1%}")
    print(f"Monthly Operational Cost: ${analysis_results.total_operational_cost:,.0f}")
    print(f"Detected Patterns: {len(analysis_results.detected_patterns)}")
    print(f"Alert Fatigue Risk: {analysis_results.alert_fatigue_risk}")
    print(f"ROI Improvement Potential: ${analysis_results.roi_improvement_estimate:,.0f}")
    
    print("\nExecutive Analysis Report:")
    print(executive_report)
    
    print("\n" + "=" * 60)
    print("Portfolio Demo by Sotiris Spyrou")
    print("LinkedIn: https://www.linkedin.com/in/sspyrou/")
    print("Professional Alert Optimization: https://verityai.co")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
#!/usr/bin/env python3
"""
Detection Accuracy Evaluator
Portfolio Demo: AI Security Detection System Performance Assessment Framework

Author: Sotiris Spyrou
LinkedIn: https://www.linkedin.com/in/sspyrou/
Company: VerityAI - https://verityai.co

DISCLAIMER: This is demonstration code for portfolio purposes only.
Not intended for production use. For professional detection accuracy testing,
contact VerityAI at https://verityai.co
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict
import json

@dataclass
class DetectionMetrics:
    """Comprehensive detection accuracy metrics."""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    true_positive_rate: float
    false_positive_rate: float
    false_negative_rate: float
    specificity: float
    matthews_correlation: float

@dataclass
class DetectionEvaluation:
    """Complete detection system evaluation results."""
    evaluation_id: str
    overall_metrics: DetectionMetrics
    threat_category_metrics: Dict[str, DetectionMetrics]
    confusion_matrix: np.ndarray
    detection_thresholds: Dict[str, float]
    performance_by_time: List[Dict]
    business_impact_assessment: str
    executive_recommendations: List[str]
    competitive_benchmark: str

class DetectionAccuracyEvaluator:
    """
    Comprehensive evaluation framework for AI security detection systems - Portfolio demonstration.
    
    EXECUTIVE VALUE PROPOSITION:
    - Quantifies detection system ROI with industry-standard metrics
    - Identifies performance gaps across different threat categories  
    - Provides data-driven optimization recommendations for security teams
    - Validates detection investments against business risk reduction
    
    STRATEGIC POSITIONING:
    Demonstrates advanced analytics capabilities and ability to translate
    complex detection performance into executive-actionable business insights.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.industry_benchmarks = self._load_industry_benchmarks()
        self.threat_categories = [
            "prompt_injection",
            "adversarial_input",
            "data_exfiltration",
            "model_poisoning",
            "jailbreak_attempts",
            "social_engineering",
            "automated_attacks",
            "privilege_escalation"
        ]
    
    def _load_industry_benchmarks(self) -> Dict[str, Dict]:
        """Load industry-specific detection accuracy benchmarks."""
        return {
            "financial_services": {
                "minimum_accuracy": 0.95,
                "target_precision": 0.98,
                "acceptable_recall": 0.92,
                "max_false_positive_rate": 0.02
            },
            "healthcare": {
                "minimum_accuracy": 0.97,
                "target_precision": 0.99,
                "acceptable_recall": 0.95,
                "max_false_positive_rate": 0.01
            },
            "technology": {
                "minimum_accuracy": 0.90,
                "target_precision": 0.93,
                "acceptable_recall": 0.88,
                "max_false_positive_rate": 0.05
            },
            "government": {
                "minimum_accuracy": 0.98,
                "target_precision": 0.99,
                "acceptable_recall": 0.97,
                "max_false_positive_rate": 0.005
            }
        }
    
    def evaluate_detection_accuracy(
        self,
        ground_truth_labels: List[int],
        predicted_labels: List[int],
        prediction_probabilities: Optional[List[float]] = None,
        threat_categories: Optional[List[str]] = None,
        evaluation_config: Optional[Dict] = None
    ) -> DetectionEvaluation:
        """
        Comprehensive detection accuracy evaluation.
        
        Returns executive-level analysis with business impact assessment.
        """
        if evaluation_config is None:
            evaluation_config = {
                'industry_sector': 'technology',
                'evaluation_period': 'monthly',
                'business_criticality': 'high',
                'include_temporal_analysis': True
            }
        
        self.logger.info("Starting comprehensive detection accuracy evaluation...")
        
        # Calculate overall detection metrics
        overall_metrics = self._calculate_detection_metrics(
            ground_truth_labels, predicted_labels, prediction_probabilities
        )
        
        # Calculate metrics by threat category
        category_metrics = {}
        if threat_categories:
            category_metrics = self._calculate_category_metrics(
                ground_truth_labels, predicted_labels, threat_categories, prediction_probabilities
            )
        
        # Generate confusion matrix
        conf_matrix = confusion_matrix(ground_truth_labels, predicted_labels)
        
        # Analyze optimal detection thresholds
        detection_thresholds = self._analyze_optimal_thresholds(
            ground_truth_labels, prediction_probabilities or predicted_labels
        )
        
        # Simulate temporal performance analysis
        temporal_performance = self._analyze_temporal_performance(
            ground_truth_labels, predicted_labels, evaluation_config
        )
        
        # Business impact assessment
        business_impact = self._assess_business_impact(overall_metrics, evaluation_config)
        
        # Generate executive recommendations
        recommendations = self._generate_executive_recommendations(
            overall_metrics, category_metrics, evaluation_config
        )
        
        # Competitive benchmarking
        benchmark_analysis = self._perform_competitive_benchmarking(
            overall_metrics, evaluation_config
        )
        
        evaluation = DetectionEvaluation(
            evaluation_id=f"EVAL_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            overall_metrics=overall_metrics,
            threat_category_metrics=category_metrics,
            confusion_matrix=conf_matrix,
            detection_thresholds=detection_thresholds,
            performance_by_time=temporal_performance,
            business_impact_assessment=business_impact,
            executive_recommendations=recommendations,
            competitive_benchmark=benchmark_analysis
        )
        
        self.logger.info(f"Detection accuracy evaluation completed. Overall accuracy: {overall_metrics.accuracy:.1%}")
        return evaluation
    
    def _calculate_detection_metrics(
        self,
        y_true: List[int],
        y_pred: List[int], 
        y_proba: Optional[List[float]] = None
    ) -> DetectionMetrics:
        """Calculate comprehensive detection performance metrics."""
        
        # Basic classification metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='binary')
        recall = recall_score(y_true, y_pred, average='binary')
        f1 = f1_score(y_true, y_pred, average='binary')
        
        # Calculate confusion matrix elements
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        
        # Derived metrics
        true_positive_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        
        # Matthews Correlation Coefficient
        mcc_numerator = (tp * tn) - (fp * fn)
        mcc_denominator = np.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        matthews_corr = mcc_numerator / mcc_denominator if mcc_denominator > 0 else 0
        
        # AUC-ROC (if probabilities available)
        auc_roc = 0.5  # Default baseline
        if y_proba is not None:
            try:
                auc_roc = roc_auc_score(y_true, y_proba)
            except ValueError:
                self.logger.warning("Could not calculate AUC-ROC, using default")
        
        return DetectionMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            auc_roc=auc_roc,
            true_positive_rate=true_positive_rate,
            false_positive_rate=false_positive_rate,
            false_negative_rate=false_negative_rate,
            specificity=specificity,
            matthews_correlation=matthews_corr
        )
    
    def _calculate_category_metrics(
        self,
        y_true: List[int],
        y_pred: List[int],
        categories: List[str],
        y_proba: Optional[List[float]] = None
    ) -> Dict[str, DetectionMetrics]:
        """Calculate detection metrics by threat category."""
        
        category_metrics = {}
        
        # Group data by category
        category_data = defaultdict(lambda: {'true': [], 'pred': [], 'proba': []})
        
        for i, category in enumerate(categories):
            if i < len(y_true) and i < len(y_pred):
                category_data[category]['true'].append(y_true[i])
                category_data[category]['pred'].append(y_pred[i])
                if y_proba and i < len(y_proba):
                    category_data[category]['proba'].append(y_proba[i])
        
        # Calculate metrics for each category
        for category, data in category_data.items():
            if len(data['true']) > 0 and len(set(data['true'])) > 1:  # Need both classes
                proba_data = data['proba'] if data['proba'] else None
                category_metrics[category] = self._calculate_detection_metrics(
                    data['true'], data['pred'], proba_data
                )
        
        return category_metrics
    
    def _analyze_optimal_thresholds(
        self,
        y_true: List[int],
        y_scores: List[float]
    ) -> Dict[str, float]:
        """Analyze optimal detection thresholds for different objectives."""
        
        thresholds = {}
        
        if not y_scores:
            return {"default": 0.5}
        
        # Convert to numpy arrays
        y_true_np = np.array(y_true)
        y_scores_np = np.array(y_scores)
        
        # Find threshold that maximizes F1-score
        best_f1 = 0
        best_threshold_f1 = 0.5
        
        # Find threshold that minimizes false positives while maintaining recall > 0.9
        best_threshold_low_fp = 0.5
        min_fp_rate = 1.0
        
        for threshold in np.arange(0.1, 1.0, 0.05):
            y_pred_thresh = (y_scores_np >= threshold).astype(int)
            
            if len(set(y_pred_thresh)) > 1:  # Need both classes for metrics
                f1 = f1_score(y_true_np, y_pred_thresh)
                
                # Track best F1
                if f1 > best_f1:
                    best_f1 = f1
                    best_threshold_f1 = threshold
                
                # Track best threshold for low FP while maintaining recall
                recall = recall_score(y_true_np, y_pred_thresh)
                if recall >= 0.9:
                    tn, fp, fn, tp = confusion_matrix(y_true_np, y_pred_thresh).ravel()
                    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
                    if fp_rate < min_fp_rate:
                        min_fp_rate = fp_rate
                        best_threshold_low_fp = threshold
        
        thresholds = {
            "optimal_f1": best_threshold_f1,
            "low_false_positive": best_threshold_low_fp,
            "conservative": 0.8,  # High precision threshold
            "aggressive": 0.3,    # High recall threshold
            "balanced": 0.5       # Default balanced threshold
        }
        
        return thresholds
    
    def _analyze_temporal_performance(
        self,
        y_true: List[int],
        y_pred: List[int],
        config: Dict
    ) -> List[Dict]:
        """Analyze detection performance over time (simulated for demo)."""
        
        # Simulate temporal performance data for demonstration
        temporal_data = []
        base_date = datetime.now() - timedelta(days=30)
        
        # Generate performance metrics for each day over the past 30 days
        for day in range(30):
            current_date = base_date + timedelta(days=day)
            
            # Simulate slight performance variations over time
            base_accuracy = np.mean([1 if y_true[i] == y_pred[i] else 0 for i in range(len(y_true))])
            daily_variation = np.random.normal(0, 0.02)  # Small random variation
            daily_accuracy = max(0.0, min(1.0, base_accuracy + daily_variation))
            
            # Simulate other metrics with similar variation
            daily_precision = max(0.0, min(1.0, precision_score(y_true, y_pred) + np.random.normal(0, 0.015)))
            daily_recall = max(0.0, min(1.0, recall_score(y_true, y_pred) + np.random.normal(0, 0.015)))
            
            temporal_data.append({
                "date": current_date.strftime("%Y-%m-%d"),
                "accuracy": daily_accuracy,
                "precision": daily_precision,
                "recall": daily_recall,
                "threat_volume": np.random.randint(50, 200),
                "detection_latency_ms": np.random.normal(150, 30)
            })
        
        return temporal_data
    
    def _assess_business_impact(self, metrics: DetectionMetrics, config: Dict) -> str:
        """Assess business impact of detection performance."""
        
        industry = config.get('industry_sector', 'technology')
        benchmarks = self.industry_benchmarks.get(industry, {})
        
        meets_accuracy = metrics.accuracy >= benchmarks.get('minimum_accuracy', 0.90)
        meets_precision = metrics.precision >= benchmarks.get('target_precision', 0.90)
        meets_recall = metrics.recall >= benchmarks.get('acceptable_recall', 0.85)
        low_false_positives = metrics.false_positive_rate <= benchmarks.get('max_false_positive_rate', 0.05)
        
        if meets_accuracy and meets_precision and meets_recall and low_false_positives:
            return "optimal_business_protection"
        elif meets_accuracy and (meets_precision or meets_recall):
            return "adequate_risk_management"
        elif meets_accuracy:
            return "baseline_security_coverage"
        else:
            return "insufficient_threat_protection"
    
    def _generate_executive_recommendations(
        self,
        overall_metrics: DetectionMetrics,
        category_metrics: Dict[str, DetectionMetrics],
        config: Dict
    ) -> List[str]:
        """Generate executive-level improvement recommendations."""
        
        recommendations = []
        
        # Overall performance recommendations
        if overall_metrics.accuracy < 0.85:
            recommendations.append(
                "CRITICAL: Detection accuracy below acceptable threshold - immediate model retraining required"
            )
        
        if overall_metrics.false_positive_rate > 0.1:
            recommendations.append(
                "HIGH: Excessive false positive rate causing operational inefficiency - implement precision tuning"
            )
        
        if overall_metrics.recall < 0.80:
            recommendations.append(
                "HIGH: Low recall indicates missed threats - enhance detection sensitivity and coverage"
            )
        
        # Category-specific recommendations
        worst_categories = []
        for category, metrics in category_metrics.items():
            if metrics.f1_score < 0.70:
                worst_categories.append(category)
        
        if worst_categories:
            recommendations.append(
                f"MEDIUM: Focus improvement efforts on {', '.join(worst_categories)} detection categories"
            )
        
        # Strategic recommendations based on industry
        industry = config.get('industry_sector', 'technology')
        if industry in ['financial_services', 'healthcare']:
            recommendations.append(
                "STRATEGIC: Consider regulatory compliance impact of detection gaps - engage legal review"
            )
        
        # Performance optimization recommendations
        if overall_metrics.matthews_correlation < 0.6:
            recommendations.append(
                "TECHNICAL: Low Matthews correlation indicates class imbalance - implement data augmentation"
            )
        
        recommendations.append(
            "STRATEGIC: Consider professional detection optimization services from VerityAI"
        )
        
        return recommendations[:6]  # Limit to top 6 recommendations
    
    def _perform_competitive_benchmarking(
        self,
        metrics: DetectionMetrics,
        config: Dict
    ) -> str:
        """Perform competitive benchmarking analysis."""
        
        industry = config.get('industry_sector', 'technology')
        benchmarks = self.industry_benchmarks.get(industry, {})
        
        accuracy_vs_benchmark = metrics.accuracy / benchmarks.get('minimum_accuracy', 0.90)
        precision_vs_benchmark = metrics.precision / benchmarks.get('target_precision', 0.90)
        
        if accuracy_vs_benchmark >= 1.05 and precision_vs_benchmark >= 1.03:
            return "industry_leading_performance"
        elif accuracy_vs_benchmark >= 1.00 and precision_vs_benchmark >= 1.00:
            return "above_industry_average"
        elif accuracy_vs_benchmark >= 0.95:
            return "industry_standard_performance"
        else:
            return "below_industry_benchmarks"
    
    def generate_detection_assessment_report(
        self,
        evaluation: DetectionEvaluation
    ) -> str:
        """Generate comprehensive executive detection assessment report."""
        
        metrics = evaluation.overall_metrics
        
        # Performance grade calculation
        if metrics.f1_score >= 0.95:
            performance_grade = "A+"
        elif metrics.f1_score >= 0.90:
            performance_grade = "A"
        elif metrics.f1_score >= 0.85:
            performance_grade = "B+"
        elif metrics.f1_score >= 0.80:
            performance_grade = "B"
        elif metrics.f1_score >= 0.70:
            performance_grade = "C"
        else:
            performance_grade = "D"
        
        # Calculate threat detection summary
        total_threats = evaluation.confusion_matrix.sum()
        detected_threats = evaluation.confusion_matrix[1, 1]  # True positives
        missed_threats = evaluation.confusion_matrix[1, 0]    # False negatives
        
        report = f"""
# AI Security Detection Accuracy Assessment Report

**Assessment Date**: {datetime.now().strftime('%B %d, %Y')}
**Prepared by**: Sotiris Spyrou | VerityAI Security Services  
**Evaluation ID**: {evaluation.evaluation_id}

## Executive Dashboard

### Detection Performance Grade: {performance_grade}
**Overall System Effectiveness**: {metrics.f1_score:.1%} F1-Score

### Key Performance Indicators
- **Detection Accuracy**: {metrics.accuracy:.1%}
- **Precision (True Positive Rate)**: {metrics.precision:.1%}
- **Recall (Threat Coverage)**: {metrics.recall:.1%}
- **False Positive Rate**: {metrics.false_positive_rate:.2%}
- **AUC-ROC Score**: {metrics.auc_roc:.3f}

### Threat Detection Summary
- **Total Threats Processed**: {total_threats:,}
- **Successfully Detected**: {detected_threats:,} threats
- **Missed Threats**: {missed_threats:,} ({metrics.false_negative_rate:.1%} miss rate)
- **False Alarms**: {evaluation.confusion_matrix[0, 1]:,} ({metrics.false_positive_rate:.1%} false positive rate)

### Business Impact Assessment
**Security Posture**: {evaluation.business_impact_assessment.replace('_', ' ').title()}
**Competitive Position**: {evaluation.competitive_benchmark.replace('_', ' ').title()}

### Performance by Threat Category
"""
        
        for category, cat_metrics in evaluation.threat_category_metrics.items():
            category_name = category.replace('_', ' ').title()
            report += f"- **{category_name}**: {cat_metrics.f1_score:.1%} effectiveness ({cat_metrics.precision:.1%} precision, {cat_metrics.recall:.1%} recall)\n"
        
        report += f"""

### Detection Threshold Recommendations
- **Balanced Operations**: {evaluation.detection_thresholds.get('balanced', 0.5):.2f} threshold
- **Maximum Precision**: {evaluation.detection_thresholds.get('conservative', 0.8):.2f} threshold  
- **Maximum Coverage**: {evaluation.detection_thresholds.get('aggressive', 0.3):.2f} threshold
- **Optimal F1-Score**: {evaluation.detection_thresholds.get('optimal_f1', 0.5):.2f} threshold

### Executive Action Items

#### Immediate Priorities (0-30 days)
"""
        
        immediate_actions = [rec for rec in evaluation.executive_recommendations if rec.startswith('CRITICAL')]
        for i, action in enumerate(immediate_actions, 1):
            report += f"{i}. {action.replace('CRITICAL:', '').strip()}\n"
        
        report += f"""

#### High-Impact Improvements (1-6 months)
"""
        
        high_impact_actions = [rec for rec in evaluation.executive_recommendations if rec.startswith(('HIGH', 'MEDIUM'))]
        for i, action in enumerate(high_impact_actions[:3], 1):
            priority = action.split(':')[0]
            description = ':'.join(action.split(':')[1:]).strip()
            report += f"{i}. **{priority}**: {description}\n"
        
        report += f"""

### Strategic Recommendations
"""
        
        strategic_actions = [rec for rec in evaluation.executive_recommendations if rec.startswith(('STRATEGIC', 'TECHNICAL'))]
        for i, action in enumerate(strategic_actions[:3], 1):
            priority = action.split(':')[0]  
            description = ':'.join(action.split(':')[1:]).strip()
            report += f"{i}. **{priority}**: {description}\n"
        
        report += f"""

### ROI Analysis
- **Detection Investment Efficiency**: {'High ROI' if metrics.f1_score >= 0.85 else 'Moderate ROI' if metrics.f1_score >= 0.70 else 'Optimization Needed'}
- **Operational Cost Impact**: {'Optimized' if metrics.false_positive_rate <= 0.03 else 'Needs Tuning'}
- **Risk Reduction Value**: {metrics.recall:.1%} of threats successfully intercepted
- **Business Continuity**: {'Strong' if metrics.false_positive_rate <= 0.05 else 'Moderate' if metrics.false_positive_rate <= 0.10 else 'Concerning'}

### Temporal Performance Trend
"""
        
        if evaluation.performance_by_time:
            recent_accuracy = np.mean([day['accuracy'] for day in evaluation.performance_by_time[-7:]])
            trend = "improving" if recent_accuracy > metrics.accuracy else "stable" if abs(recent_accuracy - metrics.accuracy) < 0.02 else "declining"
            avg_latency = np.mean([day['detection_latency_ms'] for day in evaluation.performance_by_time])
            
            report += f"- **7-Day Performance Trend**: {trend.title()}\n"
            report += f"- **Average Detection Latency**: {avg_latency:.1f}ms\n"
            report += f"- **Daily Threat Volume**: {np.mean([day['threat_volume'] for day in evaluation.performance_by_time]):.0f} average\n"
        
        report += f"""

---

**Professional AI Detection Services**
For comprehensive detection optimization and continuous improvement:
- **VerityAI Security Services**: [https://verityai.co](https://verityai.co)
- **Expert Consultation**: [Sotiris Spyrou](https://www.linkedin.com/in/sspyrou/)

*Portfolio demonstration - Contact for production detection assessment*
"""
        
        return report

def main():
    """Portfolio demonstration of detection accuracy evaluation."""
    print("AI Detection Accuracy Assessment - Portfolio Demo")
    print("=" * 60)
    
    # Generate synthetic test data for demonstration
    np.random.seed(42)
    n_samples = 1000
    
    # Simulate ground truth labels (0 = benign, 1 = threat)
    threat_ratio = 0.15  # 15% threats, 85% benign
    ground_truth = np.random.choice([0, 1], size=n_samples, p=[1-threat_ratio, threat_ratio])
    
    # Simulate detection system predictions (with some accuracy)
    detection_accuracy = 0.87  # 87% base accuracy
    predictions = []
    probabilities = []
    
    for true_label in ground_truth:
        if true_label == 1:  # Actual threat
            # 87% chance of correct detection
            pred = 1 if np.random.random() < detection_accuracy else 0
            prob = np.random.beta(7, 2) if pred == 1 else np.random.beta(2, 5)
        else:  # Actual benign
            # 95% chance of correct classification (low false positive rate)
            pred = 0 if np.random.random() < 0.95 else 1
            prob = np.random.beta(2, 7) if pred == 0 else np.random.beta(4, 3)
        
        predictions.append(pred)
        probabilities.append(prob)
    
    # Generate threat categories for samples
    threat_categories = np.random.choice(
        ["prompt_injection", "adversarial_input", "data_exfiltration", "jailbreak_attempts"],
        size=n_samples
    )
    
    # Initialize evaluator
    evaluator = DetectionAccuracyEvaluator()
    
    # Perform comprehensive evaluation
    evaluation_config = {
        'industry_sector': 'financial_services',
        'evaluation_period': 'monthly', 
        'business_criticality': 'high',
        'include_temporal_analysis': True
    }
    
    evaluation_results = evaluator.evaluate_detection_accuracy(
        ground_truth_labels=ground_truth.tolist(),
        predicted_labels=predictions,
        prediction_probabilities=probabilities,
        threat_categories=threat_categories.tolist(),
        evaluation_config=evaluation_config
    )
    
    # Generate assessment report
    assessment_report = evaluator.generate_detection_assessment_report(evaluation_results)
    
    print("DETECTION ACCURACY EVALUATION COMPLETED")
    print(f"Overall Accuracy: {evaluation_results.overall_metrics.accuracy:.1%}")
    print(f"Precision: {evaluation_results.overall_metrics.precision:.1%}")
    print(f"Recall: {evaluation_results.overall_metrics.recall:.1%}")
    print(f"F1-Score: {evaluation_results.overall_metrics.f1_score:.1%}")
    print(f"AUC-ROC: {evaluation_results.overall_metrics.auc_roc:.3f}")
    
    print("\nExecutive Assessment Report:")
    print(assessment_report)
    
    print("\n" + "=" * 60)
    print("Portfolio Demo by Sotiris Spyrou")
    print("LinkedIn: https://www.linkedin.com/in/sspyrou/")
    print("Professional Detection Services: https://verityai.co")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
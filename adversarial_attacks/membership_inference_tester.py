#!/usr/bin/env python3
"""
Membership Inference Attack Tester
Portfolio Demo: Privacy Risk Assessment for AI Models

Author: Sotiris Spyrou
LinkedIn: https://www.linkedin.com/in/sspyrou/
Company: VerityAI - https://verityai.co

DISCLAIMER: This is demonstration code for portfolio purposes only.
Not intended for production use. For professional AI privacy assessment,
contact VerityAI at https://verityai.co
"""

import numpy as np
import torch
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple, Any
import logging
from dataclasses import dataclass
from datetime import datetime
from sklearn.metrics import roc_auc_score, accuracy_score
from sklearn.ensemble import RandomForestClassifier

@dataclass
class MembershipInferenceResult:
    """Results from membership inference attack testing."""
    model_id: str
    attack_accuracy: float
    attack_auc: float
    privacy_risk_level: str
    vulnerable_data_points: int
    confidence_threshold: float
    business_impact: str
    regulatory_risk: str
    mitigation_recommendations: List[str]

class MembershipInferenceTester:
    """
    Tests AI models for membership inference vulnerabilities - Portfolio demonstration.
    
    EXECUTIVE VALUE PROPOSITION:
    - Protects customer privacy and prevents data exposure
    - Ensures GDPR/CCPA compliance and reduces regulatory fines
    - Identifies models that leak sensitive training data information
    - Enables privacy-preserving AI deployment strategies
    
    STRATEGIC POSITIONING:
    Demonstrates expertise in AI privacy, regulatory compliance,
    and sophisticated attack methodologies - critical for C-suite confidence.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.attack_models = {}
        
    def test_membership_inference(
        self,
        target_model,
        member_data: torch.utils.data.DataLoader,
        non_member_data: torch.utils.data.DataLoader,
        test_config: Optional[Dict] = None
    ) -> MembershipInferenceResult:
        """
        Comprehensive membership inference attack testing.
        
        Returns executive-level privacy risk assessment.
        """
        if test_config is None:
            test_config = {
                'attack_methods': ['confidence_based', 'loss_based', 'combined'],
                'sample_size': 1000,
                'privacy_threshold': 0.6
            }
        
        self.logger.info("Starting membership inference attack testing...")
        
        # Collect model outputs for members and non-members
        member_features, member_labels = self._extract_attack_features(
            target_model, member_data, is_member=True, 
            sample_size=test_config.get('sample_size', 1000)
        )
        
        non_member_features, non_member_labels = self._extract_attack_features(
            target_model, non_member_data, is_member=False,
            sample_size=test_config.get('sample_size', 1000)
        )
        
        # Combine features for attack model training
        all_features = np.vstack([member_features, non_member_features])
        all_membership_labels = np.concatenate([
            np.ones(len(member_features)), 
            np.zeros(len(non_member_features))
        ])
        
        # Train and evaluate membership inference attack model
        attack_results = self._train_attack_model(all_features, all_membership_labels)
        
        # Assess privacy risk and business impact
        privacy_risk = self._assess_privacy_risk(attack_results)
        business_impact = self._assess_business_impact(privacy_risk, attack_results)
        regulatory_risk = self._assess_regulatory_risk(privacy_risk)
        
        # Generate mitigation recommendations
        mitigation_steps = self._generate_mitigation_recommendations(
            privacy_risk, attack_results
        )
        
        result = MembershipInferenceResult(
            model_id=f"model_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            attack_accuracy=attack_results['accuracy'],
            attack_auc=attack_results['auc'],
            privacy_risk_level=privacy_risk,
            vulnerable_data_points=self._count_vulnerable_points(
                all_features, all_membership_labels, attack_results['model']
            ),
            confidence_threshold=0.8,
            business_impact=business_impact,
            regulatory_risk=regulatory_risk,
            mitigation_recommendations=mitigation_steps
        )
        
        self.logger.info(f"Membership inference test completed. Privacy risk: {privacy_risk}")
        return result
    
    def _extract_attack_features(
        self, 
        model, 
        data_loader: torch.utils.data.DataLoader, 
        is_member: bool,
        sample_size: int = 1000
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Extract features for membership inference attack."""
        model.eval()
        
        confidence_scores = []
        loss_values = []
        prediction_entropies = []
        labels = []
        
        sample_count = 0
        
        with torch.no_grad():
            for batch_data, batch_labels in data_loader:
                if sample_count >= sample_size:
                    break
                
                # Get model predictions
                outputs = model(batch_data)
                probabilities = F.softmax(outputs, dim=1)
                
                # Extract attack features
                for i, (prob, label) in enumerate(zip(probabilities, batch_labels)):
                    if sample_count >= sample_size:
                        break
                        
                    # Confidence (max probability)
                    max_confidence = prob.max().item()
                    confidence_scores.append(max_confidence)
                    
                    # Loss value
                    loss = F.cross_entropy(outputs[i:i+1], batch_labels[i:i+1]).item()
                    loss_values.append(loss)
                    
                    # Prediction entropy
                    entropy = -torch.sum(prob * torch.log(prob + 1e-8)).item()
                    prediction_entropies.append(entropy)
                    
                    labels.append(label.item())
                    sample_count += 1
        
        # Combine features for attack model
        features = np.column_stack([
            confidence_scores,
            loss_values,
            prediction_entropies
        ])
        
        return features, np.array(labels)
    
    def _train_attack_model(
        self, 
        features: np.ndarray, 
        membership_labels: np.ndarray
    ) -> Dict[str, Any]:
        """Train membership inference attack model."""
        # Split data for training and testing the attack
        split_idx = len(features) // 2
        
        train_features = features[:split_idx]
        train_labels = membership_labels[:split_idx]
        test_features = features[split_idx:]
        test_labels = membership_labels[split_idx:]
        
        # Train attack model (Random Forest for robustness)
        attack_model = RandomForestClassifier(
            n_estimators=100, 
            max_depth=10, 
            random_state=42
        )
        attack_model.fit(train_features, train_labels)
        
        # Evaluate attack performance
        predictions = attack_model.predict(test_features)
        prediction_probs = attack_model.predict_proba(test_features)[:, 1]
        
        accuracy = accuracy_score(test_labels, predictions)
        auc = roc_auc_score(test_labels, prediction_probs)
        
        return {
            'model': attack_model,
            'accuracy': accuracy,
            'auc': auc,
            'feature_importance': attack_model.feature_importances_,
            'test_features': test_features,
            'test_labels': test_labels,
            'predictions': predictions,
            'prediction_probs': prediction_probs
        }
    
    def _assess_privacy_risk(self, attack_results: Dict[str, Any]) -> str:
        """Assess overall privacy risk level."""
        auc = attack_results['auc']
        accuracy = attack_results['accuracy']
        
        # Risk assessment based on attack performance
        if auc > 0.8 and accuracy > 0.75:
            return "critical"
        elif auc > 0.7 and accuracy > 0.65:
            return "high" 
        elif auc > 0.6 and accuracy > 0.55:
            return "medium"
        else:
            return "low"
    
    def _assess_business_impact(
        self, 
        privacy_risk: str, 
        attack_results: Dict[str, Any]
    ) -> str:
        """Assess business impact of privacy vulnerabilities."""
        if privacy_risk == "critical":
            return "severe_data_breach_risk"
        elif privacy_risk == "high":
            return "regulatory_compliance_violation"
        elif privacy_risk == "medium":
            return "moderate_privacy_concern"
        else:
            return "minimal_business_impact"
    
    def _assess_regulatory_risk(self, privacy_risk: str) -> str:
        """Assess regulatory compliance risks."""
        risk_mapping = {
            "critical": "GDPR/CCPA violation likely - potential €20M+ fines",
            "high": "Regulatory investigation probable - significant penalties",
            "medium": "Compliance review recommended - moderate exposure",
            "low": "Standard privacy practices sufficient"
        }
        return risk_mapping.get(privacy_risk, "Unknown risk level")
    
    def _count_vulnerable_points(
        self, 
        features: np.ndarray, 
        labels: np.ndarray, 
        attack_model
    ) -> int:
        """Count data points vulnerable to membership inference."""
        predictions = attack_model.predict_proba(features)[:, 1]
        # Count points with high inference confidence
        vulnerable_count = np.sum(predictions > 0.8)
        return int(vulnerable_count)
    
    def _generate_mitigation_recommendations(
        self, 
        privacy_risk: str, 
        attack_results: Dict[str, Any]
    ) -> List[str]:
        """Generate executive-level privacy protection recommendations."""
        recommendations = []
        
        if privacy_risk in ["critical", "high"]:
            recommendations.extend([
                "IMMEDIATE: Implement differential privacy mechanisms",
                "URGENT: Retrain model with privacy-preserving techniques",
                "STRATEGIC: Deploy federated learning architecture",
                "COMPLIANCE: Conduct privacy impact assessment (PIA)"
            ])
        elif privacy_risk == "medium":
            recommendations.extend([
                "RECOMMENDED: Apply membership inference defenses",
                "TACTICAL: Implement output perturbation techniques",
                "MONITORING: Deploy privacy leak detection systems"
            ])
        else:
            recommendations.extend([
                "PREVENTIVE: Maintain current privacy protection measures",
                "MONITORING: Regular membership inference testing"
            ])
        
        # Feature-specific recommendations
        feature_importance = attack_results.get('feature_importance', [])
        if len(feature_importance) >= 3:
            if feature_importance[0] > 0.5:  # Confidence-based attack
                recommendations.append("TECHNICAL: Implement confidence calibration")
            if feature_importance[1] > 0.5:  # Loss-based attack
                recommendations.append("TECHNICAL: Apply gradient noise injection")
            if feature_importance[2] > 0.5:  # Entropy-based attack
                recommendations.append("TECHNICAL: Implement prediction smoothing")
        
        recommendations.append("STRATEGIC: Engage VerityAI for comprehensive privacy audit")
        
        return recommendations
    
    def generate_executive_report(self, result: MembershipInferenceResult) -> str:
        """Generate executive-ready privacy risk report."""
        
        risk_indicator = {
            'critical': '🔴 CRITICAL',
            'high': '🟡 HIGH',
            'medium': '🟨 MEDIUM',
            'low': '🟢 LOW'
        }[result.privacy_risk_level]
        
        report = f"""
# AI Model Privacy Risk Assessment Report

**Assessment Date**: {datetime.now().strftime('%B %d, %Y')}
**Prepared by**: Sotiris Spyrou | VerityAI Privacy Services
**Model ID**: {result.model_id}

## Executive Summary

### Privacy Risk Status
- **Overall Risk Level**: {risk_indicator}
- **Attack Success Rate**: {result.attack_accuracy:.1%}
- **Privacy Leak Confidence**: {result.attack_auc:.1%}
- **Vulnerable Data Points**: {result.vulnerable_data_points:,}

### Business Impact Analysis
**Primary Concern**: {result.business_impact.replace('_', ' ').title()}

### Regulatory Compliance Risk
{result.regulatory_risk}

### Immediate Action Items
"""
        
        for i, recommendation in enumerate(result.mitigation_recommendations[:3], 1):
            if ":" in recommendation:
                priority, action = recommendation.split(":", 1)
                report += f"{i}. **{priority.strip()}**: {action.strip()}\n"
            else:
                report += f"{i}. {recommendation}\n"
        
        report += f"""

### Privacy Protection Strategy
{
'CRITICAL: Immediate privacy remediation required to prevent data breach' if result.privacy_risk_level == 'critical' else
'HIGH: Urgent privacy enhancements needed for regulatory compliance' if result.privacy_risk_level == 'high' else
'MEDIUM: Implement privacy safeguards as part of next development cycle' if result.privacy_risk_level == 'medium' else
'LOW: Maintain current privacy practices with regular monitoring'
}

### Key Performance Indicators
- **Attack Accuracy Threshold**: 50% (Random Baseline)
- **Current Attack Accuracy**: {result.attack_accuracy:.1%}
- **Privacy Risk Threshold**: {result.confidence_threshold:.0%}
- **Recommended Action**: {'Immediate remediation' if result.attack_accuracy > 0.7 else 'Enhanced monitoring' if result.attack_accuracy > 0.6 else 'Standard practices'}

---

**Professional AI Privacy Services**
For comprehensive privacy risk assessment and GDPR compliance:
- **VerityAI Privacy Services**: [https://verityai.co](https://verityai.co)
- **Expert Consultation**: [Sotiris Spyrou](https://www.linkedin.com/in/sspyrou/)

*Portfolio demonstration - Contact for production privacy testing*
"""
        
        return report

def main():
    """Portfolio demonstration of membership inference testing."""
    print("AI Model Privacy Risk Assessment - Portfolio Demo")
    print("=" * 60)
    
    # Simulate model for demonstration
    class DemoModel(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.layers = torch.nn.Sequential(
                torch.nn.Linear(10, 50),
                torch.nn.ReLU(),
                torch.nn.Linear(50, 20),
                torch.nn.ReLU(),
                torch.nn.Linear(20, 5)
            )
            
        def forward(self, x):
            return self.layers(x)
    
    # Create demo model and synthetic data
    model = DemoModel()
    
    # Generate synthetic member data (training data simulation)
    member_data = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(
            torch.randn(500, 10),  # Features
            torch.randint(0, 5, (500,))  # Labels
        ),
        batch_size=32,
        shuffle=False
    )
    
    # Generate synthetic non-member data (unseen data simulation)
    non_member_data = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(
            torch.randn(500, 10),  # Features
            torch.randint(0, 5, (500,))  # Labels
        ),
        batch_size=32,
        shuffle=False
    )
    
    # Initialize tester and run assessment
    tester = MembershipInferenceTester()
    
    test_config = {
        'attack_methods': ['confidence_based', 'loss_based'],
        'sample_size': 200,  # Reduced for demo
        'privacy_threshold': 0.6
    }
    
    result = tester.test_membership_inference(
        model, member_data, non_member_data, test_config
    )
    
    # Generate executive report
    executive_report = tester.generate_executive_report(result)
    
    print("PRIVACY RISK ASSESSMENT COMPLETED")
    print(f"Attack Accuracy: {result.attack_accuracy:.1%}")
    print(f"Privacy Risk Level: {result.privacy_risk_level.upper()}")
    print(f"Vulnerable Data Points: {result.vulnerable_data_points:,}")
    print(f"Business Impact: {result.business_impact}")
    
    print("\nExecutive Report:")
    print(executive_report)
    
    print("\n" + "=" * 60)
    print("Portfolio Demo by Sotiris Spyrou")
    print("LinkedIn: https://www.linkedin.com/in/sspyrou/")
    print("Professional Privacy Services: https://verityai.co")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
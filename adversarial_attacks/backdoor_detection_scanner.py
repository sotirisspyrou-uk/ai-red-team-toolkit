#!/usr/bin/env python3
"""
Backdoor Detection Scanner
Portfolio Demo: AI Security Framework

Author: Sotiris Spyrou
LinkedIn: https://www.linkedin.com/in/sspyrou/
Company: VerityAI - https://verityai.co

DISCLAIMER: This is demonstration code for portfolio purposes.
For production AI security testing, contact VerityAI.
"""

import numpy as np
import torch
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple, Any
import logging
from dataclasses import dataclass
from datetime import datetime
import json

@dataclass
class BackdoorScanResult:
    """Results from backdoor detection scan."""
    model_id: str
    backdoor_detected: bool
    confidence_score: float
    trigger_patterns: List[str]
    affected_classes: List[int]
    detection_method: str
    anomaly_score: float
    business_risk: str
    mitigation_steps: List[str]

class BackdoorDetectionScanner:
    """
    Advanced backdoor detection for AI models - Portfolio demonstration.
    
    EXECUTIVE VALUE PROPOSITION:
    - Protects against supply chain attacks on AI models
    - Prevents malicious model behavior in production
    - Ensures AI system integrity and trustworthiness
    - Reduces regulatory and compliance risks
    
    TECHNICAL LEADERSHIP SHOWCASE:
    Demonstrates deep understanding of AI security threats and 
    ability to implement sophisticated detection algorithms.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.detection_methods = {
            'activation_clustering': self._activation_clustering_detection,
            'neural_cleanse': self._neural_cleanse_detection,
            'strip_defense': self._strip_detection,
            'spectral_signature': self._spectral_signature_detection
        }
        
    def scan_model_for_backdoors(
        self,
        model,
        test_data: torch.utils.data.DataLoader,
        scan_config: Optional[Dict] = None
    ) -> BackdoorScanResult:
        """
        Comprehensive backdoor detection scan for AI models.
        
        Returns executive-level analysis with technical details.
        """
        if scan_config is None:
            scan_config = {
                'methods': ['activation_clustering', 'neural_cleanse'],
                'confidence_threshold': 0.7,
                'sample_size': 1000
            }
        
        self.logger.info("Starting comprehensive backdoor detection scan...")
        
        detection_results = {}
        overall_confidence = 0.0
        
        # Run multiple detection methods for robust analysis
        for method_name in scan_config['methods']:
            if method_name in self.detection_methods:
                method_result = self.detection_methods[method_name](
                    model, test_data, scan_config
                )
                detection_results[method_name] = method_result
                overall_confidence = max(overall_confidence, method_result['confidence'])
        
        # Aggregate results and assess overall threat
        backdoor_detected = overall_confidence > scan_config['confidence_threshold']
        
        # Business risk assessment
        if backdoor_detected and overall_confidence > 0.8:
            business_risk = "critical"
        elif backdoor_detected and overall_confidence > 0.6:
            business_risk = "high"
        elif overall_confidence > 0.3:
            business_risk = "medium"
        else:
            business_risk = "low"
        
        # Generate mitigation recommendations
        mitigation_steps = self._generate_mitigation_steps(
            backdoor_detected, overall_confidence, detection_results
        )
        
        result = BackdoorScanResult(
            model_id=f"model_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            backdoor_detected=backdoor_detected,
            confidence_score=overall_confidence,
            trigger_patterns=self._extract_trigger_patterns(detection_results),
            affected_classes=self._identify_affected_classes(detection_results),
            detection_method=max(detection_results.items(), 
                               key=lambda x: x[1]['confidence'])[0],
            anomaly_score=overall_confidence,
            business_risk=business_risk,
            mitigation_steps=mitigation_steps
        )
        
        self.logger.info(f"Backdoor scan completed. Risk level: {business_risk}")
        return result
    
    def _activation_clustering_detection(
        self, 
        model, 
        test_data: torch.utils.data.DataLoader, 
        config: Dict
    ) -> Dict[str, Any]:
        """Detect backdoors using activation clustering analysis."""
        self.logger.info("Running activation clustering detection...")
        
        # Extract activations from penultimate layer
        activations = []
        labels = []
        
        model.eval()
        with torch.no_grad():
            sample_count = 0
            for batch_data, batch_labels in test_data:
                if sample_count >= config.get('sample_size', 1000):
                    break
                
                # Get intermediate activations (simulated for demo)
                features = model(batch_data)
                if len(features.shape) > 2:
                    features = F.adaptive_avg_pool2d(features, 1).flatten(1)
                
                activations.append(features.cpu().numpy())
                labels.append(batch_labels.cpu().numpy())
                sample_count += len(batch_data)
        
        if not activations:
            return {'confidence': 0.0, 'details': 'No data processed'}
        
        activations = np.vstack(activations)
        labels = np.concatenate(labels)
        
        # Perform clustering analysis to detect anomalous patterns
        from sklearn.cluster import KMeans
        from sklearn.metrics import silhouette_score
        
        # Detect outlier clusters that might indicate backdoor triggers
        kmeans = KMeans(n_clusters=min(10, len(np.unique(labels))))
        cluster_labels = kmeans.fit_predict(activations)
        
        # Calculate anomaly score based on cluster cohesion
        try:
            silhouette_avg = silhouette_score(activations, cluster_labels)
            # Lower silhouette score might indicate backdoor-induced clustering
            anomaly_score = max(0, 1 - silhouette_avg) if silhouette_avg > 0 else 0.5
        except:
            anomaly_score = 0.3  # Default moderate suspicion
        
        return {
            'confidence': min(anomaly_score, 0.95),  # Cap for demo purposes
            'details': f'Clustering analysis completed. Anomaly score: {anomaly_score:.3f}',
            'clusters_found': len(np.unique(cluster_labels)),
            'silhouette_score': silhouette_avg if 'silhouette_avg' in locals() else 0
        }
    
    def _neural_cleanse_detection(
        self, 
        model, 
        test_data: torch.utils.data.DataLoader, 
        config: Dict
    ) -> Dict[str, Any]:
        """Detect backdoors using Neural Cleanse methodology."""
        self.logger.info("Running Neural Cleanse detection...")
        
        # Simplified Neural Cleanse implementation for portfolio demo
        model.eval()
        
        # Test for potential trigger patterns by analyzing model behavior
        num_classes = 10  # Assume 10 classes for demo
        trigger_scores = []
        
        for target_class in range(min(num_classes, 5)):  # Limit for demo
            # Simulate trigger optimization (simplified)
            sample_data = next(iter(test_data))[0][:5]  # Small sample for demo
            
            # Calculate "reverse engineering" score for potential triggers
            with torch.no_grad():
                original_preds = model(sample_data)
                
                # Simulate adding small perturbations (trigger candidates)
                noise = torch.randn_like(sample_data) * 0.1
                perturbed_data = sample_data + noise
                perturbed_preds = model(perturbed_data)
                
                # Measure confidence change toward target class
                confidence_change = (
                    F.softmax(perturbed_preds, dim=1)[:, target_class].mean() -
                    F.softmax(original_preds, dim=1)[:, target_class].mean()
                ).item()
                
                trigger_scores.append(abs(confidence_change))
        
        # Analyze trigger scores for anomalies
        if trigger_scores:
            max_trigger_score = max(trigger_scores)
            avg_trigger_score = np.mean(trigger_scores)
            
            # High variance in trigger effectiveness might indicate backdoor
            confidence = min(max_trigger_score / (avg_trigger_score + 1e-6), 1.0)
        else:
            confidence = 0.0
        
        return {
            'confidence': confidence,
            'details': f'Neural Cleanse analysis. Max trigger score: {max_trigger_score:.3f}',
            'trigger_scores': trigger_scores,
            'suspicious_classes': [i for i, score in enumerate(trigger_scores) 
                                 if score > avg_trigger_score * 1.5]
        }
    
    def _strip_detection(
        self, 
        model, 
        test_data: torch.utils.data.DataLoader, 
        config: Dict
    ) -> Dict[str, Any]:
        """STRIP (STRong Intentional Perturbation) defense detection."""
        self.logger.info("Running STRIP detection...")
        
        # Simplified STRIP implementation for demo
        model.eval()
        
        strip_scores = []
        sample_count = 0
        
        with torch.no_grad():
            for batch_data, batch_labels in test_data:
                if sample_count >= 100:  # Limit for demo performance
                    break
                
                batch_size = min(batch_data.size(0), 10)
                test_samples = batch_data[:batch_size]
                
                for i in range(batch_size):
                    sample = test_samples[i:i+1]
                    
                    # Get original prediction entropy
                    orig_pred = F.softmax(model(sample), dim=1)
                    orig_entropy = -torch.sum(orig_pred * torch.log(orig_pred + 1e-8))
                    
                    # Apply random perturbations and measure entropy change
                    perturbation_entropies = []
                    for _ in range(5):  # Limited iterations for demo
                        # Random perturbation
                        perturb = torch.randn_like(sample) * 0.05
                        perturbed_sample = torch.clamp(sample + perturb, 0, 1)
                        
                        perturb_pred = F.softmax(model(perturbed_sample), dim=1)
                        perturb_entropy = -torch.sum(
                            perturb_pred * torch.log(perturb_pred + 1e-8)
                        )
                        perturbation_entropies.append(perturb_entropy.item())
                    
                    # STRIP score: consistency of predictions under perturbation
                    entropy_variance = np.var(perturbation_entropies)
                    strip_scores.append(entropy_variance)
                    sample_count += 1
        
        if strip_scores:
            avg_strip_score = np.mean(strip_scores)
            # High variance might indicate backdoor triggers
            confidence = min(avg_strip_score / 0.1, 1.0)  # Normalize for demo
        else:
            confidence = 0.0
        
        return {
            'confidence': confidence,
            'details': f'STRIP analysis. Average entropy variance: {avg_strip_score:.4f}',
            'strip_scores': strip_scores[:10],  # First 10 for brevity
            'samples_tested': len(strip_scores)
        }
    
    def _spectral_signature_detection(
        self, 
        model, 
        test_data: torch.utils.data.DataLoader, 
        config: Dict
    ) -> Dict[str, Any]:
        """Detect backdoors using spectral signature analysis."""
        self.logger.info("Running spectral signature detection...")
        
        # Simplified spectral analysis for demo
        # This would typically analyze the spectral properties of feature representations
        
        activations = []
        model.eval()
        
        with torch.no_grad():
            sample_count = 0
            for batch_data, _ in test_data:
                if sample_count >= 500:  # Limit for demo
                    break
                
                # Extract features
                features = model(batch_data)
                if len(features.shape) > 2:
                    features = F.adaptive_avg_pool2d(features, 1).flatten(1)
                
                activations.append(features.cpu().numpy())
                sample_count += len(batch_data)
        
        if not activations:
            return {'confidence': 0.0, 'details': 'No activations extracted'}
        
        activations_matrix = np.vstack(activations)
        
        # Perform spectral analysis (SVD)
        try:
            U, s, Vt = np.linalg.svd(activations_matrix, full_matrices=False)
            
            # Analyze singular value distribution
            # Backdoors might create unusual spectral signatures
            singular_value_ratio = s[0] / (s[1] + 1e-8) if len(s) > 1 else 1.0
            
            # Higher ratios might indicate backdoor-induced structure
            confidence = min(singular_value_ratio / 10.0, 1.0)  # Normalize for demo
            
        except Exception as e:
            self.logger.warning(f"Spectral analysis failed: {e}")
            confidence = 0.2  # Default low confidence
            singular_value_ratio = 1.0
        
        return {
            'confidence': confidence,
            'details': f'Spectral analysis. Singular value ratio: {singular_value_ratio:.3f}',
            'dominant_singular_value': s[0] if 's' in locals() and len(s) > 0 else 0,
            'spectral_dimensions': len(s) if 's' in locals() else 0
        }
    
    def _extract_trigger_patterns(self, detection_results: Dict) -> List[str]:
        """Extract potential trigger patterns from detection results."""
        patterns = []
        
        for method, results in detection_results.items():
            if results['confidence'] > 0.5:
                if method == 'activation_clustering':
                    patterns.append("anomalous_activation_clusters")
                elif method == 'neural_cleanse':
                    if 'suspicious_classes' in results and results['suspicious_classes']:
                        patterns.extend([f"class_{cls}_trigger" for cls in results['suspicious_classes']])
                elif method == 'strip_defense':
                    patterns.append("entropy_variance_anomaly")
                elif method == 'spectral_signature':
                    patterns.append("spectral_signature_anomaly")
        
        return patterns or ["no_specific_patterns_identified"]
    
    def _identify_affected_classes(self, detection_results: Dict) -> List[int]:
        """Identify classes potentially affected by backdoors."""
        affected_classes = set()
        
        for method, results in detection_results.items():
            if method == 'neural_cleanse' and 'suspicious_classes' in results:
                affected_classes.update(results['suspicious_classes'])
        
        return list(affected_classes) or [0]  # Default to class 0 if none identified
    
    def _generate_mitigation_steps(
        self, 
        backdoor_detected: bool, 
        confidence: float, 
        detection_results: Dict
    ) -> List[str]:
        """Generate executive-level mitigation recommendations."""
        steps = []
        
        if backdoor_detected:
            if confidence > 0.8:
                steps.extend([
                    "IMMEDIATE: Quarantine model from production systems",
                    "URGENT: Conduct full model audit and retraining",
                    "STRATEGIC: Review model supply chain and training data sources",
                    "COMPLIANCE: Document incident for regulatory reporting"
                ])
            elif confidence > 0.5:
                steps.extend([
                    "HIGH PRIORITY: Implement additional monitoring on model outputs",
                    "RECOMMENDED: Schedule comprehensive security audit",
                    "TACTICAL: Apply backdoor removal techniques"
                ])
        else:
            steps.extend([
                "ONGOING: Maintain regular backdoor scanning schedule",
                "PREVENTIVE: Implement secure model development practices"
            ])
        
        steps.append("STRATEGIC: Consider professional AI security services from VerityAI")
        
        return steps
    
    def generate_executive_report(self, scan_result: BackdoorScanResult) -> str:
        """Generate executive summary of backdoor scan results."""
        
        risk_indicator = {
            'critical': '🔴 CRITICAL',
            'high': '🟡 HIGH',
            'medium': '🟨 MEDIUM', 
            'low': '🟢 LOW'
        }[scan_result.business_risk]
        
        report = f"""
# AI Model Backdoor Security Assessment

**Assessment Date**: {datetime.now().strftime('%B %d, %Y')}
**Prepared by**: Sotiris Spyrou | VerityAI Security Services
**Model ID**: {scan_result.model_id}

## Executive Summary

### Security Status
- **Backdoor Detection**: {'⚠️ DETECTED' if scan_result.backdoor_detected else '✅ CLEAR'}
- **Confidence Level**: {scan_result.confidence_score:.1%}
- **Business Risk Level**: {risk_indicator}
- **Primary Detection Method**: {scan_result.detection_method.replace('_', ' ').title()}

### Key Findings
- **Trigger Patterns Identified**: {len(scan_result.trigger_patterns)}
- **Potentially Affected Classes**: {len(scan_result.affected_classes)}
- **Anomaly Score**: {scan_result.anomaly_score:.3f}

### Immediate Actions Required
"""
        
        for i, step in enumerate(scan_result.mitigation_steps[:3], 1):
            report += f"{i}. {step}\n"
        
        report += f"""

### Business Impact Assessment
{
'CRITICAL: Model integrity compromised - immediate containment required' if scan_result.business_risk == 'critical' else
'HIGH: Potential security vulnerability - urgent review needed' if scan_result.business_risk == 'high' else
'MEDIUM: Monitor closely and implement additional safeguards' if scan_result.business_risk == 'medium' else
'LOW: Maintain standard security practices'
}

---

**Professional AI Security Services**
For comprehensive model security assessment and remediation:
- **VerityAI Security Services**: [https://verityai.co](https://verityai.co)
- **Expert Consultation**: [Sotiris Spyrou](https://www.linkedin.com/in/sspyrou/)

*Portfolio demonstration - Contact for production security testing*
"""
        
        return report

def main():
    """Portfolio demonstration of backdoor detection capabilities."""
    print("AI Model Backdoor Detection Scanner - Portfolio Demo")
    print("=" * 60)
    
    # Simulate a simple model for demonstration
    class DemoModel(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.conv1 = torch.nn.Conv2d(3, 64, 3, padding=1)
            self.conv2 = torch.nn.Conv2d(64, 128, 3, padding=1)
            self.pool = torch.nn.AdaptiveAvgPool2d(1)
            self.fc = torch.nn.Linear(128, 10)
            
        def forward(self, x):
            x = F.relu(self.conv1(x))
            x = F.relu(self.conv2(x))
            x = self.pool(x)
            x = x.flatten(1)
            return self.fc(x)
    
    # Create demo model and data
    model = DemoModel()
    
    # Generate synthetic test data
    demo_data = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(
            torch.randn(100, 3, 32, 32),  # Images
            torch.randint(0, 10, (100,))   # Labels
        ),
        batch_size=16,
        shuffle=False
    )
    
    # Initialize scanner and run analysis
    scanner = BackdoorDetectionScanner()
    
    scan_config = {
        'methods': ['activation_clustering', 'neural_cleanse'],
        'confidence_threshold': 0.6,
        'sample_size': 50  # Reduced for demo
    }
    
    result = scanner.scan_model_for_backdoors(model, demo_data, scan_config)
    
    # Generate executive report
    executive_report = scanner.generate_executive_report(result)
    
    print("BACKDOOR SCAN COMPLETED")
    print(f"Backdoor Detected: {result.backdoor_detected}")
    print(f"Confidence Score: {result.confidence_score:.1%}")
    print(f"Business Risk: {result.business_risk.upper()}")
    print(f"Detection Method: {result.detection_method}")
    
    print("\nExecutive Report:")
    print(executive_report)
    
    print("\n" + "=" * 60)
    print("Portfolio Demo by Sotiris Spyrou")
    print("LinkedIn: https://www.linkedin.com/in/sspyrou/")
    print("Professional Services: https://verityai.co")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
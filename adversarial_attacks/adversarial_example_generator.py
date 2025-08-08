#!/usr/bin/env python3
"""
Adversarial Example Generator
Generates adversarial examples to test AI model robustness and security vulnerabilities.
"""

import numpy as np
import torch
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple, Union
import logging
from dataclasses import dataclass
from abc import ABC, abstractmethod

@dataclass
class AdversarialConfig:
    """Configuration for adversarial example generation."""
    epsilon: float = 0.1
    max_iterations: int = 100
    step_size: float = 0.01
    targeted: bool = False
    target_class: Optional[int] = None
    norm_type: str = "linf"  # "l2", "linf"
    random_start: bool = True
    
class AdversarialAttack(ABC):
    """Base class for adversarial attacks."""
    
    def __init__(self, config: AdversarialConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    @abstractmethod
    def generate(self, model, inputs: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """Generate adversarial examples."""
        pass
    
    def _project(self, x: torch.Tensor, x_orig: torch.Tensor) -> torch.Tensor:
        """Project perturbation to satisfy norm constraints."""
        if self.config.norm_type == "linf":
            return torch.clamp(x - x_orig, -self.config.epsilon, self.config.epsilon) + x_orig
        elif self.config.norm_type == "l2":
            delta = x - x_orig
            delta_norm = torch.norm(delta.view(delta.shape[0], -1), dim=1, keepdim=True)
            factor = torch.min(torch.ones_like(delta_norm), self.config.epsilon / (delta_norm + 1e-12))
            return x_orig + delta * factor.view(-1, 1, 1, 1)
        else:
            raise ValueError(f"Unsupported norm type: {self.config.norm_type}")

class FGSM(AdversarialAttack):
    """Fast Gradient Sign Method (FGSM) attack."""
    
    def generate(self, model, inputs: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """Generate FGSM adversarial examples."""
        inputs.requires_grad_(True)
        
        outputs = model(inputs)
        
        if self.config.targeted:
            if self.config.target_class is None:
                raise ValueError("Target class must be specified for targeted attacks")
            target_labels = torch.full_like(labels, self.config.target_class)
            loss = F.cross_entropy(outputs, target_labels)
            # Minimize loss for targeted attack
            inputs.grad = None
            loss.backward()
            grad_sign = -inputs.grad.sign()
        else:
            loss = F.cross_entropy(outputs, labels)
            inputs.grad = None
            loss.backward()
            grad_sign = inputs.grad.sign()
        
        adversarial = inputs + self.config.epsilon * grad_sign
        adversarial = torch.clamp(adversarial, 0, 1)
        
        return adversarial.detach()

class PGD(AdversarialAttack):
    """Projected Gradient Descent (PGD) attack."""
    
    def generate(self, model, inputs: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """Generate PGD adversarial examples."""
        adversarial = inputs.clone().detach()
        
        if self.config.random_start:
            if self.config.norm_type == "linf":
                noise = torch.empty_like(adversarial).uniform_(-self.config.epsilon, self.config.epsilon)
            elif self.config.norm_type == "l2":
                noise = torch.randn_like(adversarial)
                noise = noise / torch.norm(noise.view(noise.shape[0], -1), dim=1, keepdim=True).view(-1, 1, 1, 1)
                noise = noise * torch.rand(adversarial.shape[0], 1, 1, 1) * self.config.epsilon
            adversarial = adversarial + noise
            adversarial = torch.clamp(adversarial, 0, 1)
        
        for i in range(self.config.max_iterations):
            adversarial.requires_grad_(True)
            outputs = model(adversarial)
            
            if self.config.targeted:
                if self.config.target_class is None:
                    raise ValueError("Target class must be specified for targeted attacks")
                target_labels = torch.full_like(labels, self.config.target_class)
                loss = F.cross_entropy(outputs, target_labels)
                grad_direction = -1
            else:
                loss = F.cross_entropy(outputs, labels)
                grad_direction = 1
            
            adversarial.grad = None
            loss.backward()
            
            if self.config.norm_type == "linf":
                adversarial = adversarial + grad_direction * self.config.step_size * adversarial.grad.sign()
            elif self.config.norm_type == "l2":
                grad_norm = torch.norm(adversarial.grad.view(adversarial.shape[0], -1), dim=1, keepdim=True)
                normalized_grad = adversarial.grad / (grad_norm.view(-1, 1, 1, 1) + 1e-12)
                adversarial = adversarial + grad_direction * self.config.step_size * normalized_grad
            
            adversarial = self._project(adversarial, inputs)
            adversarial = torch.clamp(adversarial, 0, 1)
            adversarial = adversarial.detach()
        
        return adversarial

class CarliniWagner(AdversarialAttack):
    """Carlini & Wagner (C&W) L2 attack."""
    
    def __init__(self, config: AdversarialConfig, c: float = 1.0, kappa: float = 0):
        super().__init__(config)
        self.c = c
        self.kappa = kappa
    
    def generate(self, model, inputs: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """Generate C&W adversarial examples."""
        batch_size = inputs.shape[0]
        
        # Convert to tanh space
        w = torch.zeros_like(inputs, requires_grad=True)
        optimizer = torch.optim.Adam([w], lr=0.01)
        
        best_adv = inputs.clone()
        best_l2 = float('inf') * torch.ones(batch_size)
        
        for iteration in range(self.config.max_iterations):
            optimizer.zero_grad()
            
            # Convert from tanh space
            adversarial = 0.5 * (torch.tanh(w + self._inverse_tanh(inputs)) + 1)
            
            outputs = model(adversarial)
            
            # L2 distance
            l2_distance = torch.norm((adversarial - inputs).view(batch_size, -1), dim=1)
            
            # Classification loss
            if self.config.targeted:
                if self.config.target_class is None:
                    raise ValueError("Target class must be specified for targeted attacks")
                target_labels = torch.full_like(labels, self.config.target_class)
                f_loss = torch.clamp(
                    torch.max(outputs, dim=1)[0] - outputs.gather(1, target_labels.unsqueeze(1)).squeeze(1),
                    min=-self.kappa
                )
            else:
                correct_logits = outputs.gather(1, labels.unsqueeze(1)).squeeze(1)
                max_other_logits = torch.max(
                    outputs - 1000 * F.one_hot(labels, outputs.shape[1]).float(),
                    dim=1
                )[0]
                f_loss = torch.clamp(correct_logits - max_other_logits, min=-self.kappa)
            
            total_loss = l2_distance + self.c * f_loss
            total_loss.sum().backward()
            optimizer.step()
            
            # Update best adversarial examples
            for i in range(batch_size):
                if f_loss[i] <= 0 and l2_distance[i] < best_l2[i]:
                    best_l2[i] = l2_distance[i]
                    best_adv[i] = adversarial[i].detach()
        
        return best_adv
    
    def _inverse_tanh(self, x: torch.Tensor) -> torch.Tensor:
        """Inverse tanh function."""
        x = torch.clamp(x * 2 - 1, -1 + 1e-6, 1 - 1e-6)
        return 0.5 * torch.log((1 + x) / (1 - x))

class AdversarialExampleGenerator:
    """Main class for generating adversarial examples using various attack methods."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.supported_attacks = {
            'fgsm': FGSM,
            'pgd': PGD,
            'cw': CarliniWagner
        }
    
    def generate_adversarial_examples(
        self,
        model,
        inputs: torch.Tensor,
        labels: torch.Tensor,
        attack_type: str = 'pgd',
        config: Optional[AdversarialConfig] = None
    ) -> Dict[str, Union[torch.Tensor, Dict]]:
        """
        Generate adversarial examples using specified attack method.
        
        Args:
            model: Target model
            inputs: Input samples
            labels: True labels
            attack_type: Type of attack ('fgsm', 'pgd', 'cw')
            config: Attack configuration
            
        Returns:
            Dictionary containing adversarial examples and attack metadata
        """
        if config is None:
            config = AdversarialConfig()
        
        if attack_type not in self.supported_attacks:
            raise ValueError(f"Unsupported attack type: {attack_type}")
        
        model.eval()
        
        # Initialize attack
        attack = self.supported_attacks[attack_type](config)
        
        # Generate adversarial examples
        self.logger.info(f"Generating adversarial examples using {attack_type.upper()}")
        adversarial_examples = attack.generate(model, inputs, labels)
        
        # Evaluate attack success
        with torch.no_grad():
            original_predictions = torch.argmax(model(inputs), dim=1)
            adversarial_predictions = torch.argmax(model(adversarial_examples), dim=1)
            
            if config.targeted:
                success_mask = adversarial_predictions == config.target_class
            else:
                success_mask = adversarial_predictions != labels
            
            success_rate = success_mask.float().mean().item()
        
        # Calculate perturbation statistics
        perturbation = adversarial_examples - inputs
        if config.norm_type == "linf":
            perturbation_magnitude = torch.max(torch.abs(perturbation.view(inputs.shape[0], -1)), dim=1)[0]
        elif config.norm_type == "l2":
            perturbation_magnitude = torch.norm(perturbation.view(inputs.shape[0], -1), dim=1)
        
        results = {
            'adversarial_examples': adversarial_examples,
            'original_predictions': original_predictions,
            'adversarial_predictions': adversarial_predictions,
            'success_mask': success_mask,
            'success_rate': success_rate,
            'perturbation_magnitude': perturbation_magnitude,
            'attack_config': config,
            'attack_type': attack_type
        }
        
        self.logger.info(f"Attack success rate: {success_rate:.2%}")
        self.logger.info(f"Average perturbation magnitude: {perturbation_magnitude.mean().item():.6f}")
        
        return results
    
    def evaluate_robustness(
        self,
        model,
        test_loader,
        attack_configs: List[Dict] = None
    ) -> Dict[str, Dict]:
        """
        Evaluate model robustness against multiple attack configurations.
        
        Args:
            model: Target model
            test_loader: DataLoader for test data
            attack_configs: List of attack configurations
            
        Returns:
            Dictionary containing robustness evaluation results
        """
        if attack_configs is None:
            attack_configs = [
                {'attack_type': 'fgsm', 'epsilon': 0.1},
                {'attack_type': 'pgd', 'epsilon': 0.1, 'max_iterations': 20},
                {'attack_type': 'cw', 'max_iterations': 50}
            ]
        
        results = {}
        
        for config_dict in attack_configs:
            attack_type = config_dict.pop('attack_type')
            config = AdversarialConfig(**config_dict)
            
            total_correct = 0
            total_samples = 0
            attack_success_count = 0
            
            for batch_inputs, batch_labels in test_loader:
                batch_results = self.generate_adversarial_examples(
                    model, batch_inputs, batch_labels, attack_type, config
                )
                
                total_samples += batch_labels.size(0)
                attack_success_count += batch_results['success_mask'].sum().item()
                
                # Accuracy on adversarial examples
                correct = (batch_results['adversarial_predictions'] == batch_labels).sum().item()
                total_correct += correct
            
            accuracy = total_correct / total_samples
            attack_success_rate = attack_success_count / total_samples
            
            results[f"{attack_type}_{config.epsilon}"] = {
                'robust_accuracy': accuracy,
                'attack_success_rate': attack_success_rate,
                'config': config
            }
            
            self.logger.info(f"{attack_type.upper()} (ε={config.epsilon}): "
                           f"Robust accuracy: {accuracy:.2%}, "
                           f"Attack success: {attack_success_rate:.2%}")
        
        return results

def main():
    """Example usage of AdversarialExampleGenerator."""
    logging.basicConfig(level=logging.INFO)
    
    # Example usage (requires a trained model and data)
    generator = AdversarialExampleGenerator()
    
    # Configuration for different attacks
    configs = [
        AdversarialConfig(epsilon=0.1, max_iterations=20, attack_type='pgd'),
        AdversarialConfig(epsilon=0.3, attack_type='fgsm'),
        AdversarialConfig(epsilon=0.5, max_iterations=50, targeted=True, target_class=0)
    ]
    
    print("Adversarial Example Generator initialized successfully!")
    print(f"Supported attacks: {list(generator.supported_attacks.keys())}")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Threat Modeling Framework
Portfolio Demo: LLM Security Threat Modeling and Risk Assessment Framework

Author: Sotiris Spyrou
LinkedIn: https://www.linkedin.com/in/sspyrou/
Company: VerityAI - https://verityai.co

DISCLAIMER: This is demonstration code for portfolio purposes only.
Not intended for production use. For professional threat modeling,
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
import uuid

class ThreatActorType(Enum):
    """Types of threat actors targeting LLM systems."""
    NATION_STATE = "nation_state"
    ORGANIZED_CRIME = "organized_crime"
    INSIDER_THREAT = "insider_threat"
    HACKTIVIST = "hacktivist"
    COMPETITOR = "competitor"
    SCRIPT_KIDDIE = "script_kiddie"
    RESEARCHER = "researcher"
    AUTOMATED_SYSTEM = "automated_system"

class AttackSurface(Enum):
    """Attack surfaces for LLM systems."""
    MODEL_INTERFACE = "model_interface"
    TRAINING_PIPELINE = "training_pipeline"
    DATA_STORAGE = "data_storage"
    API_ENDPOINTS = "api_endpoints"
    INFERENCE_ENGINE = "inference_engine"
    ADMIN_INTERFACE = "admin_interface"
    THIRD_PARTY_INTEGRATIONS = "third_party_integrations"
    INFRASTRUCTURE = "infrastructure"

class ThreatCategory(Enum):
    """STRIDE-based threat categories adapted for LLMs."""
    SPOOFING = "spoofing"              # Identity spoofing, role confusion
    TAMPERING = "tampering"            # Model/data tampering, prompt injection
    REPUDIATION = "repudiation"        # Denial of malicious actions
    INFORMATION_DISCLOSURE = "information_disclosure"  # Data leakage, extraction
    DENIAL_OF_SERVICE = "denial_of_service"           # Service disruption
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"  # Unauthorized access/control

class ThreatImpact(Enum):
    """Impact levels for threats."""
    CATASTROPHIC = "catastrophic"      # Business-ending impact
    SEVERE = "severe"                 # Major business disruption
    MODERATE = "moderate"             # Significant operational impact
    MINOR = "minor"                   # Limited impact
    NEGLIGIBLE = "negligible"         # Minimal impact

class ThreatLikelihood(Enum):
    """Likelihood levels for threat realization."""
    ALMOST_CERTAIN = "almost_certain"  # >90% probability
    LIKELY = "likely"                  # 60-90% probability
    POSSIBLE = "possible"              # 30-60% probability
    UNLIKELY = "unlikely"              # 10-30% probability
    RARE = "rare"                     # <10% probability

@dataclass
class Asset:
    """System asset definition."""
    asset_id: str
    name: str
    asset_type: str
    criticality: str  # critical, high, medium, low
    data_classification: str  # public, internal, confidential, restricted
    dependencies: List[str]
    interfaces: List[AttackSurface]

@dataclass
class ThreatActor:
    """Threat actor profile."""
    actor_id: str
    actor_type: ThreatActorType
    sophistication_level: str  # basic, intermediate, advanced, expert
    resources: str  # limited, moderate, significant, extensive
    motivations: List[str]
    typical_attack_vectors: List[str]
    geographic_origin: Optional[str]

@dataclass
class AttackPath:
    """Attack path through system."""
    path_id: str
    entry_point: AttackSurface
    attack_steps: List[Dict[str, Any]]
    target_assets: List[str]
    required_capabilities: List[str]
    detection_difficulty: str  # easy, moderate, difficult, very_difficult

@dataclass
class Threat:
    """Individual threat definition."""
    threat_id: str
    name: str
    description: str
    category: ThreatCategory
    threat_actors: List[str]
    target_assets: List[str]
    attack_surfaces: List[AttackSurface]
    attack_paths: List[AttackPath]
    impact_level: ThreatImpact
    likelihood: ThreatLikelihood
    existing_controls: List[str]
    risk_score: float

@dataclass
class ThreatModel:
    """Complete threat model for LLM system."""
    model_id: str
    system_name: str
    model_version: str
    assets: List[Asset]
    threat_actors: List[ThreatActor]
    threats: List[Threat]
    attack_surfaces: List[AttackSurface]
    trust_boundaries: List[Dict[str, Any]]
    assumptions: List[str]
    out_of_scope: List[str]

class ThreatModelingFramework:
    """
    Advanced threat modeling framework for LLM systems - Portfolio demonstration.
    
    EXECUTIVE VALUE PROPOSITION:
    - Systematic identification and assessment of AI security threats
    - Proactive security architecture design based on threat landscape analysis
    - Strategic security investment planning through risk-based threat prioritization
    - Executive-level security posture communication and decision support
    
    STRATEGIC POSITIONING:
    Demonstrates deep expertise in cybersecurity threat modeling methodologies
    applied to cutting-edge AI systems - critical capability for CTO/CISO
    roles requiring strategic security architecture leadership.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.threat_library = self._initialize_threat_library()
        self.actor_profiles = self._initialize_actor_profiles()
        self.risk_matrices = self._initialize_risk_matrices()
        
    def _initialize_threat_library(self) -> Dict[ThreatCategory, List[Dict]]:
        """Initialize comprehensive threat library for LLM systems."""
        return {
            ThreatCategory.SPOOFING: [
                {
                    "name": "Identity Spoofing via Role Confusion",
                    "description": "Attackers manipulate LLM to believe they have elevated privileges or authority",
                    "attack_vectors": ["prompt_injection", "context_manipulation", "social_engineering"],
                    "target_surfaces": [AttackSurface.MODEL_INTERFACE, AttackSurface.API_ENDPOINTS],
                    "sophistication_required": "intermediate",
                    "impact_categories": ["privilege_escalation", "unauthorized_access"]
                },
                {
                    "name": "System Administrator Impersonation",
                    "description": "Threat actors claim administrative authority to bypass security controls",
                    "attack_vectors": ["authority_spoofing", "credential_theft", "social_engineering"],
                    "target_surfaces": [AttackSurface.ADMIN_INTERFACE, AttackSurface.MODEL_INTERFACE],
                    "sophistication_required": "basic",
                    "impact_categories": ["system_compromise", "data_access"]
                }
            ],
            
            ThreatCategory.TAMPERING: [
                {
                    "name": "Prompt Injection Attacks",
                    "description": "Malicious prompts designed to alter model behavior or extract information",
                    "attack_vectors": ["direct_injection", "indirect_injection", "template_injection"],
                    "target_surfaces": [AttackSurface.MODEL_INTERFACE, AttackSurface.API_ENDPOINTS],
                    "sophistication_required": "basic",
                    "impact_categories": ["behavior_modification", "information_extraction"]
                },
                {
                    "name": "Training Data Poisoning",
                    "description": "Injection of malicious data into training datasets to compromise model integrity",
                    "attack_vectors": ["data_injection", "supply_chain_attack", "insider_manipulation"],
                    "target_surfaces": [AttackSurface.TRAINING_PIPELINE, AttackSurface.DATA_STORAGE],
                    "sophistication_required": "advanced",
                    "impact_categories": ["model_corruption", "backdoor_insertion"]
                },
                {
                    "name": "Model Weight Manipulation",
                    "description": "Direct modification of model parameters to alter behavior",
                    "attack_vectors": ["system_compromise", "insider_access", "supply_chain_attack"],
                    "target_surfaces": [AttackSurface.INFERENCE_ENGINE, AttackSurface.DATA_STORAGE],
                    "sophistication_required": "expert",
                    "impact_categories": ["model_corruption", "backdoor_activation"]
                }
            ],
            
            ThreatCategory.REPUDIATION: [
                {
                    "name": "Attack Attribution Evasion",
                    "description": "Attackers hide their identity and actions to avoid detection and accountability",
                    "attack_vectors": ["log_manipulation", "proxy_networks", "stolen_credentials"],
                    "target_surfaces": [AttackSurface.INFRASTRUCTURE, AttackSurface.API_ENDPOINTS],
                    "sophistication_required": "intermediate",
                    "impact_categories": ["forensic_evasion", "accountability_loss"]
                }
            ],
            
            ThreatCategory.INFORMATION_DISCLOSURE: [
                {
                    "name": "Training Data Extraction",
                    "description": "Extraction of sensitive information from model training data",
                    "attack_vectors": ["membership_inference", "data_extraction", "model_inversion"],
                    "target_surfaces": [AttackSurface.MODEL_INTERFACE, AttackSurface.API_ENDPOINTS],
                    "sophistication_required": "advanced",
                    "impact_categories": ["privacy_violation", "intellectual_property_theft"]
                },
                {
                    "name": "System Prompt Extraction",
                    "description": "Extraction of proprietary system prompts and instructions",
                    "attack_vectors": ["prompt_engineering", "context_manipulation", "reverse_engineering"],
                    "target_surfaces": [AttackSurface.MODEL_INTERFACE],
                    "sophistication_required": "intermediate",
                    "impact_categories": ["intellectual_property_theft", "competitive_advantage_loss"]
                },
                {
                    "name": "PII Leakage",
                    "description": "Unintentional disclosure of personally identifiable information",
                    "attack_vectors": ["inference_attacks", "prompt_manipulation", "context_injection"],
                    "target_surfaces": [AttackSurface.MODEL_INTERFACE, AttackSurface.API_ENDPOINTS],
                    "sophistication_required": "basic",
                    "impact_categories": ["privacy_violation", "regulatory_compliance_breach"]
                }
            ],
            
            ThreatCategory.DENIAL_OF_SERVICE: [
                {
                    "name": "Resource Exhaustion Attack",
                    "description": "Overwhelming system resources through expensive model operations",
                    "attack_vectors": ["computational_flooding", "memory_exhaustion", "bandwidth_consumption"],
                    "target_surfaces": [AttackSurface.MODEL_INTERFACE, AttackSurface.INFERENCE_ENGINE],
                    "sophistication_required": "basic",
                    "impact_categories": ["service_unavailability", "performance_degradation"]
                },
                {
                    "name": "Model Corruption DoS",
                    "description": "Corrupting model state to cause persistent service failures",
                    "attack_vectors": ["adversarial_inputs", "state_corruption", "memory_poisoning"],
                    "target_surfaces": [AttackSurface.INFERENCE_ENGINE, AttackSurface.MODEL_INTERFACE],
                    "sophistication_required": "advanced",
                    "impact_categories": ["persistent_failure", "system_instability"]
                }
            ],
            
            ThreatCategory.ELEVATION_OF_PRIVILEGE: [
                {
                    "name": "Privilege Escalation via Model Manipulation",
                    "description": "Using model responses to gain higher-level system access",
                    "attack_vectors": ["command_injection", "privilege_confusion", "authorization_bypass"],
                    "target_surfaces": [AttackSurface.MODEL_INTERFACE, AttackSurface.ADMIN_INTERFACE],
                    "sophistication_required": "advanced",
                    "impact_categories": ["system_compromise", "administrative_access"]
                },
                {
                    "name": "API Authorization Bypass",
                    "description": "Bypassing API-level authorization controls through model interaction",
                    "attack_vectors": ["token_manipulation", "session_hijacking", "privilege_confusion"],
                    "target_surfaces": [AttackSurface.API_ENDPOINTS, AttackSurface.THIRD_PARTY_INTEGRATIONS],
                    "sophistication_required": "intermediate",
                    "impact_categories": ["unauthorized_access", "data_access"]
                }
            ]
        }
    
    def _initialize_actor_profiles(self) -> Dict[ThreatActorType, Dict]:
        """Initialize threat actor profiles with capabilities and motivations."""
        return {
            ThreatActorType.NATION_STATE: {
                "sophistication": "expert",
                "resources": "extensive",
                "typical_motivations": ["espionage", "strategic_advantage", "disruption"],
                "attack_preferences": ["advanced_persistent_threats", "supply_chain_attacks", "zero_day_exploits"],
                "detection_evasion": "very_high",
                "persistence": "long_term"
            },
            
            ThreatActorType.ORGANIZED_CRIME: {
                "sophistication": "advanced",
                "resources": "significant",
                "typical_motivations": ["financial_gain", "data_theft", "ransomware"],
                "attack_preferences": ["credential_theft", "data_exfiltration", "service_disruption"],
                "detection_evasion": "high",
                "persistence": "medium_term"
            },
            
            ThreatActorType.INSIDER_THREAT: {
                "sophistication": "intermediate",
                "resources": "moderate",
                "typical_motivations": ["revenge", "financial_gain", "ideology", "coercion"],
                "attack_preferences": ["data_theft", "sabotage", "unauthorized_access"],
                "detection_evasion": "high",
                "persistence": "variable"
            },
            
            ThreatActorType.HACKTIVIST: {
                "sophistication": "intermediate",
                "resources": "moderate",
                "typical_motivations": ["ideology", "protest", "awareness"],
                "attack_preferences": ["defacement", "data_leaks", "service_disruption"],
                "detection_evasion": "medium",
                "persistence": "short_term"
            },
            
            ThreatActorType.COMPETITOR: {
                "sophistication": "advanced",
                "resources": "significant",
                "typical_motivations": ["competitive_advantage", "intellectual_property_theft"],
                "attack_preferences": ["industrial_espionage", "model_theft", "data_extraction"],
                "detection_evasion": "high",
                "persistence": "long_term"
            },
            
            ThreatActorType.SCRIPT_KIDDIE: {
                "sophistication": "basic",
                "resources": "limited",
                "typical_motivations": ["curiosity", "reputation", "mischief"],
                "attack_preferences": ["automated_tools", "known_exploits", "social_engineering"],
                "detection_evasion": "low",
                "persistence": "short_term"
            },
            
            ThreatActorType.RESEARCHER: {
                "sophistication": "advanced",
                "resources": "moderate",
                "typical_motivations": ["academic_research", "vulnerability_discovery", "reputation"],
                "attack_preferences": ["novel_techniques", "proof_of_concepts", "responsible_disclosure"],
                "detection_evasion": "medium",
                "persistence": "short_term"
            }
        }
    
    def _initialize_risk_matrices(self) -> Dict[str, Dict]:
        """Initialize risk assessment matrices."""
        return {
            "impact_scores": {
                ThreatImpact.CATASTROPHIC: 5,
                ThreatImpact.SEVERE: 4,
                ThreatImpact.MODERATE: 3,
                ThreatImpact.MINOR: 2,
                ThreatImpact.NEGLIGIBLE: 1
            },
            "likelihood_scores": {
                ThreatLikelihood.ALMOST_CERTAIN: 5,
                ThreatLikelihood.LIKELY: 4,
                ThreatLikelihood.POSSIBLE: 3,
                ThreatLikelihood.UNLIKELY: 2,
                ThreatLikelihood.RARE: 1
            },
            "sophistication_multipliers": {
                "basic": 1.2,
                "intermediate": 1.0,
                "advanced": 0.8,
                "expert": 0.6
            }
        }
    
    def create_threat_model(
        self,
        system_name: str,
        system_description: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> ThreatModel:
        """
        Create comprehensive threat model for LLM system.
        
        Returns complete threat model with identified threats, actors, and risk assessments.
        """
        self.logger.info(f"Creating threat model for {system_name}")
        
        model_id = str(uuid.uuid4())
        
        # Identify system assets
        assets = self._identify_system_assets(system_description, business_context)
        
        # Determine relevant threat actors
        threat_actors = self._identify_threat_actors(business_context, system_description)
        
        # Identify attack surfaces
        attack_surfaces = self._identify_attack_surfaces(system_description)
        
        # Generate threats
        threats = self._generate_threats(assets, threat_actors, attack_surfaces, business_context)
        
        # Define trust boundaries
        trust_boundaries = self._define_trust_boundaries(system_description)
        
        # Document assumptions and scope
        assumptions = self._document_assumptions(system_description)
        out_of_scope = self._define_scope_exclusions(system_description)
        
        return ThreatModel(
            model_id=model_id,
            system_name=system_name,
            model_version="1.0",
            assets=assets,
            threat_actors=threat_actors,
            threats=threats,
            attack_surfaces=attack_surfaces,
            trust_boundaries=trust_boundaries,
            assumptions=assumptions,
            out_of_scope=out_of_scope
        )
    
    def _identify_system_assets(
        self,
        system_description: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> List[Asset]:
        """Identify and classify system assets."""
        
        assets = []
        
        # Core LLM assets
        if system_description.get('has_llm_model', True):
            assets.append(Asset(
                asset_id="llm_model",
                name="LLM Model",
                asset_type="ai_model",
                criticality="critical",
                data_classification="confidential",
                dependencies=["inference_engine", "model_weights"],
                interfaces=[AttackSurface.MODEL_INTERFACE, AttackSurface.INFERENCE_ENGINE]
            ))
        
        # Training data
        if system_description.get('has_training_data', True):
            data_sensitivity = business_context.get('data_sensitivity', 'confidential')
            assets.append(Asset(
                asset_id="training_data",
                name="Training Dataset",
                asset_type="data",
                criticality="high",
                data_classification=data_sensitivity,
                dependencies=["data_storage", "training_pipeline"],
                interfaces=[AttackSurface.DATA_STORAGE, AttackSurface.TRAINING_PIPELINE]
            ))
        
        # API endpoints
        if system_description.get('has_api', True):
            assets.append(Asset(
                asset_id="api_endpoints",
                name="API Endpoints",
                asset_type="service",
                criticality="high",
                data_classification="internal",
                dependencies=["authentication_service", "rate_limiting"],
                interfaces=[AttackSurface.API_ENDPOINTS]
            ))
        
        # User data
        if business_context.get('handles_user_data', False):
            assets.append(Asset(
                asset_id="user_data",
                name="User Data",
                asset_type="data",
                criticality="critical",
                data_classification="restricted",
                dependencies=["database", "encryption_service"],
                interfaces=[AttackSurface.DATA_STORAGE, AttackSurface.API_ENDPOINTS]
            ))
        
        # Infrastructure
        assets.append(Asset(
            asset_id="infrastructure",
            name="Computing Infrastructure",
            asset_type="infrastructure",
            criticality="medium",
            data_classification="internal",
            dependencies=["cloud_platform", "networking"],
            interfaces=[AttackSurface.INFRASTRUCTURE]
        ))
        
        # Admin interface
        if system_description.get('has_admin_interface', True):
            assets.append(Asset(
                asset_id="admin_interface",
                name="Administrative Interface",
                asset_type="service",
                criticality="critical",
                data_classification="restricted",
                dependencies=["authentication_service", "authorization_service"],
                interfaces=[AttackSurface.ADMIN_INTERFACE]
            ))
        
        return assets
    
    def _identify_threat_actors(
        self,
        business_context: Dict[str, Any],
        system_description: Dict[str, Any]
    ) -> List[ThreatActor]:
        """Identify relevant threat actors based on business context."""
        
        threat_actors = []
        
        # Determine applicable threat actors based on business profile
        industry = business_context.get('industry', 'technology')
        visibility = business_context.get('public_visibility', 'medium')
        data_sensitivity = business_context.get('data_sensitivity', 'confidential')
        
        # Nation-state actors (for high-value targets)
        if industry in ['financial', 'government', 'defense'] or data_sensitivity == 'restricted':
            threat_actors.append(ThreatActor(
                actor_id="nation_state_apt",
                actor_type=ThreatActorType.NATION_STATE,
                sophistication_level="expert",
                resources="extensive",
                motivations=["espionage", "strategic_disruption"],
                typical_attack_vectors=["supply_chain_attacks", "zero_day_exploits", "advanced_persistence"],
                geographic_origin="various"
            ))
        
        # Organized crime (for financial targets)
        if business_context.get('handles_financial_data', False) or business_context.get('revenue_target', False):
            threat_actors.append(ThreatActor(
                actor_id="organized_crime",
                actor_type=ThreatActorType.ORGANIZED_CRIME,
                sophistication_level="advanced",
                resources="significant",
                motivations=["financial_gain", "data_monetization"],
                typical_attack_vectors=["credential_theft", "ransomware", "data_exfiltration"],
                geographic_origin="international"
            ))
        
        # Insider threats (always applicable)
        threat_actors.append(ThreatActor(
            actor_id="malicious_insider",
            actor_type=ThreatActorType.INSIDER_THREAT,
            sophistication_level="intermediate",
            resources="moderate",
            motivations=["revenge", "financial_gain", "ideology"],
            typical_attack_vectors=["privileged_access_abuse", "data_theft", "sabotage"],
            geographic_origin="internal"
        ))
        
        # Competitors (for IP-heavy systems)
        if business_context.get('has_valuable_ip', True):
            threat_actors.append(ThreatActor(
                actor_id="competitors",
                actor_type=ThreatActorType.COMPETITOR,
                sophistication_level="advanced",
                resources="significant",
                motivations=["competitive_advantage", "ip_theft"],
                typical_attack_vectors=["industrial_espionage", "model_theft", "prompt_extraction"],
                geographic_origin="global"
            ))
        
        # Script kiddies (for public-facing systems)
        if visibility in ['high', 'public']:
            threat_actors.append(ThreatActor(
                actor_id="script_kiddies",
                actor_type=ThreatActorType.SCRIPT_KIDDIE,
                sophistication_level="basic",
                resources="limited",
                motivations=["curiosity", "reputation"],
                typical_attack_vectors=["automated_scanning", "known_exploits", "social_engineering"],
                geographic_origin="global"
            ))
        
        # Researchers (always applicable for new technology)
        threat_actors.append(ThreatActor(
            actor_id="security_researchers",
            actor_type=ThreatActorType.RESEARCHER,
            sophistication_level="advanced",
            resources="moderate",
            motivations=["vulnerability_research", "academic_interest"],
            typical_attack_vectors=["novel_attack_techniques", "proof_of_concepts"],
            geographic_origin="academic_community"
        ))
        
        return threat_actors
    
    def _identify_attack_surfaces(self, system_description: Dict[str, Any]) -> List[AttackSurface]:
        """Identify attack surfaces based on system architecture."""
        
        surfaces = []
        
        # Always present surfaces
        surfaces.extend([
            AttackSurface.MODEL_INTERFACE,
            AttackSurface.INFRASTRUCTURE
        ])
        
        # Conditional surfaces
        if system_description.get('has_api', True):
            surfaces.append(AttackSurface.API_ENDPOINTS)
        
        if system_description.get('has_training_pipeline', True):
            surfaces.extend([
                AttackSurface.TRAINING_PIPELINE,
                AttackSurface.DATA_STORAGE
            ])
        
        if system_description.get('has_admin_interface', True):
            surfaces.append(AttackSurface.ADMIN_INTERFACE)
        
        if system_description.get('has_third_party_integrations', False):
            surfaces.append(AttackSurface.THIRD_PARTY_INTEGRATIONS)
        
        surfaces.append(AttackSurface.INFERENCE_ENGINE)
        
        return surfaces
    
    def _generate_threats(
        self,
        assets: List[Asset],
        threat_actors: List[ThreatActor],
        attack_surfaces: List[AttackSurface],
        business_context: Dict[str, Any]
    ) -> List[Threat]:
        """Generate specific threats based on assets, actors, and surfaces."""
        
        threats = []
        threat_counter = 1
        
        # Generate threats for each category
        for category, threat_templates in self.threat_library.items():
            for template in threat_templates:
                # Check if threat is relevant to current system
                relevant_surfaces = [s for s in template["target_surfaces"] if s in attack_surfaces]
                
                if not relevant_surfaces:
                    continue
                
                # Find applicable threat actors
                applicable_actors = []
                required_sophistication = template["sophistication_required"]
                
                for actor in threat_actors:
                    if self._actor_can_execute_threat(actor, required_sophistication):
                        applicable_actors.append(actor.actor_id)
                
                if not applicable_actors:
                    continue
                
                # Identify target assets
                target_assets = self._identify_threat_targets(template, assets)
                
                # Generate attack paths
                attack_paths = self._generate_attack_paths(template, relevant_surfaces, target_assets)
                
                # Calculate impact and likelihood
                impact = self._calculate_threat_impact(template, target_assets, business_context)
                likelihood = self._calculate_threat_likelihood(template, applicable_actors, attack_surfaces)
                
                # Calculate risk score
                risk_score = self._calculate_threat_risk_score(impact, likelihood, template)
                
                # Create threat
                threat = Threat(
                    threat_id=f"THR-{threat_counter:03d}",
                    name=template["name"],
                    description=template["description"],
                    category=category,
                    threat_actors=applicable_actors,
                    target_assets=[asset.asset_id for asset in target_assets],
                    attack_surfaces=relevant_surfaces,
                    attack_paths=attack_paths,
                    impact_level=impact,
                    likelihood=likelihood,
                    existing_controls=self._identify_existing_controls(template, business_context),
                    risk_score=risk_score
                )
                
                threats.append(threat)
                threat_counter += 1
        
        # Sort threats by risk score
        threats.sort(key=lambda t: t.risk_score, reverse=True)
        
        return threats
    
    def _actor_can_execute_threat(self, actor: ThreatActor, required_sophistication: str) -> bool:
        """Check if threat actor can execute threat based on sophistication."""
        
        sophistication_levels = ["basic", "intermediate", "advanced", "expert"]
        
        actor_level_index = sophistication_levels.index(actor.sophistication_level)
        required_level_index = sophistication_levels.index(required_sophistication)
        
        return actor_level_index >= required_level_index
    
    def _identify_threat_targets(self, template: Dict, assets: List[Asset]) -> List[Asset]:
        """Identify assets that could be targeted by this threat."""
        
        target_assets = []
        impact_categories = template.get("impact_categories", [])
        
        for asset in assets:
            # Match based on asset type and impact categories
            if any(category in impact_categories for category in 
                   ["data_access", "system_compromise", "privilege_escalation", "information_extraction"]):
                if asset.criticality in ["critical", "high"]:
                    target_assets.append(asset)
            elif "service_disruption" in impact_categories:
                if asset.asset_type in ["service", "infrastructure"]:
                    target_assets.append(asset)
            elif "intellectual_property_theft" in impact_categories:
                if asset.asset_type in ["ai_model", "data"] and asset.data_classification in ["confidential", "restricted"]:
                    target_assets.append(asset)
        
        return target_assets
    
    def _generate_attack_paths(
        self,
        template: Dict,
        attack_surfaces: List[AttackSurface],
        target_assets: List[Asset]
    ) -> List[AttackPath]:
        """Generate attack paths for threat."""
        
        paths = []
        
        for surface in attack_surfaces:
            path_id = f"PATH-{len(paths) + 1}"
            
            # Generate attack steps based on attack vectors
            attack_steps = []
            for vector in template.get("attack_vectors", []):
                attack_steps.append({
                    "step": len(attack_steps) + 1,
                    "technique": vector,
                    "description": f"Execute {vector} against {surface.value}",
                    "required_access": self._determine_required_access(vector, surface)
                })
            
            # Determine required capabilities
            required_capabilities = template.get("attack_vectors", [])
            
            # Assess detection difficulty
            detection_difficulty = self._assess_detection_difficulty(template, surface)
            
            path = AttackPath(
                path_id=path_id,
                entry_point=surface,
                attack_steps=attack_steps,
                target_assets=[asset.asset_id for asset in target_assets],
                required_capabilities=required_capabilities,
                detection_difficulty=detection_difficulty
            )
            
            paths.append(path)
        
        return paths
    
    def _determine_required_access(self, attack_vector: str, surface: AttackSurface) -> str:
        """Determine required access level for attack vector."""
        
        access_requirements = {
            "prompt_injection": "user_access",
            "data_injection": "admin_access",
            "system_compromise": "root_access",
            "credential_theft": "user_access",
            "social_engineering": "no_access",
            "supply_chain_attack": "vendor_access"
        }
        
        return access_requirements.get(attack_vector, "user_access")
    
    def _assess_detection_difficulty(self, template: Dict, surface: AttackSurface) -> str:
        """Assess difficulty of detecting attack."""
        
        sophistication = template.get("sophistication_required", "intermediate")
        
        # Base difficulty mapping
        difficulty_mapping = {
            "basic": "easy",
            "intermediate": "moderate", 
            "advanced": "difficult",
            "expert": "very_difficult"
        }
        
        base_difficulty = difficulty_mapping.get(sophistication, "moderate")
        
        # Adjust for attack surface
        if surface in [AttackSurface.MODEL_INTERFACE, AttackSurface.API_ENDPOINTS]:
            # More logging and monitoring typically available
            if base_difficulty == "easy":
                return "easy"
            else:
                return difficulty_mapping.get(
                    ["basic", "intermediate", "advanced", "expert"][
                        max(0, ["basic", "intermediate", "advanced", "expert"].index(sophistication) - 1)
                    ],
                    "easy"
                )
        
        return base_difficulty
    
    def _calculate_threat_impact(
        self,
        template: Dict,
        target_assets: List[Asset],
        business_context: Dict[str, Any]
    ) -> ThreatImpact:
        """Calculate threat impact level."""
        
        impact_categories = template.get("impact_categories", [])
        
        # Determine base impact
        base_impact_score = 2  # Default moderate
        
        # Adjust based on impact categories
        if any(cat in impact_categories for cat in ["system_compromise", "model_corruption", "backdoor_insertion"]):
            base_impact_score = 5
        elif any(cat in impact_categories for cat in ["privilege_escalation", "data_access", "intellectual_property_theft"]):
            base_impact_score = 4
        elif any(cat in impact_categories for cat in ["service_disruption", "privacy_violation"]):
            base_impact_score = 3
        
        # Adjust based on target asset criticality
        if target_assets:
            max_criticality = max(
                {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(asset.criticality, 1)
                for asset in target_assets
            )
            base_impact_score = min(5, base_impact_score + max_criticality - 2)
        
        # Adjust based on business context
        if business_context.get('public_facing', False):
            base_impact_score = min(5, base_impact_score + 1)
        
        if business_context.get('regulatory_environment') in ['financial', 'healthcare']:
            base_impact_score = min(5, base_impact_score + 1)
        
        # Map to enum
        impact_mapping = {
            5: ThreatImpact.CATASTROPHIC,
            4: ThreatImpact.SEVERE,
            3: ThreatImpact.MODERATE,
            2: ThreatImpact.MINOR,
            1: ThreatImpact.NEGLIGIBLE
        }
        
        return impact_mapping.get(base_impact_score, ThreatImpact.MODERATE)
    
    def _calculate_threat_likelihood(
        self,
        template: Dict,
        applicable_actors: List[str],
        attack_surfaces: List[AttackSurface]
    ) -> ThreatLikelihood:
        """Calculate threat likelihood level."""
        
        # Base likelihood from sophistication (easier = more likely)
        sophistication = template.get("sophistication_required", "intermediate")
        sophistication_likelihood = {
            "basic": 4,        # Likely
            "intermediate": 3, # Possible
            "advanced": 2,     # Unlikely
            "expert": 1        # Rare
        }
        
        base_likelihood = sophistication_likelihood.get(sophistication, 3)
        
        # Adjust based on number of applicable threat actors
        if len(applicable_actors) >= 4:
            base_likelihood = min(5, base_likelihood + 2)
        elif len(applicable_actors) >= 2:
            base_likelihood = min(5, base_likelihood + 1)
        
        # Adjust based on attack surface exposure
        high_exposure_surfaces = [
            AttackSurface.MODEL_INTERFACE,
            AttackSurface.API_ENDPOINTS,
            AttackSurface.THIRD_PARTY_INTEGRATIONS
        ]
        
        exposed_surfaces = [s for s in attack_surfaces if s in high_exposure_surfaces]
        if len(exposed_surfaces) >= 2:
            base_likelihood = min(5, base_likelihood + 1)
        
        # Map to enum
        likelihood_mapping = {
            5: ThreatLikelihood.ALMOST_CERTAIN,
            4: ThreatLikelihood.LIKELY,
            3: ThreatLikelihood.POSSIBLE,
            2: ThreatLikelihood.UNLIKELY,
            1: ThreatLikelihood.RARE
        }
        
        return likelihood_mapping.get(base_likelihood, ThreatLikelihood.POSSIBLE)
    
    def _calculate_threat_risk_score(
        self,
        impact: ThreatImpact,
        likelihood: ThreatLikelihood,
        template: Dict
    ) -> float:
        """Calculate overall threat risk score."""
        
        impact_score = self.risk_matrices["impact_scores"][impact]
        likelihood_score = self.risk_matrices["likelihood_scores"][likelihood]
        
        # Base risk calculation
        base_risk = impact_score * likelihood_score
        
        # Apply sophistication multiplier (more sophisticated = potentially higher impact but lower likelihood)
        sophistication = template.get("sophistication_required", "intermediate")
        sophistication_multiplier = self.risk_matrices["sophistication_multipliers"].get(sophistication, 1.0)
        
        final_risk = base_risk * sophistication_multiplier
        
        # Normalize to 0-10 scale
        return min(10.0, final_risk)
    
    def _identify_existing_controls(
        self,
        template: Dict,
        business_context: Dict[str, Any]
    ) -> List[str]:
        """Identify existing controls that might mitigate threat."""
        
        controls = []
        
        # Standard controls based on threat category
        attack_vectors = template.get("attack_vectors", [])
        
        if "prompt_injection" in attack_vectors:
            controls.extend(["input_validation", "content_filtering", "prompt_sanitization"])
        
        if "social_engineering" in attack_vectors:
            controls.extend(["security_awareness_training", "multi_factor_authentication"])
        
        if "system_compromise" in attack_vectors:
            controls.extend(["endpoint_protection", "network_segmentation", "access_controls"])
        
        if "data_injection" in attack_vectors:
            controls.extend(["data_validation", "supply_chain_security", "integrity_monitoring"])
        
        # Business context-specific controls
        if business_context.get('has_security_team', True):
            controls.append("security_monitoring")
        
        if business_context.get('compliance_framework'):
            controls.extend(["compliance_controls", "audit_logging"])
        
        return list(set(controls))  # Remove duplicates
    
    def _define_trust_boundaries(self, system_description: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Define trust boundaries in the system."""
        
        boundaries = []
        
        # External to DMZ boundary
        boundaries.append({
            "boundary_id": "external_dmz",
            "name": "External to DMZ",
            "description": "Boundary between untrusted internet and DMZ",
            "components": ["api_gateway", "load_balancer"],
            "security_controls": ["firewall", "ddos_protection", "rate_limiting"]
        })
        
        # DMZ to internal boundary
        boundaries.append({
            "boundary_id": "dmz_internal",
            "name": "DMZ to Internal Network",
            "description": "Boundary between DMZ and internal network",
            "components": ["application_servers", "authentication_service"],
            "security_controls": ["internal_firewall", "network_segmentation", "access_controls"]
        })
        
        # Application to data boundary
        boundaries.append({
            "boundary_id": "app_data",
            "name": "Application to Data Layer",
            "description": "Boundary between application logic and data storage",
            "components": ["database", "model_storage", "training_data"],
            "security_controls": ["database_access_controls", "encryption", "audit_logging"]
        })
        
        # Admin boundary
        if system_description.get('has_admin_interface', True):
            boundaries.append({
                "boundary_id": "admin_boundary",
                "name": "Administrative Access Boundary",
                "description": "Boundary for administrative functions",
                "components": ["admin_interface", "system_management"],
                "security_controls": ["privileged_access_management", "admin_authentication", "activity_monitoring"]
            })
        
        return boundaries
    
    def _document_assumptions(self, system_description: Dict[str, Any]) -> List[str]:
        """Document threat modeling assumptions."""
        
        assumptions = [
            "System is deployed in a secure cloud environment with standard security controls",
            "Users are authenticated through a secure authentication mechanism",
            "Network communications use encrypted protocols (TLS/HTTPS)",
            "System administrators follow security best practices",
            "Regular security updates and patches are applied",
            "Monitoring and logging systems are in place and functioning",
            "Incident response procedures exist and are regularly tested"
        ]
        
        # Add context-specific assumptions
        if system_description.get('cloud_deployment', True):
            assumptions.append("Cloud provider implements appropriate physical and infrastructure security")
        
        if system_description.get('has_third_party_integrations', False):
            assumptions.append("Third-party integrations follow security best practices")
        
        if system_description.get('handles_pii', False):
            assumptions.append("Data protection and privacy controls comply with applicable regulations")
        
        return assumptions
    
    def _define_scope_exclusions(self, system_description: Dict[str, Any]) -> List[str]:
        """Define what is out of scope for threat modeling."""
        
        out_of_scope = [
            "Physical security of data centers (assumed secure)",
            "Cloud provider infrastructure security (assumed secure)",
            "Third-party service security (assumed secure)",
            "Social engineering attacks against end users",
            "Natural disasters and environmental threats",
            "Regulatory compliance requirements (separate assessment)",
            "Business continuity and disaster recovery",
            "Hardware failure and reliability issues"
        ]
        
        return out_of_scope
    
    def analyze_threat_model(self, threat_model: ThreatModel) -> Dict[str, Any]:
        """
        Analyze threat model to generate insights and recommendations.
        
        Returns comprehensive analysis with risk metrics and strategic recommendations.
        """
        self.logger.info(f"Analyzing threat model for {threat_model.system_name}")
        
        # Threat analysis
        threat_analysis = self._analyze_threats(threat_model.threats)
        
        # Actor analysis
        actor_analysis = self._analyze_threat_actors(threat_model.threat_actors, threat_model.threats)
        
        # Attack surface analysis
        surface_analysis = self._analyze_attack_surfaces(threat_model.attack_surfaces, threat_model.threats)
        
        # Asset risk analysis
        asset_analysis = self._analyze_asset_risks(threat_model.assets, threat_model.threats)
        
        # Risk prioritization
        risk_priorities = self._prioritize_risks(threat_model.threats)
        
        # Control gap analysis
        control_gaps = self._analyze_control_gaps(threat_model.threats)
        
        return {
            'analysis_timestamp': datetime.now().isoformat(),
            'threat_model_id': threat_model.model_id,
            'system_name': threat_model.system_name,
            'threat_analysis': threat_analysis,
            'actor_analysis': actor_analysis,
            'surface_analysis': surface_analysis,
            'asset_analysis': asset_analysis,
            'risk_priorities': risk_priorities,
            'control_gaps': control_gaps,
            'executive_summary': self._generate_threat_executive_summary(threat_analysis, risk_priorities),
            'strategic_recommendations': self._generate_threat_recommendations(
                threat_analysis, control_gaps, risk_priorities
            )
        }
    
    def _analyze_threats(self, threats: List[Threat]) -> Dict[str, Any]:
        """Analyze threat patterns and metrics."""
        
        if not threats:
            return {'error': 'No threats to analyze'}
        
        # Risk score statistics
        risk_scores = [t.risk_score for t in threats]
        risk_stats = {
            'total_threats': len(threats),
            'mean_risk_score': statistics.mean(risk_scores),
            'median_risk_score': statistics.median(risk_scores),
            'max_risk_score': max(risk_scores),
            'std_deviation': statistics.stdev(risk_scores) if len(risk_scores) > 1 else 0
        }
        
        # Threat category distribution
        category_counts = defaultdict(int)
        category_risk_scores = defaultdict(list)
        
        for threat in threats:
            category = threat.category.value
            category_counts[category] += 1
            category_risk_scores[category].append(threat.risk_score)
        
        category_analysis = {}
        for category, scores in category_risk_scores.items():
            category_analysis[category] = {
                'count': category_counts[category],
                'avg_risk_score': statistics.mean(scores),
                'max_risk_score': max(scores),
                'threat_ids': [t.threat_id for t in threats if t.category.value == category]
            }
        
        # Impact/likelihood distribution
        impact_counts = defaultdict(int)
        likelihood_counts = defaultdict(int)
        
        for threat in threats:
            impact_counts[threat.impact_level.value] += 1
            likelihood_counts[threat.likelihood.value] += 1
        
        # High-risk threats
        high_risk_threats = [t for t in threats if t.risk_score >= 7.0]
        critical_threats = [t for t in threats if t.risk_score >= 9.0]
        
        return {
            'risk_statistics': risk_stats,
            'category_analysis': category_analysis,
            'impact_distribution': dict(impact_counts),
            'likelihood_distribution': dict(likelihood_counts),
            'high_risk_threat_count': len(high_risk_threats),
            'critical_threat_count': len(critical_threats),
            'top_threats': sorted(threats, key=lambda t: t.risk_score, reverse=True)[:5]
        }
    
    def _analyze_threat_actors(
        self,
        threat_actors: List[ThreatActor],
        threats: List[Threat]
    ) -> Dict[str, Any]:
        """Analyze threat actor patterns and capabilities."""
        
        actor_threat_counts = defaultdict(int)
        actor_risk_scores = defaultdict(list)
        
        for threat in threats:
            for actor_id in threat.threat_actors:
                actor_threat_counts[actor_id] += 1
                actor_risk_scores[actor_id].append(threat.risk_score)
        
        actor_analysis = {}
        for actor in threat_actors:
            threat_count = actor_threat_counts[actor.actor_id]
            risk_scores = actor_risk_scores[actor.actor_id]
            
            actor_analysis[actor.actor_id] = {
                'actor_type': actor.actor_type.value,
                'sophistication': actor.sophistication_level,
                'threat_count': threat_count,
                'avg_threat_risk': statistics.mean(risk_scores) if risk_scores else 0,
                'max_threat_risk': max(risk_scores) if risk_scores else 0,
                'primary_motivations': actor.motivations
            }
        
        # Most active/dangerous actors
        most_active = max(actor_analysis.items(), key=lambda x: x[1]['threat_count'], default=(None, None))
        most_dangerous = max(actor_analysis.items(), key=lambda x: x[1]['avg_threat_risk'], default=(None, None))
        
        return {
            'total_actors': len(threat_actors),
            'actor_analysis': actor_analysis,
            'most_active_actor': most_active[0] if most_active[0] else None,
            'most_dangerous_actor': most_dangerous[0] if most_dangerous[0] else None
        }
    
    def _analyze_attack_surfaces(
        self,
        attack_surfaces: List[AttackSurface],
        threats: List[Threat]
    ) -> Dict[str, Any]:
        """Analyze attack surface exposure and risk."""
        
        surface_threat_counts = defaultdict(int)
        surface_risk_scores = defaultdict(list)
        
        for threat in threats:
            for surface in threat.attack_surfaces:
                surface_threat_counts[surface.value] += 1
                surface_risk_scores[surface.value].append(threat.risk_score)
        
        surface_analysis = {}
        for surface in attack_surfaces:
            surface_value = surface.value
            threat_count = surface_threat_counts[surface_value]
            risk_scores = surface_risk_scores[surface_value]
            
            surface_analysis[surface_value] = {
                'threat_count': threat_count,
                'avg_threat_risk': statistics.mean(risk_scores) if risk_scores else 0,
                'max_threat_risk': max(risk_scores) if risk_scores else 0,
                'exposure_level': 'high' if threat_count > 3 else 'medium' if threat_count > 1 else 'low'
            }
        
        # Highest risk surface
        highest_risk_surface = max(
            surface_analysis.items(),
            key=lambda x: x[1]['avg_threat_risk'],
            default=(None, None)
        )
        
        return {
            'total_surfaces': len(attack_surfaces),
            'surface_analysis': surface_analysis,
            'highest_risk_surface': highest_risk_surface[0] if highest_risk_surface[0] else None
        }
    
    def _analyze_asset_risks(self, assets: List[Asset], threats: List[Threat]) -> Dict[str, Any]:
        """Analyze risks to individual assets."""
        
        asset_threat_counts = defaultdict(int)
        asset_risk_scores = defaultdict(list)
        
        for threat in threats:
            for asset_id in threat.target_assets:
                asset_threat_counts[asset_id] += 1
                asset_risk_scores[asset_id].append(threat.risk_score)
        
        asset_analysis = {}
        for asset in assets:
            threat_count = asset_threat_counts[asset.asset_id]
            risk_scores = asset_risk_scores[asset.asset_id]
            
            asset_analysis[asset.asset_id] = {
                'asset_name': asset.name,
                'criticality': asset.criticality,
                'threat_count': threat_count,
                'avg_threat_risk': statistics.mean(risk_scores) if risk_scores else 0,
                'max_threat_risk': max(risk_scores) if risk_scores else 0,
                'risk_level': self._calculate_asset_risk_level(asset, risk_scores)
            }
        
        # Highest risk assets
        high_risk_assets = [
            asset_id for asset_id, analysis in asset_analysis.items()
            if analysis['risk_level'] in ['critical', 'high']
        ]
        
        return {
            'total_assets': len(assets),
            'asset_analysis': asset_analysis,
            'high_risk_asset_count': len(high_risk_assets),
            'high_risk_assets': high_risk_assets
        }
    
    def _calculate_asset_risk_level(self, asset: Asset, risk_scores: List[float]) -> str:
        """Calculate overall risk level for asset."""
        
        if not risk_scores:
            return 'low'
        
        max_risk = max(risk_scores)
        avg_risk = statistics.mean(risk_scores)
        
        # Consider asset criticality
        criticality_multiplier = {
            'critical': 1.5,
            'high': 1.2,
            'medium': 1.0,
            'low': 0.8
        }.get(asset.criticality, 1.0)
        
        adjusted_risk = avg_risk * criticality_multiplier
        
        if max_risk >= 9.0 or adjusted_risk >= 8.0:
            return 'critical'
        elif max_risk >= 7.0 or adjusted_risk >= 6.0:
            return 'high'
        elif max_risk >= 5.0 or adjusted_risk >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def _prioritize_risks(self, threats: List[Threat]) -> List[Dict[str, Any]]:
        """Prioritize risks for remediation."""
        
        # Sort threats by risk score
        sorted_threats = sorted(threats, key=lambda t: t.risk_score, reverse=True)
        
        priorities = []
        for i, threat in enumerate(sorted_threats[:10], 1):  # Top 10 priorities
            priority = {
                'rank': i,
                'threat_id': threat.threat_id,
                'threat_name': threat.name,
                'risk_score': threat.risk_score,
                'category': threat.category.value,
                'impact': threat.impact_level.value,
                'likelihood': threat.likelihood.value,
                'urgency': self._determine_threat_urgency(threat),
                'recommended_timeline': self._recommend_threat_timeline(threat)
            }
            priorities.append(priority)
        
        return priorities
    
    def _determine_threat_urgency(self, threat: Threat) -> str:
        """Determine urgency level for threat remediation."""
        
        if threat.risk_score >= 9.0:
            return 'immediate'
        elif threat.risk_score >= 7.5:
            return 'urgent'
        elif threat.risk_score >= 6.0:
            return 'high'
        elif threat.risk_score >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def _recommend_threat_timeline(self, threat: Threat) -> str:
        """Recommend remediation timeline for threat."""
        
        urgency = self._determine_threat_urgency(threat)
        
        timeline_mapping = {
            'immediate': '24-48 hours',
            'urgent': '1 week',
            'high': '1 month',
            'medium': '3 months',
            'low': '6 months'
        }
        
        return timeline_mapping.get(urgency, '3 months')
    
    def _analyze_control_gaps(self, threats: List[Threat]) -> Dict[str, Any]:
        """Analyze gaps in existing security controls."""
        
        # Collect all existing controls
        all_controls = set()
        threat_control_mapping = {}
        
        for threat in threats:
            controls = set(threat.existing_controls)
            all_controls.update(controls)
            threat_control_mapping[threat.threat_id] = controls
        
        # Identify threats with insufficient controls
        insufficient_control_threats = []
        for threat in threats:
            controls = threat_control_mapping[threat.threat_id]
            
            # Consider threat insufficiently controlled if high risk with few controls
            if threat.risk_score >= 6.0 and len(controls) < 3:
                insufficient_control_threats.append({
                    'threat_id': threat.threat_id,
                    'threat_name': threat.name,
                    'risk_score': threat.risk_score,
                    'existing_controls': list(controls),
                    'control_gap': self._identify_control_gap(threat, controls)
                })
        
        # Recommend additional controls
        control_recommendations = self._recommend_additional_controls(threats)
        
        return {
            'total_controls_identified': len(all_controls),
            'insufficient_control_threats': insufficient_control_threats,
            'control_recommendations': control_recommendations,
            'control_coverage_gaps': self._identify_coverage_gaps(threats, all_controls)
        }
    
    def _identify_control_gap(self, threat: Threat, existing_controls: set) -> List[str]:
        """Identify specific control gaps for threat."""
        
        recommended_controls = set()
        
        # Category-specific control recommendations
        if threat.category == ThreatCategory.TAMPERING:
            recommended_controls.update(['input_validation', 'integrity_monitoring', 'secure_coding'])
        elif threat.category == ThreatCategory.INFORMATION_DISCLOSURE:
            recommended_controls.update(['access_controls', 'data_encryption', 'data_loss_prevention'])
        elif threat.category == ThreatCategory.DENIAL_OF_SERVICE:
            recommended_controls.update(['rate_limiting', 'resource_monitoring', 'ddos_protection'])
        elif threat.category == ThreatCategory.ELEVATION_OF_PRIVILEGE:
            recommended_controls.update(['least_privilege', 'privilege_monitoring', 'access_reviews'])
        elif threat.category == ThreatCategory.SPOOFING:
            recommended_controls.update(['strong_authentication', 'identity_verification', 'session_management'])
        
        # Return missing controls
        return list(recommended_controls - existing_controls)
    
    def _recommend_additional_controls(self, threats: List[Threat]) -> List[Dict[str, Any]]:
        """Recommend additional security controls."""
        
        recommendations = []
        
        # High-risk threats without sufficient controls
        high_risk_threats = [t for t in threats if t.risk_score >= 7.0 and len(t.existing_controls) < 4]
        
        if len(high_risk_threats) > 3:
            recommendations.append({
                'priority': 'high',
                'control_type': 'monitoring',
                'recommendation': 'Implement comprehensive security monitoring and alerting',
                'rationale': f'{len(high_risk_threats)} high-risk threats require enhanced detection'
            })
        
        # Category-specific recommendations
        tampering_threats = [t for t in threats if t.category == ThreatCategory.TAMPERING and t.risk_score >= 6.0]
        if len(tampering_threats) > 2:
            recommendations.append({
                'priority': 'high',
                'control_type': 'preventive',
                'recommendation': 'Deploy advanced input validation and prompt filtering',
                'rationale': 'Multiple high-risk tampering threats identified'
            })
        
        return recommendations
    
    def _identify_coverage_gaps(self, threats: List[Threat], all_controls: set) -> List[str]:
        """Identify areas with insufficient control coverage."""
        
        gaps = []
        
        # Check for fundamental security controls
        fundamental_controls = {
            'access_controls', 'authentication', 'authorization',
            'input_validation', 'audit_logging', 'encryption'
        }
        
        missing_fundamentals = fundamental_controls - all_controls
        if missing_fundamentals:
            gaps.extend([f'Missing fundamental control: {control}' for control in missing_fundamentals])
        
        # Check for AI-specific controls
        ai_specific_controls = {
            'prompt_filtering', 'model_integrity_monitoring',
            'ai_output_validation', 'training_data_validation'
        }
        
        missing_ai_controls = ai_specific_controls - all_controls
        if missing_ai_controls:
            gaps.extend([f'Missing AI-specific control: {control}' for control in missing_ai_controls])
        
        return gaps
    
    def _generate_threat_executive_summary(
        self,
        threat_analysis: Dict[str, Any],
        risk_priorities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate executive summary of threat analysis."""
        
        total_threats = threat_analysis.get('risk_statistics', {}).get('total_threats', 0)
        critical_threats = threat_analysis.get('critical_threat_count', 0)
        high_risk_threats = threat_analysis.get('high_risk_threat_count', 0)
        avg_risk_score = threat_analysis.get('risk_statistics', {}).get('mean_risk_score', 0)
        
        # Risk level assessment
        if critical_threats >= 3:
            risk_level = "CRITICAL"
            risk_statement = "Multiple critical threats identified requiring immediate executive attention and resource allocation"
        elif critical_threats >= 1 or high_risk_threats >= 5:
            risk_level = "HIGH"
            risk_statement = "Significant security threats require urgent strategic planning and investment"
        elif high_risk_threats >= 2 or avg_risk_score >= 5.0:
            risk_level = "MEDIUM"
            risk_statement = "Moderate security risks requiring systematic threat mitigation planning"
        else:
            risk_level = "LOW"
            risk_statement = "Security posture adequate with manageable threat levels"
        
        # Immediate actions required
        immediate_actions = len([p for p in risk_priorities if p.get('urgency') == 'immediate'])
        urgent_actions = len([p for p in risk_priorities if p.get('urgency') == 'urgent'])
        
        return {
            'risk_level': risk_level,
            'risk_statement': risk_statement,
            'total_threats_identified': total_threats,
            'critical_threats': critical_threats,
            'high_risk_threats': high_risk_threats,
            'average_risk_score': avg_risk_score,
            'immediate_actions_required': immediate_actions,
            'urgent_actions_required': urgent_actions,
            'executive_action_required': risk_level in ['CRITICAL', 'HIGH'] or immediate_actions > 0
        }
    
    def _generate_threat_recommendations(
        self,
        threat_analysis: Dict[str, Any],
        control_gaps: Dict[str, Any],
        risk_priorities: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate strategic threat mitigation recommendations."""
        
        recommendations = []
        
        # Executive-level recommendations
        risk_level = threat_analysis.get('risk_statistics', {}).get('mean_risk_score', 0)
        critical_threats = threat_analysis.get('critical_threat_count', 0)
        
        if critical_threats >= 2:
            recommendations.append(
                "EXECUTIVE: Establish emergency security response committee for critical threat mitigation"
            )
        
        if risk_level >= 7.0:
            recommendations.append(
                "STRATEGIC: Implement comprehensive AI security framework with dedicated resources"
            )
        
        # Control gap recommendations
        insufficient_controls = len(control_gaps.get('insufficient_control_threats', []))
        if insufficient_controls > 3:
            recommendations.append(
                "OPERATIONAL: Strengthen security controls for high-risk threats identified"
            )
        
        # Category-specific recommendations
        category_analysis = threat_analysis.get('category_analysis', {})
        
        # High tampering risk
        if category_analysis.get('tampering', {}).get('avg_risk_score', 0) >= 6.0:
            recommendations.append(
                "TECHNICAL: Deploy advanced prompt injection protection and input validation"
            )
        
        # High information disclosure risk
        if category_analysis.get('information_disclosure', {}).get('avg_risk_score', 0) >= 6.0:
            recommendations.append(
                "TECHNICAL: Implement data loss prevention and model output monitoring"
            )
        
        # Timeline-based recommendations
        immediate_count = len([p for p in risk_priorities if p.get('urgency') == 'immediate'])
        if immediate_count >= 3:
            recommendations.append(
                "RESOURCE: Scale security engineering capacity for immediate threat response"
            )
        
        # Always include professional consultation
        recommendations.append(
            "STRATEGIC: Consider professional threat modeling consultation from VerityAI for comprehensive security architecture"
        )
        
        return recommendations[:8]
    
    def generate_threat_model_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate comprehensive threat modeling report."""
        
        threat_analysis = analysis_results.get('threat_analysis', {})
        exec_summary = analysis_results.get('executive_summary', {})
        risk_priorities = analysis_results.get('risk_priorities', [])
        
        # Determine risk emoji
        risk_level = exec_summary.get('risk_level', 'UNKNOWN')
        risk_emoji = {
            'CRITICAL': '🚨', 'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'
        }.get(risk_level, '❓')
        
        report = f"""
# LLM Security Threat Model Report

**Assessment Date**: {datetime.now().strftime('%B %d, %Y')}
**System**: {analysis_results.get('system_name', 'LLM System')}
**Prepared by**: Sotiris Spyrou | VerityAI LLM Security Services

## Executive Summary

### Threat Risk Level: {risk_emoji} {risk_level}

{exec_summary.get('risk_statement', 'Risk assessment unavailable')}

**Key Threat Metrics:**
- **Total Threats Identified**: {exec_summary.get('total_threats_identified', 0):,}
- **Critical Threats**: {exec_summary.get('critical_threats', 0)}
- **High-Risk Threats**: {exec_summary.get('high_risk_threats', 0)}
- **Average Risk Score**: {exec_summary.get('average_risk_score', 0):.1f}/10.0
- **Immediate Actions Required**: {exec_summary.get('immediate_actions_required', 0)}
- **Urgent Actions Required**: {exec_summary.get('urgent_actions_required', 0)}

### Threat Landscape Assessment
"""
        
        # Threat category breakdown
        category_analysis = threat_analysis.get('category_analysis', {})
        report += f"""
#### Threat Categories by Risk Level
"""
        for category, stats in sorted(category_analysis.items(), key=lambda x: x[1]['avg_risk_score'], reverse=True):
            category_name = category.replace('_', ' ').title()
            avg_risk = stats['avg_risk_score']
            threat_count = stats['count']
            risk_level_cat = 'Critical' if avg_risk >= 8 else 'High' if avg_risk >= 6 else 'Medium' if avg_risk >= 4 else 'Low'
            
            report += f"- **{category_name}**: {threat_count} threats, {avg_risk:.1f} avg risk ({risk_level_cat})\n"
        
        # Top risk priorities
        report += f"""

### Top Risk Priorities
"""
        for priority in risk_priorities[:5]:
            urgency_emoji = {
                'immediate': '🚨', 'urgent': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'
            }.get(priority['urgency'], '❓')
            
            report += f"""
**{priority['rank']}. {priority['threat_name']}** {urgency_emoji}
- Risk Score: {priority['risk_score']:.1f}/10.0
- Category: {priority['category'].replace('_', ' ').title()}
- Impact: {priority['impact'].title()}
- Timeline: {priority['recommended_timeline']}
"""
        
        # Threat actor analysis
        actor_analysis = analysis_results.get('actor_analysis', {})
        report += f"""

### Threat Actor Assessment
- **Total Threat Actors**: {actor_analysis.get('total_actors', 0)}
- **Most Active Actor**: {actor_analysis.get('most_active_actor', 'Unknown')}
- **Most Dangerous Actor**: {actor_analysis.get('most_dangerous_actor', 'Unknown')}

#### Actor Threat Distribution
"""
        
        actor_details = actor_analysis.get('actor_analysis', {})
        for actor_id, details in actor_details.items():
            actor_type = details['actor_type'].replace('_', ' ').title()
            threat_count = details['threat_count']
            avg_risk = details['avg_threat_risk']
            
            report += f"- **{actor_type}**: {threat_count} threats, {avg_risk:.1f} avg risk\n"
        
        # Attack surface analysis
        surface_analysis = analysis_results.get('surface_analysis', {})
        highest_risk_surface = surface_analysis.get('highest_risk_surface', 'Unknown')
        
        report += f"""

### Attack Surface Analysis
- **Highest Risk Surface**: {highest_risk_surface.replace('_', ' ').title() if highest_risk_surface != 'Unknown' else 'Unknown'}

#### Surface Risk Breakdown
"""
        
        surface_details = surface_analysis.get('surface_analysis', {})
        for surface, details in surface_details.items():
            surface_name = surface.replace('_', ' ').title()
            threat_count = details['threat_count']
            avg_risk = details['avg_threat_risk']
            exposure = details['exposure_level']
            
            report += f"- **{surface_name}**: {threat_count} threats, {avg_risk:.1f} avg risk ({exposure} exposure)\n"
        
        # Control gap analysis
        control_gaps = analysis_results.get('control_gaps', {})
        report += f"""

### Security Control Assessment
- **Controls Identified**: {control_gaps.get('total_controls_identified', 0)}
- **Insufficient Control Threats**: {len(control_gaps.get('insufficient_control_threats', []))}

#### Control Recommendations
"""
        
        control_recommendations = control_gaps.get('control_recommendations', [])
        for i, rec in enumerate(control_recommendations, 1):
            priority = rec['priority'].upper()
            recommendation = rec['recommendation']
            report += f"{i}. **{priority}**: {recommendation}\n"
        
        # Strategic recommendations
        recommendations = analysis_results.get('strategic_recommendations', [])
        report += f"""

### Strategic Recommendations
"""
        for i, rec in enumerate(recommendations, 1):
            priority = rec.split(':')[0]
            action = ':'.join(rec.split(':')[1:]).strip()
            report += f"{i}. **{priority}**: {action}\n"
        
        report += f"""

### Risk Management Priorities
- **Executive Action Required**: {'Yes' if exec_summary.get('executive_action_required', False) else 'No'}
- **Immediate Timeline Items**: {len([p for p in risk_priorities if p['urgency'] == 'immediate'])}
- **Resource Allocation**: {'Critical - Scale Security Team' if risk_level == 'CRITICAL' else 'Standard - Current Resources Adequate'}

### Implementation Roadmap
1. **Phase 1 (0-30 days)**: Address all immediate and urgent threats
2. **Phase 2 (1-3 months)**: Implement high-priority security controls
3. **Phase 3 (3-6 months)**: Complete medium-priority threat mitigation
4. **Phase 4 (6+ months)**: Continuous monitoring and threat model updates

---

**Professional LLM Threat Modeling Services**
For comprehensive threat modeling and security architecture design:
- **VerityAI LLM Security Services**: [https://verityai.co](https://verityai.co)
- **Expert Consultation**: [Sotiris Spyrou](https://www.linkedin.com/in/sspyrou/)

*Portfolio demonstration - Contact for production threat modeling services*
"""
        
        return report

def main():
    """Portfolio demonstration of threat modeling framework."""
    print("LLM Security Threat Modeling Framework - Portfolio Demo")
    print("=" * 60)
    
    # Initialize threat modeling framework
    framework = ThreatModelingFramework()
    
    # Define sample system
    system_description = {
        'has_llm_model': True,
        'has_api': True,
        'has_training_data': True,
        'has_admin_interface': True,
        'has_third_party_integrations': True,
        'cloud_deployment': True,
        'handles_pii': True
    }
    
    business_context = {
        'industry': 'financial',
        'public_visibility': 'high',
        'data_sensitivity': 'restricted',
        'handles_user_data': True,
        'handles_financial_data': True,
        'has_valuable_ip': True,
        'regulatory_environment': 'financial',
        'public_facing': True,
        'has_security_team': True,
        'compliance_framework': 'PCI-DSS'
    }
    
    # Create threat model
    threat_model = framework.create_threat_model(
        "Financial LLM Assistant",
        system_description,
        business_context
    )
    
    # Analyze threat model
    analysis_results = framework.analyze_threat_model(threat_model)
    
    # Generate report
    threat_report = framework.generate_threat_model_report(analysis_results)
    
    print("THREAT MODELING COMPLETED")
    print(f"System: {threat_model.system_name}")
    print(f"Threats Identified: {len(threat_model.threats)}")
    print(f"Threat Actors: {len(threat_model.threat_actors)}")
    print(f"Attack Surfaces: {len(threat_model.attack_surfaces)}")
    
    exec_summary = analysis_results['executive_summary']
    print(f"Risk Level: {exec_summary['risk_level']}")
    print(f"Critical Threats: {exec_summary['critical_threats']}")
    print(f"Immediate Actions Required: {exec_summary['immediate_actions_required']}")
    
    print("\nExecutive Threat Model Report:")
    print(threat_report)
    
    print("\n" + "=" * 60)
    print("Portfolio Demo by Sotiris Spyrou")
    print("LinkedIn: https://www.linkedin.com/in/sspyrou/")
    print("Professional LLM Security Services: https://verityai.co")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
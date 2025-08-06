from adversarial_attacks import PromptInjectionTester

# Initialize prompt injection testing framework
injection_tester = PromptInjectionTester()

# Define target AI system
target_system = {
    'type': 'customer_service_chatbot',
    'model': 'gpt-4-based',
    'safety_filters': ['content_filter', 'toxicity_detector'],
    'business_context': 'financial_services'
}

# Generate injection attack vectors
attack_vectors = injection_tester.generate_attack_vectors(
    system_config=target_system,
    attack_types=['system_prompt_override', 'context_manipulation', 'role_confusion'],
    sophistication_levels=['basic', 'intermediate', 'advanced'],
    domain_specific=True
)

# Execute systematic testing
test_results = injection_tester.execute_attack_campaign(
    target=target_system,
    attack_vectors=attack_vectors,
    success_criteria=['system_prompt_exposure', 'unauthorized_actions', 'data_leakage'],
    documentation_level='detailed'
)

print(f"Vulnerabilities Detected: {len(test_results['successful_attacks'])}")
print(f"Critical Vulnerabilities: {test_results['critical_count']}")
print(f"Risk Score: {test_results['overall_risk_score']}/100")

from risk_assessment import BusinessImpactCalculator

# Calculate financial impact of AI security incidents
impact_calculator = BusinessImpactCalculator()

# Define potential incident scenarios
incident_scenarios = [
    {
        'scenario': 'ai_model_manipulation_causes_loan_defaults',
        'probability': 0.15,  # 15% annual probability
        'financial_impact': 5000000,  # $5M potential loss
        'reputation_damage': 'high',
        'regulatory_fines': 2000000  # $2M potential fines
    },
    {
        'scenario': 'customer_data_extraction_via_model_inversion',
        'probability': 0.08,  # 8% annual probability  
        'financial_impact': 12000000,  # $12M potential loss
        'reputation_damage': 'critical',
        'regulatory_fines': 8000000  # $8M potential fines
    }
]

# Calculate expected annual loss
annual_risk_exposure = impact_calculator.calculate_annual_loss_expectancy(
    scenarios=incident_scenarios,
    mitigation_effectiveness=current_security_posture,
    insurance_coverage=cyber_insurance_policy,
    business_continuity_plans=recovery_procedures
)

# Cost-benefit analysis for security investments
security_investment_analysis = impact_calculator.analyze_security_investments(
    current_risk_exposure=annual_risk_exposure,
    proposed_security_measures=security_enhancement_plan,
    investment_costs=security_budget_proposal,
    roi_calculation_period=3  # years
)

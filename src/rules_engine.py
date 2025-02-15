class RulesEngine:
    def __init__(self):
        self.compliance_rules = self._load_compliance_rules()

    def _load_compliance_rules(self):
        """Load compliance rules from configuration"""
        # This could be loaded from a config file
        return {
            'max_wildcard_actions': 0,
            'max_resource_wildcards': 0,
            'prohibited_actions': ['iam:*', 'lambda:*'],
            'required_conditions': ['aws:MultiFactorAuthPresent']
        }

    def evaluate_policy(self, policy_analysis):
        """Evaluate policy against compliance rules"""
        violations = []
        
        # Check for overly permissive actions
        if policy_analysis['overly_permissive']:
            violations.append({
                'severity': 'HIGH',
                'type': 'OVERLY_PERMISSIVE',
                'description': 'Policy contains overly permissive actions',
                'actions': policy_analysis['high_risk_actions']
            })

        # Check for wildcard resources
        if policy_analysis['wildcard_resources']:
            violations.append({
                'severity': 'MEDIUM',
                'type': 'WILDCARD_RESOURCE',
                'description': 'Policy uses wildcard resources'
            })

        return {
            'compliant': len(violations) == 0,
            'violations': violations,
            'recommendations': policy_analysis['recommendations']
        } 
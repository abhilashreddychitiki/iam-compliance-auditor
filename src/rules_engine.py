class RulesEngine:
    def __init__(self):
        self.compliance_rules = self._load_compliance_rules()

    def _load_compliance_rules(self):
        """Load compliance rules from configuration"""
        return {
            'max_wildcard_actions': 0,
            'max_resource_wildcards': 0,
            'prohibited_actions': [
                'iam:*',
                'lambda:*',
                'ec2:*',
                's3:*',
                'rds:*',
                'dynamodb:*'
            ],
            'required_conditions': [
                'aws:MultiFactorAuthPresent',
                'aws:SecureTransport'
            ],
            'high_risk_services': [
                'iam',
                'organizations',
                'lambda',
                'ec2',
                'rds',
                'dynamodb'
            ],
            'security_best_practices': {
                'require_mfa': True,
                'require_ssl': True,
                'deny_root_account': True,
                'resource_constraints': True
            }
        }

    def evaluate_policy(self, policy_analysis):
        """Evaluate policy against compliance rules"""
        violations = []
        recommendations = []
        
        # Check for overly permissive actions
        if policy_analysis['overly_permissive']:
            violations.append({
                'severity': 'HIGH',
                'type': 'OVERLY_PERMISSIVE',
                'description': 'Policy contains overly permissive actions',
                'actions': policy_analysis['high_risk_actions']
            })
            recommendations.append(
                "Consider restricting broad permissions to specific actions"
            )

        # Check for wildcard resources
        if policy_analysis['wildcard_resources']:
            violations.append({
                'severity': 'MEDIUM',
                'type': 'WILDCARD_RESOURCE',
                'description': 'Policy uses wildcard resources',
                'impact': 'Increases attack surface and potential blast radius'
            })
            recommendations.append(
                "Specify explicit resource ARNs instead of using wildcards"
            )

        # Check for high-risk services
        high_risk_services_used = self._check_high_risk_services(policy_analysis['high_risk_actions'])
        if high_risk_services_used:
            violations.append({
                'severity': 'MEDIUM',
                'type': 'HIGH_RISK_SERVICES',
                'description': 'Policy grants access to high-risk services',
                'services': high_risk_services_used
            })
            recommendations.append(
                "Review and limit access to high-risk services"
            )

        return {
            'compliant': len(violations) == 0,
            'violations': violations,
            'recommendations': recommendations,
            'risk_score': self._calculate_risk_score(violations)
        }

    def _check_high_risk_services(self, actions):
        """Check for high-risk services in actions"""
        high_risk_services_used = set()
        for action in actions:
            service = action.split(':')[0] if ':' in action else action
            if service in self.compliance_rules['high_risk_services']:
                high_risk_services_used.add(service)
        return list(high_risk_services_used)

    def _calculate_risk_score(self, violations):
        """Calculate a risk score based on violations"""
        risk_score = 0
        severity_weights = {
            'HIGH': 10,
            'MEDIUM': 5,
            'LOW': 2
        }
        
        for violation in violations:
            risk_score += severity_weights.get(violation['severity'], 1)
        
        # Normalize score to 0-100 range
        normalized_score = min(100, risk_score * 10)
        return normalized_score 
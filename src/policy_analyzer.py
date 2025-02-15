class PolicyAnalyzer:
    def __init__(self):
        self.high_risk_actions = {
            '*',
            'iam:*',
            's3:*',
            'ec2:*'
        }

    def analyze_policy(self, policy_document):
        """Analyze a policy document for potential risks"""
        if not policy_document:
            return {
                'overly_permissive': False,
                'high_risk_actions': [],
                'resource_count': 0,
                'wildcard_resources': False,
                'recommendations': ['Unable to analyze policy document']
            }

        analysis = {
            'overly_permissive': False,
            'high_risk_actions': [],
            'resource_count': 0,
            'wildcard_resources': False,
            'recommendations': []
        }

        try:
            for statement in policy_document.get('Statement', []):
                self._analyze_statement(statement, analysis)
        except AttributeError:
            analysis['recommendations'].append('Invalid policy document format')
        except Exception as e:
            analysis['recommendations'].append(f'Error analyzing policy: {str(e)}')

        return analysis

    def _analyze_statement(self, statement, analysis):
        """Analyze individual policy statement"""
        effect = statement.get('Effect', '')
        actions = self._get_actions(statement)
        resources = self._get_resources(statement)

        # Check for overly permissive actions
        if effect == 'Allow':
            for action in actions:
                if action in self.high_risk_actions:
                    analysis['overly_permissive'] = True
                    analysis['high_risk_actions'].append(action)

        # Check resources
        analysis['resource_count'] += len(resources)
        if '*' in resources:
            analysis['wildcard_resources'] = True

        # Generate recommendations
        self._generate_recommendations(analysis)

    def _get_actions(self, statement):
        """Extract actions from statement"""
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        return actions

    def _get_resources(self, statement):
        """Extract resources from statement"""
        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        return resources

    def _generate_recommendations(self, analysis):
        """Generate recommendations based on analysis"""
        if analysis['overly_permissive']:
            analysis['recommendations'].append(
                "Consider restricting wildcard permissions to specific actions"
            )
        if analysis['wildcard_resources']:
            analysis['recommendations'].append(
                "Specify explicit resources instead of using wildcards"
            ) 
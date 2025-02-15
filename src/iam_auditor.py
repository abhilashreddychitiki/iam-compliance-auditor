import boto3
import json
from datetime import datetime
from policy_analyzer import PolicyAnalyzer
from rules_engine import RulesEngine
from report_generator import ReportGenerator

class IAMComplianceAuditor:
    def __init__(self):
        self.iam_client = boto3.client('iam')
        self.analyzer = PolicyAnalyzer()
        self.rules_engine = RulesEngine()
        self.report_generator = ReportGenerator()

    def get_all_iam_policies(self):
        """Retrieve all IAM policies in the account"""
        policies = []
        paginator = self.iam_client.get_paginator('list_policies')
        
        # Get both AWS managed and customer managed policies
        for page in paginator.paginate(Scope='All'):
            policies.extend(page['Policies'])
        
        return policies

    def get_policy_details(self, policy_arn):
        """Get detailed policy information including policy document"""
        try:
            response = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=self.iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            )
            document = response['PolicyVersion']['Document']
            
            # Handle case where document is a string
            if isinstance(document, str):
                document = json.loads(document)
            
            return document
        except Exception as e:
            return None

    def audit_policies(self):
        """Main function to audit all policies"""
        policies = self.get_all_iam_policies()
        audit_results = []

        for policy in policies:
            policy_document = self.get_policy_details(policy['Arn'])
            
            if policy_document:
                # Analyze policy
                analysis = self.analyzer.analyze_policy(policy_document)
                
                # Check compliance
                compliance_results = self.rules_engine.evaluate_policy(analysis)
                
                result = {
                    'policy_name': policy['PolicyName'],
                    'policy_arn': policy['Arn'],
                    'analysis': analysis,
                    'compliance_results': compliance_results
                }
                
                audit_results.append(result)

        return audit_results

def main():
    try:
        auditor = IAMComplianceAuditor()
        results = auditor.audit_policies()
        auditor.report_generator.generate_report(results)
    except Exception as e:
        import traceback
        print(f"Error during audit: {str(e)}")
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
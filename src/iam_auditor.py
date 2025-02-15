import boto3
import json
from datetime import datetime
from policy_analyzer import PolicyAnalyzer
from rules_engine import RulesEngine
from report_generator import ReportGenerator

# Add this debug code at the start
try:
    sts = boto3.client('sts')
    caller_identity = sts.get_caller_identity()
    print("Successfully connected to AWS!")
    print(f"Account: {caller_identity['Account']}")
    print(f"ARN: {caller_identity['Arn']}")
except Exception as e:
    print(f"Error connecting to AWS: {str(e)}")

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
        
        print(f"Found {len(policies)} total policies")
        print("Breaking down policies:")
        aws_managed = len([p for p in policies if p['Arn'].startswith('arn:aws:iam::aws:')])
        customer_managed = len([p for p in policies if not p['Arn'].startswith('arn:aws:iam::aws:')])
        print(f"- AWS-managed policies: {aws_managed}")
        print(f"- Customer-managed policies: {customer_managed}")
        
        return policies

    def audit_policies(self):
        """Main function to audit all policies"""
        policies = self.get_all_iam_policies()
        audit_results = []

        print("\nAnalyzing policies...")
        for policy in policies:
            print(f"\nAnalyzing policy: {policy['PolicyName']}")
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
                
                # Print immediate feedback
                print(f"- Compliance status: {'✅ Compliant' if compliance_results['compliant'] else '❌ Non-compliant'}")
                if not compliance_results['compliant']:
                    print("  Violations found:")
                    for violation in compliance_results['violations']:
                        print(f"  - {violation['severity']}: {violation['description']}")
                
                audit_results.append(result)

        return audit_results

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
            print(f"Error getting policy details for {policy_arn}: {str(e)}")
            return None

def main():
    try:
        auditor = IAMComplianceAuditor()
        results = auditor.audit_policies()
        auditor.report_generator.generate_report(results)
        print(f"\nAudit completed. Found {len(results)} policies.")
    except Exception as e:
        print(f"Error during audit: {str(e)}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
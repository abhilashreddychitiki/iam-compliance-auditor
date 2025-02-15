import json
import os
from datetime import datetime

class ReportGenerator:
    def generate_report(self, audit_results):
        """Generate a detailed compliance report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': self._generate_summary(audit_results),
            'detailed_results': audit_results
        }

        # Create reports directory if it doesn't exist
        os.makedirs('reports', exist_ok=True)

        # Save report to file
        filename = f"reports/iam_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary to console
        summary = report['summary']
        print("\n=== Audit Summary ===")
        print(f"Total Policies: {summary['total_policies']}")
        print(f"Compliant Policies: {summary['compliant_policies']}")
        print(f"Non-compliant Policies: {summary['non_compliant_policies']}")
        print(f"Compliance Rate: {summary['compliance_rate']:.2f}%")
        print(f"\nDetailed report saved to: {filename}")

    def _generate_summary(self, audit_results):
        """Generate summary statistics"""
        total_policies = len(audit_results)
        non_compliant = len([r for r in audit_results if not r['compliance_results']['compliant']])
        
        return {
            'total_policies': total_policies,
            'compliant_policies': total_policies - non_compliant,
            'non_compliant_policies': non_compliant,
            'compliance_rate': ((total_policies - non_compliant) / total_policies) * 100 if total_policies > 0 else 0
        } 
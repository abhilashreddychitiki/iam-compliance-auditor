import json
import os
from datetime import datetime
import pandas as pd

class ReportGenerator:
    def generate_report(self, audit_results):
        """Generate a detailed compliance report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': self._generate_summary(audit_results),
            'risk_analysis': self._generate_risk_analysis(audit_results),
            'detailed_results': audit_results
        }

        # Create reports directory if it doesn't exist
        os.makedirs('reports', exist_ok=True)

        # Save JSON report
        json_filename = f"reports/iam_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_filename, 'w') as f:
            json.dump(report, f, indent=2)

        # Generate Excel report
        excel_filename = json_filename.replace('.json', '.xlsx')
        self._generate_excel_report(audit_results, excel_filename)

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

    def _generate_risk_analysis(self, audit_results):
        """Generate risk analysis statistics"""
        high_risk_count = 0
        medium_risk_count = 0
        low_risk_count = 0
        total_violations = 0
        
        for result in audit_results:
            for violation in result['compliance_results'].get('violations', []):
                total_violations += 1
                if violation['severity'] == 'HIGH':
                    high_risk_count += 1
                elif violation['severity'] == 'MEDIUM':
                    medium_risk_count += 1
                else:
                    low_risk_count += 1

        return {
            'total_violations': total_violations,
            'risk_breakdown': {
                'high': high_risk_count,
                'medium': medium_risk_count,
                'low': low_risk_count
            },
            'average_risk_score': self._calculate_average_risk_score(audit_results)
        }

    def _generate_excel_report(self, audit_results, filename):
        """Generate Excel report with multiple sheets"""
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            # Summary sheet
            summary_data = []
            for result in audit_results:
                summary_data.append({
                    'Policy Name': result['policy_name'],
                    'Policy ARN': result['policy_arn'],
                    'Compliant': result['compliance_results']['compliant'],
                    'Risk Score': result['compliance_results'].get('risk_score', 0),
                    'Violations Count': len(result['compliance_results'].get('violations', []))
                })
            
            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)

            # Violations sheet
            violations_data = []
            for result in audit_results:
                for violation in result['compliance_results'].get('violations', []):
                    violations_data.append({
                        'Policy Name': result['policy_name'],
                        'Severity': violation['severity'],
                        'Type': violation['type'],
                        'Description': violation['description']
                    })
            
            pd.DataFrame(violations_data).to_excel(writer, sheet_name='Violations', index=False)

    def _print_console_summary(self, report):
        """Print formatted summary to console"""
        pass  # Removed print statements

    def _calculate_average_risk_score(self, audit_results):
        """Calculate average risk score across all policies"""
        scores = [r['compliance_results'].get('risk_score', 0) for r in audit_results]
        return sum(scores) / len(scores) if scores else 0 
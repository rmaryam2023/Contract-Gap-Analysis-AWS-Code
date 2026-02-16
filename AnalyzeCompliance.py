 

import json 

import boto3 

import re 

from datetime import datetime 

from urllib.parse import unquote_plus 

 

s3_client = boto3.client('s3') 

dynamodb = boto3.resource('dynamodb') 

table = dynamodb.Table('complianceRulesTable') 

 

def lambda_handler(event, context): 

   """ 

   Analyzes MSA text against compliance rules from DynamoDB 

   Generates compliance report 

   """ 

   

   # Get MSA text file location 

   msa_text_key = event.get('msa_text_key') 

   msa_source_file = event.get('msa_source_file', 'Unknown') 

   

   print(f"Analyzing compliance for: {msa_text_key}") 

   

   try: 

       # Read MSA text from S3 

       response = s3_client.get_object( 

           Bucket='processed-output-mr-2026', 

           Key=msa_text_key 

       ) 

       msa_data = json.loads(response['Body'].read().decode('utf-8')) 

       msa_text = msa_data['extracted_text'] 

       

       # Determine jurisdiction from MSA text 

       jurisdiction = detect_jurisdiction(msa_text) 

       print(f"Detected jurisdiction: {jurisdiction}") 

       

       # Get compliance rules for this jurisdiction 

       rules = get_compliance_rules(jurisdiction) 

       print(f"Found {len(rules)} compliance rules for {jurisdiction}") 

       

       # Analyze MSA against each rule 

       compliance_results = [] 

       for rule in rules: 

           result = check_compliance(msa_text, rule) 

           compliance_results.append(result) 

       

       # Generate compliance report 

       report = generate_compliance_report( 

           msa_source_file, 

           jurisdiction, 

           compliance_results, 

           msa_text 

       ) 

       

       # Save report to S3 

       base_name = msa_text_key.split('/')[-1].replace('_msa_text.json', '') 

       report_key = f"compliance-reports/{base_name}_compliance_report.json" 

       

       s3_client.put_object( 

           Bucket='processed-output-mr-2026', 

           Key=report_key, 

           Body=json.dumps(report, indent=2), 

           ContentType='application/json' 

       ) 

       

       print(f"Saved compliance report to: s3://processed-output-mr-2026/{report_key}") 

       

       # Calculate summary statistics 

       total_rules = len(compliance_results) 

       compliant = sum(1 for r in compliance_results if r['status'] == 'COMPLIANT') 

       non_compliant = sum(1 for r in compliance_results if r['status'] == 'NON_COMPLIANT') 

       partial = sum(1 for r in compliance_results if r['status'] == 'PARTIAL') 

       

       return { 

           'statusCode': 200, 

           'body': json.dumps({ 

               'message': 'Compliance analysis complete', 

               'report_file': report_key, 

               'jurisdiction': jurisdiction, 

               'summary': { 

                   'total_rules': total_rules, 

                   'compliant': compliant, 

                   'non_compliant': non_compliant, 

                   'partial': partial, 

                   'compliance_rate': f"{(compliant/total_rules*100):.1f}%" if total_rules > 0 else "0%" 

               } 

           }) 

       } 

       

   except Exception as e: 

       print(f"Error analyzing compliance: {str(e)}") 

       raise e 

 

def detect_jurisdiction(msa_text): 

   """Detect jurisdiction from MSA text""" 

   text_upper = msa_text.upper() 

   

   # Check for UK indicators 

   uk_indicators = [ 

       'ENGLAND AND WALES', 

       'UK GDPR', 

       'INFORMATION COMMISSIONER', 

       'DATA PROTECTION ACT 2018', 

       'REGISTERED IN ENGLAND', 

       'COMPANY NUMBER', 

       'POUNDS STERLING', 

       'GBP' 

   ] 

   

   if any(indicator in text_upper for indicator in uk_indicators): 

       return 'UK' 

   

   # Check for US indicators 

   us_indicators = [ 

       'DELAWARE', 

       'UNITED STATES', 

       'US DATA PRIVACY', 

       'STATE OF', 

       'USD', 

       'DOLLARS' 

   ] 

   

   if any(indicator in text_upper for indicator in us_indicators): 

       return 'US' 

   

   # Default to UNKNOWN if can't determine 

   return 'UNKNOWN' 

 

def get_compliance_rules(jurisdiction): 

   """Retrieve all compliance rules for a jurisdiction from DynamoDB""" 

   try: 

       response = table.query( 

           KeyConditionExpression='Jurisdiction = :jurisdiction', 

           ExpressionAttributeValues={ 

               ':jurisdiction': jurisdiction 

           } 

       ) 

       return response.get('Items', []) 

   except Exception as e: 

       print(f"Error querying DynamoDB: {str(e)}") 

       return [] 

 

def check_compliance(msa_text, rule): 

   """ 

   Check if MSA complies with a specific rule 

   Returns compliance status and evidence 

   """ 

   clause_type = rule['ClauseType'] 

   required_text = rule['RequiredText'] 

   risk_level = rule['RiskLevel'] 

   regulation = rule['Regulation'] 

   

   # Convert to lowercase for case-insensitive search 

   msa_lower = msa_text.lower() 

   

   result = { 

       'clause_type': clause_type, 

       'regulation': regulation, 

       'risk_level': risk_level, 

       'required_text': required_text, 

       'status': 'NON_COMPLIANT', 

       'evidence': [], 

       'findings': '' 

   } 

   

   # Clause-specific compliance checks 

   if clause_type == 'DataBreachNotification': 

       # Check for notification timeframe 

       threshold = rule.get('Threshold', '36') 

       patterns = [ 

           rf'notify.*?within\s+{threshold}\s+hours', 

           rf'notification.*?{threshold}\s+hours', 

           rf'{threshold}.*?hours.*?breach', 

           rf'thirty-six.*?hours' 

       ] 

       

       for pattern in patterns: 

           matches = list(re.finditer(pattern, msa_lower, re.IGNORECASE)) 

           if matches: 

               result['status'] = 'COMPLIANT' 

               result['evidence'] = [match.group(0) for match in matches[:3]] 

               result['findings'] = f'MSA specifies {threshold}-hour breach notification requirement' 

               break 

       

       if result['status'] == 'NON_COMPLIANT': 

           result['findings'] = f'MSA does not specify {threshold}-hour breach notification requirement' 

   

   elif clause_type == 'InternationalTransfer': 

       # Check for lawful transfer mechanisms 

       keywords = ['uk scc', 'standard contractual clauses', 'data bridge', 

                  'uk-us data bridge', 'adequacy', 'privacy framework'] 

       

       found_keywords = [kw for kw in keywords if kw in msa_lower] 

       if found_keywords: 

           result['status'] = 'COMPLIANT' 

           result['evidence'] = found_keywords 

           result['findings'] = f'MSA includes lawful transfer mechanism: {", ".join(found_keywords)}' 

       else: 

           result['findings'] = 'MSA does not specify lawful international transfer mechanism' 

   

   elif clause_type == 'DataProcessorObligations': 

       # Check for processor obligations 

       keywords = ['documented instructions', 'written instructions', 

                  'process only on', 'data controller', 'data processor'] 

       

       found_keywords = [kw for kw in keywords if kw in msa_lower] 

       if len(found_keywords) >= 2: 

           result['status'] = 'COMPLIANT' 

           result['evidence'] = found_keywords 

           result['findings'] = 'MSA includes data processor obligations' 

       elif len(found_keywords) == 1: 

           result['status'] = 'PARTIAL' 

           result['evidence'] = found_keywords 

           result['findings'] = 'MSA partially addresses data processor obligations' 

       else: 

           result['findings'] = 'MSA does not clearly define data processor obligations' 

   

   elif clause_type == 'SecurityMeasures': 

       # Check for security measures 

       keywords = ['encryption', 'access control', 'security measure', 

                  'technical and organisational', 'penetration testing', 

                  'vulnerability', 'multi-factor'] 

       

       found_keywords = [kw for kw in keywords if kw in msa_lower] 

       if len(found_keywords) >= 3: 

           result['status'] = 'COMPLIANT' 

           result['evidence'] = found_keywords 

           result['findings'] = f'MSA specifies comprehensive security measures: {", ".join(found_keywords)}' 

       elif len(found_keywords) >= 1: 

           result['status'] = 'PARTIAL' 

           result['evidence'] = found_keywords 

           result['findings'] = f'MSA mentions some security measures but could be more comprehensive' 

       else: 

           result['findings'] = 'MSA does not specify adequate security measures' 

   

   elif clause_type == 'SubProcessorConsent': 

       # Check for sub-processor requirements 

       keywords = ['sub-processor', 'subprocessor', 'prior written consent', 

                  'third party', 'prior consent'] 

       

       found_keywords = [kw for kw in keywords if kw in msa_lower] 

       if 'prior' in msa_lower and any(kw in msa_lower for kw in ['consent', 'written']): 

           result['status'] = 'COMPLIANT' 

           result['evidence'] = found_keywords 

           result['findings'] = 'MSA requires prior consent for sub-processors' 

       elif found_keywords: 

           result['status'] = 'PARTIAL' 

           result['evidence'] = found_keywords 

           result['findings'] = 'MSA mentions sub-processors but consent requirements unclear' 

       else: 

           result['findings'] = 'MSA does not address sub-processor consent requirements' 

   

   elif clause_type == 'DataSubjectRights': 

       # Check for data subject rights support 

       keywords = ['data subject', 'right of access', 'erasure', 

                  'rectification', 'assistance', 'rights'] 

       

       found_keywords = [kw for kw in keywords if kw in msa_lower] 

       if len(found_keywords) >= 2: 

           result['status'] = 'COMPLIANT' 

           result['evidence'] = found_keywords 

           result['findings'] = 'MSA addresses data subject rights' 

       elif found_keywords: 

           result['status'] = 'PARTIAL' 

           result['evidence'] = found_keywords 

           result['findings'] = 'MSA partially addresses data subject rights' 

       else: 

           result['findings'] = 'MSA does not address data subject rights' 

   

   elif clause_type == 'AuditRights': 

       # Check for audit provisions 

       keywords = ['audit', 'inspection', 'demonstrate compliance', 

                  'soc 2', 'iso 27001', 'third-party audit'] 

       

       found_keywords = [kw for kw in keywords if kw in msa_lower] 

       if found_keywords: 

           result['status'] = 'COMPLIANT' 

           result['evidence'] = found_keywords 

           result['findings'] = 'MSA includes audit rights' 

       else: 

           result['findings'] = 'MSA does not specify audit rights' 

   

   else: 

       # Generic keyword matching for other clause types 

       keywords = required_text.lower().split()[:5]  # Use first 5 words 

       found_keywords = [kw for kw in keywords if kw in msa_lower and len(kw) > 3] 

       

       if len(found_keywords) >= 2: 

           result['status'] = 'PARTIAL' 

           result['evidence'] = found_keywords 

           result['findings'] = f'MSA may address this requirement (keywords found: {", ".join(found_keywords)})' 

       else: 

           result['findings'] = 'Compliance status unclear - manual review recommended' 

   

   return result 

 

def generate_compliance_report(msa_source, jurisdiction, compliance_results, msa_text): 

   """Generate comprehensive compliance report""" 

   

   # Calculate statistics 

   total_rules = len(compliance_results) 

   compliant = sum(1 for r in compliance_results if r['status'] == 'COMPLIANT') 

   non_compliant = sum(1 for r in compliance_results if r['status'] == 'NON_COMPLIANT') 

   partial = sum(1 for r in compliance_results if r['status'] == 'PARTIAL') 

   

   high_risk_issues = [r for r in compliance_results 

                      if r['risk_level'] == 'HIGH' and r['status'] != 'COMPLIANT'] 

   

   report = { 

       'report_metadata': { 

           'generated_at': datetime.utcnow().isoformat() + 'Z', 

           'msa_source_file': msa_source, 

           'jurisdiction': jurisdiction, 

           'analysis_version': '1.0' 

       }, 

       'executive_summary': { 

           'total_rules_checked': total_rules, 

           'compliant': compliant, 

           'non_compliant': non_compliant, 

           'partial_compliance': partial, 

           'compliance_rate': f"{(compliant/total_rules*100):.1f}%" if total_rules > 0 else "0%", 

           'high_risk_issues': len(high_risk_issues), 

           'overall_status': 'PASS' if non_compliant == 0 and len(high_risk_issues) == 0 else 'REVIEW_REQUIRED' 

       }, 

       'detailed_findings': compliance_results, 

       'high_risk_issues': high_risk_issues, 

       'recommendations': generate_recommendations(compliance_results), 

       'msa_summary': { 

           'document_length': len(msa_text), 

           'key_sections_found': detect_key_sections(msa_text) 

       } 

   } 

   

   return report 

 

def detect_key_sections(msa_text): 

   """Detect which key sections are present in the MSA""" 

   msa_lower = msa_text.lower() 

   

   sections = { 

       'Data Protection': any(kw in msa_lower for kw in ['data protection', 'gdpr', 'personal data']), 

       'Security': any(kw in msa_lower for kw in ['security', 'encryption', 'access control']), 

       'Breach Notification': any(kw in msa_lower for kw in ['breach', 'notification', 'incident']), 

       'International Transfers': any(kw in msa_lower for kw in ['transfer', 'cross-border', 'scc']), 

       'Liability': any(kw in msa_lower for kw in ['liability', 'indemnit', 'damages']), 

       'Termination': any(kw in msa_lower for kw in ['termination', 'terminate', 'expiration']), 

       'Audit Rights': any(kw in msa_lower for kw in ['audit', 'inspection', 'compliance']) 

   } 

   

   return sections 

 

def generate_recommendations(compliance_results): 

   """Generate recommendations based on compliance findings""" 

   recommendations = [] 

   

   # Group by status 

   non_compliant = [r for r in compliance_results if r['status'] == 'NON_COMPLIANT'] 

   partial = [r for r in compliance_results if r['status'] == 'PARTIAL'] 

   

   # High priority recommendations 

   high_risk_non_compliant = [r for r in non_compliant if r['risk_level'] == 'HIGH'] 

   if high_risk_non_compliant: 

       recommendations.append({ 

           'priority': 'HIGH', 

           'category': 'Critical Gaps', 

           'recommendation': f"Address {len(high_risk_non_compliant)} high-risk compliance gaps immediately", 

           'affected_clauses': [r['clause_type'] for r in high_risk_non_compliant] 

       }) 

   

   # Medium priority recommendations 

   if partial: 

       recommendations.append({ 

           'priority': 'MEDIUM', 

           'category': 'Incomplete Provisions', 

           'recommendation': f"Strengthen {len(partial)} partially compliant clauses with more specific language", 

           'affected_clauses': [r['clause_type'] for r in partial] 

       }) 

   

   # Specific clause recommendations 

   for result in non_compliant: 

       if result['clause_type'] == 'DataBreachNotification': 

           recommendations.append({ 

               'priority': 'HIGH', 

               'category': result['clause_type'], 

               'recommendation': 'Add explicit breach notification timeframe to Section 7', 

               'suggested_text': result['required_text'] 

           }) 

       elif result['clause_type'] == 'InternationalTransfer': 

           recommendations.append({ 

               'priority': 'HIGH', 

               'category': result['clause_type'], 

               'recommendation': 'Add lawful transfer mechanism to Section 6', 

               'suggested_text': result['required_text'] 

           }) 

   

   return recommendations 

 

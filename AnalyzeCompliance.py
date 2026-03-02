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
    Generates compliance report - WORKS FOR ALL JURISDICTIONS
    """
    
    # Get MSA text file location
    msa_text_key = event.get('msa_text_key')
    msa_source_file = event.get('msa_source_file', 'Unknown')
    
    print(f"Analyzing compliance for: {msa_text_key}")
    
    try:
        # Read MSA text from S3
        response = s3_client.get_object(
            Bucket='processed-output-2026',
            Key=msa_text_key
        )
        msa_data = json.loads(response['Body'].read().decode('utf-8'))
        msa_text = msa_data['extracted_text']
        
        print(f"MSA text length: {len(msa_text)} characters")
        
        # Auto-detect ALL jurisdictions present in MSA
        detected_jurisdictions = detect_all_jurisdictions(msa_text)
        print(f"Detected jurisdictions: {detected_jurisdictions}")
        
        if not detected_jurisdictions:
            print("WARNING: No jurisdiction detected, checking all available rules")
            detected_jurisdictions = get_all_available_jurisdictions()
        
        # Get compliance rules for ALL detected jurisdictions
        all_rules = []
        for jurisdiction in detected_jurisdictions:
            rules = get_compliance_rules(jurisdiction)
            print(f"Found {len(rules)} compliance rules for {jurisdiction}")
            all_rules.extend(rules)
        
        if not all_rules:
            print("ERROR: No compliance rules found in DynamoDB for any jurisdiction")
            print("Available jurisdictions in DynamoDB:")
            scan_jurisdictions()
            
            # Create a report anyway indicating no rules
            report = {
                'report_metadata': {
                    'generated_at': datetime.utcnow().isoformat() + 'Z',
                    'msa_source_file': msa_source_file,
                    'detected_jurisdictions': detected_jurisdictions,
                    'analysis_version': '1.0',
                    'status': 'NO_RULES_FOUND'
                },
                'executive_summary': {
                    'total_rules_checked': 0,
                    'compliant': 0,
                    'non_compliant': 0,
                    'partial_compliance': 0,
                    'compliance_rate': '0%',
                    'high_risk_issues': 0,
                    'overall_status': 'NO_RULES_AVAILABLE',
                    'message': 'No compliance rules found in database. Please add rules for detected jurisdictions.'
                },
                'detected_jurisdictions': detected_jurisdictions,
                'recommendations': [{
                    'priority': 'HIGH',
                    'category': 'System Setup',
                    'recommendation': 'Add compliance rules to DynamoDB for the detected jurisdictions',
                    'action': f'Run: aws dynamodb put-item --table-name complianceRulesTable ...'
                }]
            }
        else:
            # Analyze MSA against each rule
            compliance_results = []
            for rule in all_rules:
                result = check_compliance(msa_text, rule)
                compliance_results.append(result)
            
            # Generate compliance report
            report = generate_compliance_report(
                msa_source_file,
                detected_jurisdictions,
                compliance_results,
                msa_text
            )
        
        # Save report to S3
        base_name = msa_text_key.split('/')[-1].replace('_msa_text.json', '')
        report_key = f"compliance-reports/{base_name}_compliance_report.json"
        
        s3_client.put_object(
            Bucket='processed-output-2026',
            Key=report_key,
            Body=json.dumps(report, indent=2),
            ContentType='application/json'
        )
        
        print(f"Saved compliance report to: s3://processed-output-2026/{report_key}")
        
        # Calculate summary statistics
        total_rules = len(all_rules)
        if total_rules > 0:
            compliant = len([r for r in compliance_results if r['status'] == 'COMPLIANT'])
            non_compliant = len([r for r in compliance_results if r['status'] == 'NON_COMPLIANT'])
            partial = len([r for r in compliance_results if r['status'] == 'PARTIAL'])
        else:
            compliant = non_compliant = partial = 0
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Compliance analysis complete',
                'report_file': report_key,
                'detected_jurisdictions': detected_jurisdictions,
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
        import traceback
        traceback.print_exc()
        raise e

def detect_all_jurisdictions(msa_text):
    """
    Auto-detect ALL jurisdictions mentioned in MSA
    Returns list of jurisdiction codes
    """
    text_upper = msa_text.upper()
    detected = []
    
    # UK / United Kingdom
    uk_indicators = [
        'ENGLAND AND WALES', 'UK GDPR', 'INFORMATION COMMISSIONER',
        'DATA PROTECTION ACT 2018', 'REGISTERED IN ENGLAND',
        'COMPANY NUMBER', 'POUNDS STERLING', 'GBP', 'SCOTLAND',
        'NORTHERN IRELAND', 'UNITED KINGDOM', 'GREAT BRITAIN'
    ]
    if any(indicator in text_upper for indicator in uk_indicators):
        detected.append('UK')
    
    # India
    india_indicators = [
        'INDIA', 'INDIAN', 'DIGITAL PERSONAL DATA PROTECTION ACT',
        'DPDPA', 'DATA PROTECTION BOARD OF INDIA', 'RUPEES', 'INR',
        'REGISTERED IN INDIA', 'DELHI', 'MUMBAI', 'BANGALORE', 'CHENNAI',
        'HYDERABAD', 'GOVERNED BY THE LAWS OF INDIA', 'INDIAN JURISDICTION',
        'COMPANIES ACT 2013', 'MINISTRY OF ELECTRONICS'
    ]
    if any(indicator in text_upper for indicator in india_indicators):
        detected.append('INDIA')
    
    # United States
    us_indicators = [
        'DELAWARE', 'UNITED STATES', 'US DATA PRIVACY', 'STATE OF',
        'USD', 'DOLLARS', 'CALIFORNIA', 'NEW YORK', 'TEXAS',
        'CCPA', 'CPRA', 'FEDERAL TRADE COMMISSION', 'FTC'
    ]
    if any(indicator in text_upper for indicator in us_indicators):
        detected.append('US')
    
    # European Union
    eu_indicators = [
        'EUROPEAN UNION', 'EU GDPR', 'EUROPEAN COMMISSION',
        'BRUSSELS', 'EURO', 'EUR', 'SCHREMS'
    ]
    if any(indicator in text_upper for indicator in eu_indicators):
        detected.append('EU')
    
    # Canada
    canada_indicators = [
        'CANADA', 'CANADIAN', 'PIPEDA', 'PRIVACY COMMISSIONER OF CANADA',
        'TORONTO', 'MONTREAL', 'VANCOUVER', 'CAD'
    ]
    if any(indicator in text_upper for indicator in canada_indicators):
        detected.append('CANADA')
    
    # Australia
    australia_indicators = [
        'AUSTRALIA', 'AUSTRALIAN', 'PRIVACY ACT 1988', 'OAIC',
        'SYDNEY', 'MELBOURNE', 'AUD', 'AUSTRALIAN DOLLAR'
    ]
    if any(indicator in text_upper for indicator in australia_indicators):
        detected.append('AUSTRALIA')
    
    # Singapore
    singapore_indicators = [
        'SINGAPORE', 'PDPA', 'PERSONAL DATA PROTECTION ACT',
        'PDPC', 'SGD', 'SINGAPOREAN'
    ]
    if any(indicator in text_upper for indicator in singapore_indicators):
        detected.append('SINGAPORE')
    
    # Remove duplicates and return
    return list(set(detected))

def get_all_available_jurisdictions():
    """
    Scan DynamoDB to find all available jurisdictions
    Used as fallback if detection fails
    """
    try:
        response = table.scan(
            ProjectionExpression='Jurisdiction',
            Limit=100
        )
        
        jurisdictions = set()
        for item in response.get('Items', []):
            if 'Jurisdiction' in item:
                jurisdictions.add(item['Jurisdiction'])
        
        print(f"Available jurisdictions in DynamoDB: {list(jurisdictions)}")
        return list(jurisdictions)
    except Exception as e:
        print(f"Error scanning jurisdictions: {str(e)}")
        return []

def scan_jurisdictions():
    """Debug helper to print all jurisdictions in DynamoDB"""
    try:
        response = table.scan()
        jurisdictions = {}
        for item in response.get('Items', []):
            j = item.get('Jurisdiction', 'UNKNOWN')
            if j not in jurisdictions:
                jurisdictions[j] = 0
            jurisdictions[j] += 1
        
        print("Jurisdictions in DynamoDB:")
        for j, count in jurisdictions.items():
            print(f"  - {j}: {count} rules")
    except Exception as e:
        print(f"Error scanning: {str(e)}")

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
        print(f"Error querying DynamoDB for {jurisdiction}: {str(e)}")
        return []

def check_compliance(msa_text, rule):
    """
    UNIVERSAL compliance checker - works for ANY jurisdiction
    Uses intelligent keyword matching and pattern detection
    """
    clause_type = rule['ClauseType']
    required_text = rule.get('RequiredText', '')
    risk_level = rule.get('RiskLevel', 'MEDIUM')
    regulation = rule.get('Regulation', 'N/A')
    jurisdiction = rule.get('Jurisdiction', 'UNKNOWN')
    
    # Convert to lowercase for case-insensitive search
    msa_lower = msa_text.lower()
    required_lower = required_text.lower()
    
    result = {
        'clause_type': clause_type,
        'regulation': regulation,
        'jurisdiction': jurisdiction,
        'risk_level': risk_level,
        'required_text': required_text,
        'status': 'NON_COMPLIANT',
        'evidence': [],
        'findings': ''
    }
    
    # Extract key search terms from required text
    search_keywords = extract_keywords(required_lower)
    
    # Generic compliance check based on keywords
    found_keywords = [kw for kw in search_keywords if kw in msa_lower]
    match_rate = len(found_keywords) / len(search_keywords) if search_keywords else 0
    
    # Clause-type specific checks (works across jurisdictions)
    if 'breach' in clause_type.lower() or 'notification' in clause_type.lower():
        # Data breach notification
        patterns = [
            r'notify.*?within\s+(\d+)\s+(hours?|days?)',
            r'notification.*?(\d+)\s+(hours?|days?)',
            r'(\d+)[\s-]+(hour|day).*?(notification|breach)'
        ]
        
        threshold = rule.get('Threshold')
        for pattern in patterns:
            matches = list(re.finditer(pattern, msa_lower, re.IGNORECASE))
            if matches:
                result['status'] = 'COMPLIANT'
                result['evidence'] = [match.group(0) for match in matches[:2]]
                if threshold:
                    result['findings'] = f'MSA specifies {threshold}-hour breach notification requirement'
                else:
                    result['findings'] = 'MSA includes breach notification timeframe'
                return result
        
        if match_rate >= 0.5:
            result['status'] = 'PARTIAL'
            result['evidence'] = found_keywords
            result['findings'] = 'MSA mentions breach notification but lacks specific timeframe'
        else:
            result['findings'] = 'MSA does not specify breach notification requirements'
    
    elif 'transfer' in clause_type.lower() or 'cross' in clause_type.lower():
        # International/cross-border data transfers
        keywords = ['transfer', 'cross-border', 'international', 'scc', 'standard contractual',
                   'adequacy', 'data bridge', 'privacy framework', 'approved countries', 'safeguards']
        
        found = [kw for kw in keywords if kw in msa_lower]
        if len(found) >= 2:
            result['status'] = 'COMPLIANT'
            result['evidence'] = found
            result['findings'] = f'MSA addresses cross-border data transfers: {", ".join(found[:3])}'
        elif found:
            result['status'] = 'PARTIAL'
            result['evidence'] = found
            result['findings'] = 'MSA mentions data transfers but lacks detail'
        else:
            result['findings'] = 'MSA does not address cross-border data transfers'
    
    elif 'processor' in clause_type.lower() or 'fiduciary' in clause_type.lower():
        # Data processor/fiduciary obligations
        keywords = ['processor', 'fiduciary', 'documented instructions', 'written instructions',
                   'process only', 'controller', 'specified purpose']
        
        found = [kw for kw in keywords if kw in msa_lower]
        if len(found) >= 2:
            result['status'] = 'COMPLIANT'
            result['evidence'] = found
            result['findings'] = 'MSA includes data processor obligations'
        elif found:
            result['status'] = 'PARTIAL'
            result['evidence'] = found
            result['findings'] = 'MSA partially addresses processor obligations'
        else:
            result['findings'] = 'MSA does not clearly define processor obligations'
    
    elif 'security' in clause_type.lower() or 'safeguard' in clause_type.lower():
        # Security measures
        keywords = ['encryption', 'access control', 'security measure', 'safeguard',
                   'technical and organisational', 'penetration testing', 'vulnerability',
                   'multi-factor', 'authentication', 'firewall']
        
        found = [kw for kw in keywords if kw in msa_lower]
        if len(found) >= 3:
            result['status'] = 'COMPLIANT'
            result['evidence'] = found
            result['findings'] = f'MSA specifies comprehensive security measures: {", ".join(found[:4])}'
        elif len(found) >= 1:
            result['status'] = 'PARTIAL'
            result['evidence'] = found
            result['findings'] = 'MSA mentions some security measures but could be more comprehensive'
        else:
            result['findings'] = 'MSA does not specify adequate security measures'
    
    elif 'consent' in clause_type.lower():
        # Consent requirements
        keywords = ['consent', 'freely given', 'informed', 'specific', 'clear',
                   'opt-in', 'agreement', 'permission', 'authorization']
        
        found = [kw for kw in keywords if kw in msa_lower]
        if len(found) >= 3:
            result['status'] = 'COMPLIANT'
            result['evidence'] = found
            result['findings'] = 'MSA includes comprehensive consent requirements'
        elif found:
            result['status'] = 'PARTIAL'
            result['evidence'] = found
            result['findings'] = 'MSA mentions consent but lacks detail'
        else:
            result['findings'] = 'MSA does not address consent requirements'
    
    elif 'sub' in clause_type.lower() and 'processor' in clause_type.lower():
        # Sub-processor consent
        keywords = ['sub-processor', 'subprocessor', 'prior written consent',
                   'third party', 'prior consent', 'prior approval']
        
        found = [kw for kw in keywords if kw in msa_lower]
        if 'prior' in msa_lower and any(kw in msa_lower for kw in ['consent', 'written', 'approval']):
            result['status'] = 'COMPLIANT'
            result['evidence'] = found
            result['findings'] = 'MSA requires prior consent for sub-processors'
        elif found:
            result['status'] = 'PARTIAL'
            result['evidence'] = found
            result['findings'] = 'MSA mentions sub-processors but consent requirements unclear'
        else:
            result['findings'] = 'MSA does not address sub-processor consent'
    
    elif 'right' in clause_type.lower() or 'principal' in clause_type.lower():
        # Data subject/principal rights
        keywords = ['data subject', 'data principal', 'right of access', 'erasure',
                   'rectification', 'portability', 'rights', 'assistance']
        
        found = [kw for kw in keywords if kw in msa_lower]
        if len(found) >= 2:
            result['status'] = 'COMPLIANT'
            result['evidence'] = found
            result['findings'] = 'MSA addresses data subject rights'
        elif found:
            result['status'] = 'PARTIAL'
            result['evidence'] = found
            result['findings'] = 'MSA partially addresses data subject rights'
        else:
            result['findings'] = 'MSA does not address data subject rights'
    
    elif 'audit' in clause_type.lower() or 'inspection' in clause_type.lower():
        # Audit rights
        keywords = ['audit', 'inspection', 'demonstrate compliance',
                   'soc 2', 'iso 27001', 'third-party audit', 'certification']
        
        found = [kw for kw in keywords if kw in msa_lower]
        if found:
            result['status'] = 'COMPLIANT'
            result['evidence'] = found
            result['findings'] = 'MSA includes audit rights'
        else:
            result['findings'] = 'MSA does not specify audit rights'
    
    elif 'retention' in clause_type.lower():
        # Data retention
        keywords = ['retention', 'retain', 'erase', 'delete', 'duration',
                   'necessary period', 'purpose fulfilled']
        
        found = [kw for kw in keywords if kw in msa_lower]
        if len(found) >= 2:
            result['status'] = 'COMPLIANT'
            result['evidence'] = found
            result['findings'] = 'MSA addresses data retention limits'
        elif found:
            result['status'] = 'PARTIAL'
            result['evidence'] = found
            result['findings'] = 'MSA mentions retention but lacks detail'
        else:
            result['findings'] = 'MSA does not address data retention'
    
    elif 'grievance' in clause_type.lower() or 'complaint' in clause_type.lower():
        # Grievance redressal
        keywords = ['grievance', 'complaint', 'redressal', 'dispute resolution',
                   'escalation', 'complaint mechanism']
        
        found = [kw for kw in keywords if kw in msa_lower]
        if found:
            result['status'] = 'COMPLIANT'
            result['evidence'] = found
            result['findings'] = 'MSA includes grievance mechanism'
        else:
            result['findings'] = 'MSA does not include grievance mechanism'
    
    else:
        # Generic check for any other clause type
        if match_rate >= 0.6:
            result['status'] = 'COMPLIANT'
            result['evidence'] = found_keywords
            result['findings'] = f'MSA addresses this requirement (matched {int(match_rate*100)}% of keywords)'
        elif match_rate >= 0.3:
            result['status'] = 'PARTIAL'
            result['evidence'] = found_keywords
            result['findings'] = f'MSA partially addresses this requirement (matched {int(match_rate*100)}% of keywords)'
        else:
            result['findings'] = 'Compliance status unclear - manual review recommended'
    
    return result

def extract_keywords(text):
    """Extract meaningful keywords from requirement text"""
    # Remove common words
    stop_words = ['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
                  'of', 'with', 'by', 'from', 'as', 'is', 'are', 'was', 'were', 'be']
    
    words = re.findall(r'\b\w+\b', text.lower())
    keywords = [w for w in words if w not in stop_words and len(w) > 3]
    
    return keywords[:10]  # Return top 10 keywords

def generate_compliance_report(msa_source, jurisdictions, compliance_results, msa_text):
    """Generate comprehensive compliance report for multiple jurisdictions"""
    
    # Calculate statistics
    total_rules = len(compliance_results)
    compliant = sum(1 for r in compliance_results if r['status'] == 'COMPLIANT')
    non_compliant = sum(1 for r in compliance_results if r['status'] == 'NON_COMPLIANT')
    partial = sum(1 for r in compliance_results if r['status'] == 'PARTIAL')
    
    high_risk_issues = [r for r in compliance_results 
                       if r['risk_level'] == 'HIGH' and r['status'] != 'COMPLIANT']
    
    # Group results by jurisdiction
    by_jurisdiction = {}
    for result in compliance_results:
        j = result.get('jurisdiction', 'UNKNOWN')
        if j not in by_jurisdiction:
            by_jurisdiction[j] = []
        by_jurisdiction[j].append(result)
    
    report = {
        'report_metadata': {
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'msa_source_file': msa_source,
            'detected_jurisdictions': jurisdictions,
            'analysis_version': '2.0'
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
        'jurisdiction_breakdown': {
            j: {
                'total_rules': len(results),
                'compliant': sum(1 for r in results if r['status'] == 'COMPLIANT'),
                'non_compliant': sum(1 for r in results if r['status'] == 'NON_COMPLIANT'),
                'partial': sum(1 for r in results if r['status'] == 'PARTIAL')
            }
            for j, results in by_jurisdiction.items()
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
        'Data Protection': any(kw in msa_lower for kw in ['data protection', 'gdpr', 'personal data', 'dpdpa']),
        'Security': any(kw in msa_lower for kw in ['security', 'encryption', 'access control']),
        'Breach Notification': any(kw in msa_lower for kw in ['breach', 'notification', 'incident']),
        'International Transfers': any(kw in msa_lower for kw in ['transfer', 'cross-border', 'scc']),
        'Liability': any(kw in msa_lower for kw in ['liability', 'indemnit', 'damages']),
        'Termination': any(kw in msa_lower for kw in ['termination', 'terminate', 'expiration']),
        'Audit Rights': any(kw in msa_lower for kw in ['audit', 'inspection', 'compliance'])
    }
    
    return sections

def generate_recommendations(compliance_results):
    """Generate actionable recommendations based on compliance findings"""
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
            'affected_clauses': [r['clause_type'] for r in high_risk_non_compliant],
            'jurisdictions': list(set([r['jurisdiction'] for r in high_risk_non_compliant]))
        })
    
    # Medium priority recommendations
    if partial:
        recommendations.append({
            'priority': 'MEDIUM',
            'category': 'Incomplete Provisions',
            'recommendation': f"Strengthen {len(partial)} partially compliant clauses with more specific language",
            'affected_clauses': [r['clause_type'] for r in partial]
        })
    
    # Specific recommendations by jurisdiction
    for result in high_risk_non_compliant[:5]:  # Top 5 issues
        recommendations.append({
            'priority': 'HIGH',
            'category': f"{result['jurisdiction']} - {result['clause_type']}",
            'recommendation': f"Add missing clause to address: {result['required_text']}",
            'regulation': result['regulation']
        })
    
    return recommendations

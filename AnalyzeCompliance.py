import json
import boto3
import re
from datetime import datetime
from urllib.parse import unquote_plus
from collections import Counter

s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('complianceRulesTable')

def lambda_handler(event, context):
    """
    Analyzes MSA text against compliance rules from DynamoDB
    CONTENT-BASED JURISDICTION DETECTION - analyzes MSA text to determine jurisdiction
    """
    
    # Get MSA text file location
    msa_text_key = event.get('msa_text_key')
    msa_source_file = event.get('msa_source_file', 'Unknown')
    
    print(f"Analyzing compliance for: {msa_text_key}")
    print(f"Source file: {msa_source_file}")
    
    try:
        # Read MSA text from S3
        response = s3_client.get_object(
            Bucket='processed-output-2026',
            Key=msa_text_key
        )
        msa_data = json.loads(response['Body'].read().decode('utf-8'))
        msa_text = msa_data['extracted_text']
        
        print(f"MSA text length: {len(msa_text)} characters")
        
        # CONTENT-BASED: Detect jurisdiction from MSA text itself
        detected_jurisdiction = detect_jurisdiction_from_content(msa_text, msa_source_file)
        print(f"Detected jurisdiction from MSA content: {detected_jurisdiction}")
        
        detected_jurisdictions = [detected_jurisdiction] if detected_jurisdiction else ['UNKNOWN']
        
        # Get compliance rules for detected jurisdiction
        all_rules = []
        if detected_jurisdiction and detected_jurisdiction != 'UNKNOWN':
            rules = get_compliance_rules(detected_jurisdiction)
            print(f"Found {len(rules)} compliance rules for {detected_jurisdiction}")
            all_rules.extend(rules)
        
        if not all_rules:
            print(f"ERROR: No compliance rules found for jurisdiction: {detected_jurisdiction}")
            
            # Create a report indicating no rules
            report = {
                'report_metadata': {
                    'generated_at': datetime.utcnow().isoformat() + 'Z',
                    'msa_source_file': msa_source_file,
                    'detected_jurisdictions': detected_jurisdictions,
                    'detection_method': 'content-based',
                    'analysis_version': '4.0-content-detection',
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
                    'message': f'No compliance rules found for {detected_jurisdiction}. Please upload regulation PDFs for this jurisdiction.'
                },
                'detected_jurisdictions': detected_jurisdictions,
                'jurisdiction_detection_confidence': 'Based on MSA content analysis',
                'recommendations': [{
                    'priority': 'HIGH',
                    'category': 'System Setup',
                    'recommendation': f'Add compliance rules to DynamoDB for {detected_jurisdiction}',
                    'action': f'Upload regulation PDFs for {detected_jurisdiction} to compliance-rules-2026 bucket'
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
            
            # Add detection metadata
            report['report_metadata']['detection_method'] = 'content-based'
            report['report_metadata']['analysis_version'] = '4.0-content-detection'
            report['jurisdiction_detection_confidence'] = 'Based on MSA content analysis'
        
        # Save report to S3
        base_name = msa_text_key.split('/')[-1].replace('_msa_text.json', '')
        report_key = f"compliance-reports/{base_name}_compliance_report.json"
        
        s3_client.put_object(
            Bucket='processed-output-2026',
            Key=report_key,
            Body=json.dumps(report, indent=2),
            ContentType='application/json'
        )
        
        print(f"Compliance report saved to: {report_key}")
        
        # Return summary
        total_rules = report.get('executive_summary', {}).get('total_rules_checked', 0)
        compliant = report.get('executive_summary', {}).get('compliant', 0)
        non_compliant = report.get('executive_summary', {}).get('non_compliant', 0)
        partial = report.get('executive_summary', {}).get('partial_compliance', 0)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Compliance analysis complete',
                'report_file': report_key,
                'detected_jurisdictions': detected_jurisdictions,
                'detection_method': 'content-based',
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

def detect_jurisdiction_from_content(msa_text, filename=""):
    """
    Detect jurisdiction by analyzing the CONTENT of the MSA
    Uses keyword frequency, specific legal terms, and governing law clauses
    
    Returns SINGLE most likely jurisdiction
    """
    text_upper = msa_text.upper()
    
    # Score each jurisdiction based on content
    jurisdiction_scores = Counter()
    
    # ==================== LOOK FOR GOVERNING LAW CLAUSES ====================
    
    # Extract governing law section (most reliable indicator)
    governing_law_patterns = [
        r'GOVERNING LAW[\s\S]{0,500}',
        r'APPLICABLE LAW[\s\S]{0,500}',
        r'CHOICE OF LAW[\s\S]{0,500}',
        r'THIS AGREEMENT.*?GOVERNED BY[\s\S]{0,300}',
        r'SHALL BE GOVERNED BY[\s\S]{0,300}',
        r'GOVERNED BY AND CONSTRUED[\s\S]{0,300}'
    ]
    
    governing_law_text = ""
    for pattern in governing_law_patterns:
        matches = re.findall(pattern, text_upper)
        if matches:
            governing_law_text = " ".join(matches)
            break
    
    print(f"Governing law clause found: {bool(governing_law_text)}")
    if governing_law_text:
        print(f"Governing law excerpt: {governing_law_text[:200]}...")
    
    # ==================== US STATES ====================
    
    # California
    california_keywords = ['CALIFORNIA', 'CCPA', 'CPRA', 'CALIFORNIA CONSUMER PRIVACY ACT', 'CAL. CIV. CODE']
    california_score = sum(1 for kw in california_keywords if kw in text_upper)
    if 'CALIFORNIA' in governing_law_text:
        california_score += 10  # Strong indicator
    if 'CCPA' in text_upper or 'CPRA' in text_upper:
        california_score += 5
    jurisdiction_scores['CALIFORNIA'] = california_score
    
    # Virginia
    virginia_keywords = ['VIRGINIA', 'VCDPA', 'VIRGINIA CONSUMER DATA PROTECTION ACT']
    virginia_score = sum(1 for kw in virginia_keywords if kw in text_upper)
    if 'VIRGINIA' in governing_law_text:
        virginia_score += 10
    if 'VCDPA' in text_upper:
        virginia_score += 5
    jurisdiction_scores['VIRGINIA'] = virginia_score
    
    # Colorado
    colorado_keywords = ['COLORADO', 'COLORADO PRIVACY ACT', 'CPA']
    colorado_score = sum(1 for kw in colorado_keywords if kw in text_upper)
    if 'COLORADO' in governing_law_text:
        colorado_score += 10
    jurisdiction_scores['COLORADO'] = colorado_score
    
    # Connecticut
    connecticut_keywords = ['CONNECTICUT', 'CTDPA', 'CONNECTICUT DATA PRIVACY ACT']
    connecticut_score = sum(1 for kw in connecticut_keywords if kw in text_upper)
    if 'CONNECTICUT' in governing_law_text:
        connecticut_score += 10
    jurisdiction_scores['CONNECTICUT'] = connecticut_score
    
    # Texas
    texas_keywords = ['TEXAS', 'TDPSA', 'TEXAS DATA PRIVACY']
    texas_score = sum(1 for kw in texas_keywords if kw in text_upper)
    if 'TEXAS' in governing_law_text:
        texas_score += 10
    jurisdiction_scores['TEXAS'] = texas_score
    
    # Other US states with similar logic
    state_checks = {
        'UTAH': ['UTAH', 'UCPA'],
        'FLORIDA': ['FLORIDA', 'FDBR'],
        'OREGON': ['OREGON', 'OCPA'],
        'MONTANA': ['MONTANA', 'MCDPA'],
        'DELAWARE': ['DELAWARE', 'DPDPA'],
        'NEW JERSEY': ['NEW JERSEY', 'NJDPA'],
        'NEW HAMPSHIRE': ['NEW HAMPSHIRE', 'NHPA'],
        'IOWA': ['IOWA', 'ICDPA'],
        'NEBRASKA': ['NEBRASKA', 'NDPA'],
        'TENNESSEE': ['TENNESSEE', 'TIPA'],
        'INDIANA': ['INDIANA', 'INCDPA']
    }
    
    for state, keywords in state_checks.items():
        score = sum(1 for kw in keywords if kw in text_upper)
        if state in governing_law_text or state.replace(' ', '-') in governing_law_text:
            score += 10
        jurisdiction_scores[state] = score
    
    # Generic US (only if no specific state detected)
    us_keywords = ['UNITED STATES', 'U.S.', 'USA', 'AMERICAN']
    us_score = sum(1 for kw in us_keywords if kw in text_upper)
    if 'UNITED STATES' in governing_law_text or 'U.S.' in governing_law_text:
        us_score += 5  # Lower weight than specific states
    jurisdiction_scores['US'] = us_score
    
    # ==================== INTERNATIONAL ====================
    
    # UK / United Kingdom
    uk_keywords = ['UNITED KINGDOM', 'UK GDPR', 'ENGLAND AND WALES', 'ENGLISH LAW', 
                   'DATA PROTECTION ACT 2018', 'ICO', 'INFORMATION COMMISSIONER']
    uk_score = sum(1 for kw in uk_keywords if kw in text_upper)
    if 'ENGLAND' in governing_law_text or 'WALES' in governing_law_text or 'UNITED KINGDOM' in governing_law_text:
        uk_score += 10
    if 'UK GDPR' in text_upper or 'DATA PROTECTION ACT 2018' in text_upper:
        uk_score += 5
    jurisdiction_scores['UK'] = uk_score
    
    # European Union
    eu_keywords = ['EUROPEAN UNION', 'EU GDPR', 'GDPR', 'EU AI ACT', 'EUROPEAN COMMISSION',
                   'EU DATA PROTECTION', 'SCHREMS II']
    eu_score = sum(1 for kw in eu_keywords if kw in text_upper)
    if 'EUROPEAN UNION' in governing_law_text or 'EU' in governing_law_text:
        eu_score += 10
    if 'GDPR' in text_upper:
        eu_score += 5
    jurisdiction_scores['EU'] = eu_score
    
    # Canada
    canada_keywords = ['CANADA', 'CANADIAN', 'PIPEDA', 'BILL C-27', 'PRIVACY COMMISSIONER OF CANADA']
    canada_score = sum(1 for kw in canada_keywords if kw in text_upper)
    if 'CANADA' in governing_law_text or 'CANADIAN' in governing_law_text:
        canada_score += 10
    if 'PIPEDA' in text_upper:
        canada_score += 5
    jurisdiction_scores['CANADA'] = canada_score
    
    # Australia
    australia_keywords = ['AUSTRALIA', 'AUSTRALIAN', 'PRIVACY ACT 1988', 'OAIC', 
                         'AUSTRALIAN PRIVACY PRINCIPLES', 'APP']
    australia_score = sum(1 for kw in australia_keywords if kw in text_upper)
    if 'AUSTRALIA' in governing_law_text or 'AUSTRALIAN' in governing_law_text:
        australia_score += 10
    if 'PRIVACY ACT 1988' in text_upper or 'AUSTRALIAN PRIVACY PRINCIPLES' in text_upper:
        australia_score += 5
    jurisdiction_scores['AUSTRALIA'] = australia_score
    
    # Brazil
    brazil_keywords = ['BRAZIL', 'BRAZILIAN', 'LGPD', 'LEI GERAL DE PROTEÇÃO']
    brazil_score = sum(1 for kw in brazil_keywords if kw in text_upper)
    if 'BRAZIL' in governing_law_text or 'BRAZILIAN' in governing_law_text:
        brazil_score += 10
    if 'LGPD' in text_upper:
        brazil_score += 5
    jurisdiction_scores['BRAZIL'] = brazil_score
    
    # India
    india_keywords = ['INDIA', 'INDIAN', 'DPDPA', 'DIGITAL PERSONAL DATA PROTECTION ACT']
    india_score = sum(1 for kw in india_keywords if kw in text_upper)
    if 'INDIA' in governing_law_text or 'INDIAN' in governing_law_text:
        india_score += 10
    if 'DPDPA' in text_upper or 'DIGITAL PERSONAL DATA PROTECTION ACT' in text_upper:
        india_score += 5
    jurisdiction_scores['INDIA'] = india_score
    
    # Japan
    japan_keywords = ['JAPAN', 'JAPANESE', 'APPI', 'ACT ON PROTECTION OF PERSONAL INFORMATION']
    japan_score = sum(1 for kw in japan_keywords if kw in text_upper)
    if 'JAPAN' in governing_law_text or 'JAPANESE' in governing_law_text:
        japan_score += 10
    if 'APPI' in text_upper:
        japan_score += 5
    jurisdiction_scores['JAPAN'] = japan_score
    
    # China
    china_keywords = ['CHINA', 'CHINESE', 'PIPL', 'PERSONAL INFORMATION PROTECTION LAW', 'PRC']
    china_score = sum(1 for kw in china_keywords if kw in text_upper)
    if 'CHINA' in governing_law_text or 'PRC' in governing_law_text:
        china_score += 10
    if 'PIPL' in text_upper:
        china_score += 5
    jurisdiction_scores['CHINA'] = china_score
    
    # Other international jurisdictions
    other_intl = {
        'SOUTH AFRICA': ['SOUTH AFRICA', 'POPIA', 'PROTECTION OF PERSONAL INFORMATION ACT'],
        'MEXICO': ['MEXICO', 'MEXICAN', 'LFPDPPP'],
        'SOUTH KOREA': ['SOUTH KOREA', 'KOREA', 'PIPA', 'PERSONAL INFORMATION PROTECTION ACT'],
        'SINGAPORE': ['SINGAPORE', 'PDPA', 'PERSONAL DATA PROTECTION ACT'],
        'THAILAND': ['THAILAND', 'THAI', 'PDPA'],
        'ISRAEL': ['ISRAEL', 'ISRAELI', 'PRIVACY PROTECTION LAW']
    }
    
    for jurisdiction, keywords in other_intl.items():
        score = sum(1 for kw in keywords if kw in text_upper)
        if jurisdiction in governing_law_text or jurisdiction.replace(' ', '') in governing_law_text:
            score += 10
        jurisdiction_scores[jurisdiction] = score
    
    # ==================== FRAMEWORKS ====================
    
    # Standard Contractual Clauses
    scc_keywords = ['STANDARD CONTRACTUAL CLAUSES', 'SCC', 'MODEL CLAUSES']
    scc_score = sum(1 for kw in scc_keywords if kw in text_upper)
    if 'STANDARD CONTRACTUAL CLAUSES' in text_upper or 'MODEL CLAUSES' in text_upper:
        scc_score += 5
    jurisdiction_scores['SCC'] = scc_score
    
    # EU-US Data Privacy Framework
    dpf_keywords = ['DATA PRIVACY FRAMEWORK', 'DPF', 'EU-U.S. DPF', 'PRIVACY SHIELD']
    dpf_score = sum(1 for kw in dpf_keywords if kw in text_upper)
    if 'DATA PRIVACY FRAMEWORK' in text_upper:
        dpf_score += 5
    jurisdiction_scores['DPF'] = dpf_score
    
    # ==================== DETERMINE WINNER ====================
    
    # Remove entries with score of 0
    jurisdiction_scores_filtered = {k: v for k, v in jurisdiction_scores.items() if v > 0}
    
    if not jurisdiction_scores_filtered:
        print("No jurisdiction keywords found in MSA content")
        return None
    
    # Get top jurisdiction (use max on dict items)
    top_jurisdiction = max(jurisdiction_scores_filtered.items(), key=lambda x: x[1])
    jurisdiction = top_jurisdiction[0]
    score = top_jurisdiction[1]
    
    # Log all scores for debugging (sorted by score)
    sorted_scores = sorted(jurisdiction_scores_filtered.items(), key=lambda x: x[1], reverse=True)
    print(f"Jurisdiction scores: {dict(sorted_scores)}")
    print(f"Selected jurisdiction: {jurisdiction} (score: {score})")
    
    # If score is very low (< 2), it might be a false positive
    if score < 2:
        print(f"WARNING: Low confidence score ({score}) for jurisdiction detection")
        return None
    
    return jurisdiction

def get_compliance_rules(jurisdiction):
    """
    Retrieve compliance rules for a specific jurisdiction from DynamoDB
    """
    try:
        response = table.query(
            KeyConditionExpression='Jurisdiction = :j',
            ExpressionAttributeValues={
                ':j': jurisdiction
            }
        )
        return response.get('Items', [])
    except Exception as e:
        print(f"Error retrieving rules for {jurisdiction}: {str(e)}")
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

def check_compliance(msa_text, rule):
    """
    Check if MSA complies with a specific rule
    Returns compliance result with evidence
    """
    clause_type = rule.get('ClauseType', 'Unknown')
    required_text = rule.get('RequiredText', '')
    regulation = rule.get('Regulation', 'Unknown Regulation')
    jurisdiction = rule.get('Jurisdiction', 'Unknown')
    risk_level = rule.get('RiskLevel', 'MEDIUM')
    source_document = rule.get('SourceDocument', 'Unknown Source')
    
    # Convert to uppercase for case-insensitive matching
    msa_upper = msa_text.upper()
    required_upper = required_text.upper()
    
    # Extract keywords from required text
    keywords = extract_keywords(required_text)
    
    # Check for presence of keywords
    found_keywords = []
    missing_keywords = []
    
    for keyword in keywords:
        if keyword.upper() in msa_upper:
            found_keywords.append(keyword)
        else:
            missing_keywords.append(keyword)
    
    # Determine compliance status
    if len(found_keywords) == 0:
        status = 'NON_COMPLIANT'
        findings = f"Required clause '{clause_type}' not found in MSA. Missing all key requirements."
    elif len(missing_keywords) == 0:
        status = 'COMPLIANT'
        findings = f"MSA contains required '{clause_type}' clause with all necessary elements."
    else:
        status = 'PARTIAL'
        findings = f"MSA partially addresses '{clause_type}'. Found {len(found_keywords)}/{len(keywords)} required elements. Missing: {', '.join(missing_keywords[:3])}."
    
    # Extract evidence (snippets containing found keywords)
    evidence = extract_evidence(msa_text, found_keywords[:5])  # Limit to 5 pieces of evidence
    
    return {
        'clause_type': clause_type,
        'jurisdiction': jurisdiction,
        'regulation': regulation,
        'required_text': required_text,
        'status': status,
        'risk_level': risk_level,
        'findings': findings,
        'evidence': evidence,
        'keywords_found': found_keywords[:10],
        'keywords_missing': missing_keywords[:10],
        'source_document': source_document
    }

def extract_keywords(text):
    """
    Extract meaningful keywords from required text
    """
    stop_words = {
        'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
        'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'been',
        'be', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
        'should', 'could', 'may', 'might', 'must', 'shall', 'can', 'this',
        'that', 'these', 'those', 'it', 'its', 'their', 'them', 'they'
    }
    
    words = re.findall(r'\b\w{3,}\b', text.lower())
    keywords = [w for w in words if w not in stop_words]
    
    seen = set()
    unique_keywords = []
    for k in keywords:
        if k not in seen:
            seen.add(k)
            unique_keywords.append(k)
    
    return unique_keywords[:20]

def extract_evidence(text, keywords):
    """
    Extract snippets of text that contain the found keywords
    """
    evidence = []
    text_lower = text.lower()
    
    for keyword in keywords:
        pattern = re.compile(r'.{0,50}\b' + re.escape(keyword.lower()) + r'\b.{0,50}', re.IGNORECASE)
        matches = pattern.findall(text)
        
        if matches:
            snippet = matches[0].strip()
            if snippet and snippet not in evidence:
                evidence.append(snippet)
        
        if len(evidence) >= 5:
            break
    
    return evidence

def generate_compliance_report(msa_source_file, detected_jurisdictions, compliance_results, msa_text):
    """
    Generate comprehensive compliance report
    """
    total_rules = len(compliance_results)
    compliant = sum(1 for r in compliance_results if r['status'] == 'COMPLIANT')
    non_compliant = sum(1 for r in compliance_results if r['status'] == 'NON_COMPLIANT')
    partial = sum(1 for r in compliance_results if r['status'] == 'PARTIAL')
    
    compliance_rate = (compliant / total_rules * 100) if total_rules > 0 else 0
    
    high_risk_issues = [
        r for r in compliance_results 
        if r['status'] in ['NON_COMPLIANT', 'PARTIAL'] and r['risk_level'] == 'HIGH'
    ]
    
    if compliance_rate == 100:
        overall_status = 'PASS'
    elif compliance_rate >= 80:
        overall_status = 'REVIEW_REQUIRED'
    else:
        overall_status = 'FAIL'
    
    recommendations = generate_recommendations(compliance_results)
    
    jurisdiction_breakdown = {}
    for result in compliance_results:
        j = result['jurisdiction']
        if j not in jurisdiction_breakdown:
            jurisdiction_breakdown[j] = {
                'total': 0,
                'compliant': 0,
                'non_compliant': 0,
                'partial': 0
            }
        jurisdiction_breakdown[j]['total'] += 1
        if result['status'] == 'COMPLIANT':
            jurisdiction_breakdown[j]['compliant'] += 1
        elif result['status'] == 'NON_COMPLIANT':
            jurisdiction_breakdown[j]['non_compliant'] += 1
        else:
            jurisdiction_breakdown[j]['partial'] += 1
    
    report = {
        'report_metadata': {
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'msa_source_file': msa_source_file,
            'msa_length': len(msa_text),
            'analysis_version': '4.0-content-detection',
            'jurisdictions_analyzed': len(detected_jurisdictions)
        },
        'executive_summary': {
            'total_rules_checked': total_rules,
            'compliant': compliant,
            'non_compliant': non_compliant,
            'partial_compliance': partial,
            'compliance_rate': f"{compliance_rate:.1f}%",
            'high_risk_issues': len(high_risk_issues),
            'overall_status': overall_status
        },
        'detected_jurisdictions': detected_jurisdictions,
        'jurisdiction_breakdown': jurisdiction_breakdown,
        'detailed_findings': compliance_results,
        'high_risk_issues': high_risk_issues,
        'recommendations': recommendations
    }
    
    return report

def generate_recommendations(compliance_results):
    """
    Generate actionable recommendations
    """
    recommendations = []
    
    issues_by_clause = {}
    for result in compliance_results:
        if result['status'] in ['NON_COMPLIANT', 'PARTIAL']:
            clause = result['clause_type']
            if clause not in issues_by_clause:
                issues_by_clause[clause] = []
            issues_by_clause[clause].append(result)
    
    for clause_type, issues in issues_by_clause.items():
        priority = 'HIGH' if any(i['risk_level'] == 'HIGH' for i in issues) else 'MEDIUM'
        
        jurisdictions_affected = list(set(i['jurisdiction'] for i in issues))
        
        recommendation = {
            'priority': priority,
            'category': clause_type,
            'recommendation': f"Add or update {clause_type} clause to comply with {', '.join(jurisdictions_affected)} requirements",
            'affected_clauses': [clause_type],
            'affected_jurisdictions': jurisdictions_affected
        }
        
        if issues[0].get('required_text'):
            recommendation['suggested_text'] = issues[0]['required_text'][:200] + '...'
        
        recommendations.append(recommendation)
    
    priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    recommendations.sort(key=lambda x: priority_order.get(x['priority'], 3))
    
    return recommendations[:10]
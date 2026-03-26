import json
import boto3
import re
from urllib.parse import unquote_plus

s3_client = boto3.client('s3')
comprehend_client = boto3.client('comprehend')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('complianceRulesTable')

def lambda_handler(event, context):
    """
    Triggered by JSON upload to processed-output-2026/regulations/
    Extracts compliance rules using NLP and stores in DynamoDB
    ENHANCED: Includes source document in each rule
    """
    
    # Get bucket and key from S3 event
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = unquote_plus(event['Records'][0]['s3']['object']['key'])
    
    print(f"Processing regulation text: {key} from bucket: {bucket}")
    
    try:
        # Read extracted text from S3
        response = s3_client.get_object(Bucket=bucket, Key=key)
        regulation_data = json.loads(response['Body'].read().decode('utf-8'))
        extracted_text = regulation_data['extracted_text']
        source_file = regulation_data['source_file']
        
        print(f"Source regulation document: {source_file}")
        
        # Determine jurisdiction from filename AND content
        jurisdiction = extract_jurisdiction(source_file, extracted_text)
        print(f"Detected jurisdiction: {jurisdiction}")
        
        # Extract compliance rules using pattern matching and NLP
        # Pass source_file to include in each rule
        rules = extract_compliance_rules(extracted_text, jurisdiction, source_file)
        
        print(f"Extracted {len(rules)} compliance rules from {source_file}")
        
        # Store rules in DynamoDB
        stored_count = 0
        for rule in rules:
            try:
                table.put_item(Item=rule)
                stored_count += 1
                print(f"Stored rule: {rule['ClauseType']} from {rule['SourceDocument']}")
            except Exception as e:
                print(f"Error storing rule {rule['ClauseType']}: {str(e)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Rules extraction successful',
                'source_document': source_file,
                'jurisdiction': jurisdiction,
                'rules_extracted': len(rules),
                'rules_stored': stored_count
            })
        }
        
    except Exception as e:
        print(f"Error processing {key}: {str(e)}")
        raise e

def extract_jurisdiction(filename, content):
    """
    Extract jurisdiction from filename AND content for better accuracy
    """
    filename_upper = filename.upper()
    content_upper = content.upper()
    
    # Check UK
    uk_patterns = ['UK', 'UNITED-KINGDOM', 'GDPR', 'ENGLAND', 'WALES']
    if any(p in filename_upper for p in uk_patterns):
        return 'UK'
    
    # Check India
    india_patterns = ['INDIA', 'DPDPA', 'INDIAN', 'DIGITAL PERSONAL DATA PROTECTION']
    if any(p in filename_upper for p in india_patterns):
        return 'INDIA'
    
    # Check content if filename unclear
    if 'DIGITAL PERSONAL DATA PROTECTION ACT' in content_upper or 'MINISTRY OF ELECTRONICS' in content_upper:
        return 'INDIA'
    
    # Check Australia BEFORE US (Australia contains "US")
    australia_patterns = ['AUSTRALIA', 'AUSTRALIAN', 'PRIVACY ACT 1988']
    if any(p in filename_upper for p in australia_patterns):
        return 'AUSTRALIA'
    
    # Check US (after Australia to avoid false match)
    us_patterns = ['US', 'USA', 'UNITED-STATES', 'CALIFORNIA', 'CCPA', 'CPRA']
    if any(p in filename_upper for p in us_patterns):
        return 'US'
    
    # Check EU
    eu_patterns = ['EU', 'EUROPE', 'EUROPEAN']
    if any(p in filename_upper for p in eu_patterns):
        return 'EU'
    
    # Check Canada
    canada_patterns = ['CANADA', 'PIPEDA', 'CANADIAN']
    if any(p in filename_upper for p in canada_patterns):
        return 'CANADA'
    
    # Check Singapore
    singapore_patterns = ['SINGAPORE', 'PDPA']
    if any(p in filename_upper for p in singapore_patterns):
        return 'SINGAPORE'
    
    # Default to generic
    print(f"WARNING: Could not detect jurisdiction from {filename}")
    return 'UNKNOWN'

def extract_compliance_rules(text, jurisdiction, source_file):
    """
    Extract compliance rules from regulation text using pattern matching
    UPDATED: Includes source_file in each rule
    """
    rules = []
    
    # Pattern 1: Data breach notification requirements
    breach_pattern = r'notify.*?within\s+(\d+)\s+(hours|days)'
    matches = re.finditer(breach_pattern, text, re.IGNORECASE)
    
    for match in matches:
        time_value = match.group(1)
        time_unit = match.group(2).lower()
        
        # Convert to hours for consistency
        hours = int(time_value) if time_unit == 'hours' else int(time_value) * 24
        
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'DataBreachNotification',
            'RequiredText': f'notify within {hours} hours of breach',
            'Threshold': str(hours),
            'RiskLevel': 'HIGH',
            'Regulation': f'{jurisdiction} Data Protection Law - Breach Notification',
            'SourceDocument': source_file  # ADD SOURCE FILE
        })
        break  # Only take first match
    
    # Pattern 2: International data transfers
    transfer_keywords = [
        'international transfer', 'cross-border transfer', 'data transfer',
        'standard contractual clauses', 'SCC', 'adequacy decision',
        'data bridge', 'privacy framework', 'approved countries'
    ]
    
    if any(keyword.lower() in text.lower() for keyword in transfer_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'CrossBorderTransfer',
            'RequiredText': 'Implement lawful mechanism for cross-border data transfers',
            'RiskLevel': 'HIGH',
            'Regulation': f'{jurisdiction} Data Protection Law - Cross-Border Transfers',
            'SourceDocument': source_file  # ADD SOURCE FILE
        })
    
    # Pattern 3: Data processor/fiduciary obligations
    processor_keywords = ['processor', 'fiduciary', 'data processing', 'process personal data']
    if any(keyword in text.lower() for keyword in processor_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'DataProcessorObligations',
            'RequiredText': 'Process data only on documented instructions with appropriate security',
            'RiskLevel': 'HIGH',
            'Regulation': f'{jurisdiction} Data Protection Law - Processor Requirements',
            'SourceDocument': source_file  # ADD SOURCE FILE
        })
    
    # Pattern 4: Security measures
    security_keywords = ['security measure', 'technical and organisational', 'encryption', 
                        'pseudonymisation', 'access control', 'safeguard']
    if any(keyword in text.lower() for keyword in security_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'SecuritySafeguards',
            'RequiredText': 'Implement appropriate technical and organisational security measures',
            'RiskLevel': 'HIGH',
            'Regulation': f'{jurisdiction} Data Protection Law - Security Requirements',
            'SourceDocument': source_file  # ADD SOURCE FILE
        })
    
    # Pattern 5: Consent requirements
    consent_keywords = ['consent', 'freely given', 'informed consent', 'specific consent']
    if any(keyword in text.lower() for keyword in consent_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'ConsentRequirements',
            'RequiredText': 'Obtain clear, specific, informed, and freely given consent',
            'RiskLevel': 'HIGH',
            'Regulation': f'{jurisdiction} Data Protection Law - Consent',
            'SourceDocument': source_file  # ADD SOURCE FILE
        })
    
    # Pattern 6: Sub-processor requirements
    subprocessor_keywords = ['sub-processor', 'subprocessor', 'third party processor']
    if any(keyword in text.lower() for keyword in subprocessor_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'SubProcessorConsent',
            'RequiredText': 'Obtain prior written consent before engaging sub-processors',
            'RiskLevel': 'MEDIUM',
            'Regulation': f'{jurisdiction} Data Protection Law - Sub-Processor Rules',
            'SourceDocument': source_file  # ADD SOURCE FILE
        })
    
    # Pattern 7: Data retention requirements
    retention_keywords = ['retention', 'retain data', 'storage limitation', 'keep data']
    if any(keyword in text.lower() for keyword in retention_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'DataRetention',
            'RequiredText': 'Retain data only for as long as necessary for specified purposes',
            'RiskLevel': 'MEDIUM',
            'Regulation': f'{jurisdiction} Data Protection Law - Retention',
            'SourceDocument': source_file  # ADD SOURCE FILE
        })
    
    # Pattern 8: Right to erasure/deletion
    erasure_keywords = ['right to erasure', 'right to be forgotten', 'delete data', 'removal']
    if any(keyword in text.lower() for keyword in erasure_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'RightToErasure',
            'RequiredText': 'Provide mechanism for data subject to request deletion of their data',
            'RiskLevel': 'HIGH',
            'Regulation': f'{jurisdiction} Data Protection Law - Erasure Rights',
            'SourceDocument': source_file  # ADD SOURCE FILE
        })
    
    # Pattern 9: Data portability
    portability_keywords = ['data portability', 'port data', 'export data', 'transfer data']
    if any(keyword in text.lower() for keyword in portability_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'DataPortability',
            'RequiredText': 'Provide data in structured, commonly used, machine-readable format',
            'RiskLevel': 'MEDIUM',
            'Regulation': f'{jurisdiction} Data Protection Law - Data Portability',
            'SourceDocument': source_file  # ADD SOURCE FILE
        })
    
    # Pattern 10: Privacy by design
    privacy_design_keywords = ['privacy by design', 'data protection by design', 'privacy by default']
    if any(keyword in text.lower() for keyword in privacy_design_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'PrivacyByDesign',
            'RequiredText': 'Implement privacy by design and by default in all processing activities',
            'RiskLevel': 'MEDIUM',
            'Regulation': f'{jurisdiction} Data Protection Law - Privacy by Design',
            'SourceDocument': source_file  # ADD SOURCE FILE
        })
    
    # Pattern 11: Audit rights
    audit_keywords = ['audit', 'inspection', 'right to audit', 'verify compliance']
    if any(keyword in text.lower() for keyword in audit_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'AuditRights',
            'RequiredText': 'Grant audit rights to verify compliance with data protection obligations',
            'RiskLevel': 'MEDIUM',
            'Regulation': f'{jurisdiction} Data Protection Law - Audit Requirements',
            'SourceDocument': source_file  # ADD SOURCE FILE
        })
    
    # Pattern 12: Indemnification
    indemnify_keywords = ['indemnify', 'indemnification', 'hold harmless', 'liability']
    if any(keyword in text.lower() for keyword in indemnify_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'IndemnificationClause',
            'RequiredText': 'Include indemnification provisions for data protection breaches',
            'RiskLevel': 'HIGH',
            'Regulation': f'{jurisdiction} Data Protection Law - Liability',
            'SourceDocument': source_file  # ADD SOURCE FILE
        })
    
    return rules
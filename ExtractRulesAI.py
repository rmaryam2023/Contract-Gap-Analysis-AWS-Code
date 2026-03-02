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
    ENHANCED: Better jurisdiction detection for ALL countries
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
        
        # Determine jurisdiction from filename AND content
        jurisdiction = extract_jurisdiction(source_file, extracted_text)
        print(f"Detected jurisdiction: {jurisdiction}")
        
        # Extract compliance rules using pattern matching and NLP
        rules = extract_compliance_rules(extracted_text, jurisdiction)
        
        print(f"Extracted {len(rules)} compliance rules")
        
        # Store rules in DynamoDB
        stored_count = 0
        for rule in rules:
            try:
                table.put_item(Item=rule)
                stored_count += 1
                print(f"Stored rule: {rule['ClauseType']}")
            except Exception as e:
                print(f"Error storing rule {rule['ClauseType']}: {str(e)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Rules extraction successful',
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
    
    # Check US
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
    
    # Check Australia
    australia_patterns = ['AUSTRALIA', 'AUSTRALIAN', 'PRIVACY ACT 1988']
    if any(p in filename_upper for p in australia_patterns):
        return 'AUSTRALIA'
    
    # Check Singapore
    singapore_patterns = ['SINGAPORE', 'PDPA', 'SINGAPOREAN']
    if any(p in filename_upper for p in singapore_patterns):
        return 'SINGAPORE'
    
    # Default to UNKNOWN
    print(f"WARNING: Could not determine jurisdiction from filename: {filename}")
    return 'UNKNOWN'

def extract_compliance_rules(text, jurisdiction):
    """
    Extract compliance rules from regulation text using pattern matching
    UNIVERSAL: Works for any jurisdiction
    """
    rules = []
    
    # Pattern 1: Data breach notification requirements
    breach_patterns = [
        r'notify.*?within\s+(\d+)\s+hours',
        r'notification.*?(\d+)\s+hours',
        r'(\d+)[-\s]hour.*?notification'
    ]
    
    for pattern in breach_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            hours = match.group(1)
            rules.append({
                'Jurisdiction': jurisdiction,
                'ClauseType': 'DataBreachNotification',
                'RequiredText': f'notify within {hours} hours of breach',
                'Threshold': hours,
                'RiskLevel': 'HIGH',
                'Regulation': f'{jurisdiction} Data Protection Law - Breach Notification'
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
            'Regulation': f'{jurisdiction} Data Protection Law - Cross-Border Transfers'
        })
    
    # Pattern 3: Data processor/fiduciary obligations
    processor_keywords = ['processor', 'fiduciary', 'data processing', 'process personal data']
    if any(keyword in text.lower() for keyword in processor_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'DataProcessorObligations',
            'RequiredText': 'Process data only on documented instructions with appropriate security',
            'RiskLevel': 'HIGH',
            'Regulation': f'{jurisdiction} Data Protection Law - Processor Requirements'
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
            'Regulation': f'{jurisdiction} Data Protection Law - Security Requirements'
        })
    
    # Pattern 5: Consent requirements
    consent_keywords = ['consent', 'freely given', 'informed consent', 'specific consent']
    if any(keyword in text.lower() for keyword in consent_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'ConsentRequirements',
            'RequiredText': 'Obtain clear, specific, informed, and freely given consent',
            'RiskLevel': 'HIGH',
            'Regulation': f'{jurisdiction} Data Protection Law - Consent'
        })
    
    # Pattern 6: Sub-processor requirements
    subprocessor_keywords = ['sub-processor', 'subprocessor', 'third party processor']
    if any(keyword in text.lower() for keyword in subprocessor_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'SubProcessorConsent',
            'RequiredText': 'Obtain prior written consent before engaging sub-processors',
            'RiskLevel': 'MEDIUM',
            'Regulation': f'{jurisdiction} Data Protection Law - Sub-Processor Rules'
        })
    
    # Pattern 7: Data subject/principal rights
    rights_keywords = ['data subject rights', 'data principal rights', 'right of access', 
                      'right to erasure', 'right to rectification', 'right to object', 'data portability']
    if any(keyword in text.lower() for keyword in rights_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'DataPrincipalRights',
            'RequiredText': 'Enable data subject rights including access, correction, and erasure',
            'RiskLevel': 'MEDIUM',
            'Regulation': f'{jurisdiction} Data Protection Law - Individual Rights'
        })
    
    # Pattern 8: Audit rights
    audit_keywords = ['audit', 'inspection', 'demonstrate compliance']
    if any(keyword in text.lower() for keyword in audit_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'AuditRights',
            'RequiredText': 'Provide information to demonstrate compliance and allow audits',
            'RiskLevel': 'MEDIUM',
            'Regulation': f'{jurisdiction} Data Protection Law - Accountability'
        })
    
    # Pattern 9: Data retention
    retention_keywords = ['retention', 'retain data', 'erase', 'delete', 'purpose fulfilled']
    if any(keyword in text.lower() for keyword in retention_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'DataRetention',
            'RequiredText': 'Retain data only for necessary duration, erase after purpose fulfilled',
            'RiskLevel': 'MEDIUM',
            'Regulation': f'{jurisdiction} Data Protection Law - Data Retention'
        })
    
    # Pattern 10: Grievance mechanism (especially for India)
    grievance_keywords = ['grievance', 'complaint mechanism', 'redressal', 'dispute resolution']
    if any(keyword in text.lower() for keyword in grievance_keywords):
        rules.append({
            'Jurisdiction': jurisdiction,
            'ClauseType': 'GrievanceRedressal',
            'RequiredText': 'Establish grievance redressal mechanism for complaints',
            'RiskLevel': 'MEDIUM',
            'Regulation': f'{jurisdiction} Data Protection Law - Grievance Redressal'
        })
    
    return rules

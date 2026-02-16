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

   Triggered by JSON upload to processed-output-mr-2026/regulations/ 

   Extracts compliance rules using NLP and stores in DynamoDB 

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

       

       # Determine jurisdiction from filename 

       jurisdiction = extract_jurisdiction(source_file) 

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

 

def extract_jurisdiction(filename): 

   """Extract jurisdiction from filename (e.g., UK-GDPR.pdf -> UK)""" 

   filename = filename.upper() 

   

   # Common jurisdiction patterns 

   if 'UK' in filename or 'UNITED-KINGDOM' in filename or 'GDPR' in filename: 

       return 'UK' 

   elif 'US' in filename or 'USA' in filename or 'UNITED-STATES' in filename: 

       return 'US' 

   elif 'EU' in filename or 'EUROPE' in filename: 

       return 'EU' 

   elif 'CA' in filename or 'CANADA' in filename: 

       return 'CA' 

   elif 'AU' in filename or 'AUSTRALIA' in filename: 

       return 'AU' 

   else: 

       return 'UNKNOWN' 

 

def extract_compliance_rules(t ext, jurisdiction): 

   """ 

   Extract compliance rules from regulation text using pattern matching 

   This is a simplified version - in production, you'd use more sophisticated NLP 

   """ 

   rules = [] 

   

   # Pattern 1: Data breach notification requirements 

   breach_patterns = [ 

       r'notify.*?within\s+(\d+)\s+hours', 

       r'notification.*?(\d+)\s+hours', 

       r'(\d+)-hour.*?notification' 

   ] 

   

   for pattern in breach_patterns: 

       matches = re.finditer(pattern, text, re.IGNORECASE) 

       for match in matches: 

           hours = match.group(1) 

           rules.append({ 

               'Jurisdiction': jurisdiction, 

               'ClauseType': 'DataBreachNotification', 

               'RequiredText': f'notify Customer within {hours} hours', 

               'Threshold': hours, 

               'RiskLevel': 'HIGH', 

               'Regulation': f'{jurisdiction} Data Protection Law - Breach Notification' 

           }) 

           break  # Only take first match 

   

   # Pattern 2: International data transfers 

   transfer_keywords = [ 

       'international transfer', 'cross-border transfer', 'data transfer', 

       'standard contractual clauses', 'SCC', 'adequacy decision', 

       'data bridge', 'privacy framework' 

   ] 

   

   for keyword in transfer_keywords: 

       if keyword.lower() in text.lower(): 

           rules.append({ 

               'Jurisdiction': jurisdiction, 

               'ClauseType': 'InternationalTransfer', 

               'RequiredText': 'Lawful transfer mechanism required (SCCs, adequacy decision, or approved framework)', 

               'RiskLevel': 'HIGH', 

               'Regulation': f'{jurisdiction} Data Protection Law - Cross-Border Transfers' 

           }) 

           break 

   

   # Pattern 3: Data processor obligations 

   processor_keywords = ['processor', 'data processing', 'process personal data'] 

   if any(keyword in text.lower() for keyword in processor_keywords): 

       rules.append({ 

           'Jurisdiction': jurisdiction, 

           'ClauseType': 'DataProcessorObligations', 

           'RequiredText': 'Process only on documented written instructions from controller', 

           'RiskLevel': 'HIGH', 

           'Regulation': f'{jurisdiction} Data Protection Law - Processor Requirements' 

       }) 

   

   # Pattern 4: Security measures 

   security_keywords = ['security measure', 'technical and organisational', 'encryption', 

                       'pseudonymisation', 'access control'] 

   if any(keyword in text.lower() for keyword in security_keywords): 

       rules.append({ 

           'Jurisdiction': jurisdiction, 

           'ClauseType': 'SecurityMeasures', 

           'RequiredText': 'Implement appropriate technical and organisational security measures', 

           'RiskLevel': 'HIGH', 

           'Regulation': f'{jurisdiction} Data Protection Law - Security Requirements' 

       }) 

   

   # Pattern 5: Sub-processor requirements 

   subprocessor_keywords = ['sub-processor', 'subprocessor', 'third party processor'] 

   if any(keyword in text.lower() for keyword in subprocessor_keywords): 

       rules.append({ 

           'Jurisdiction': jurisdiction, 

           'ClauseType': 'SubProcessorConsent', 

           'RequiredText': 'Obtain prior written consent before engaging sub-processors', 

           'RiskLevel': 'MEDIUM', 

           'Regulation': f'{jurisdiction} Data Protection Law - Sub-Processor Rules' 

       }) 

   

   # Pattern 6: Data subject rights 

   rights_keywords = ['data subject rights', 'right of access', 'right to erasure', 

                     'right to rectification', 'right to object'] 

   if any(keyword in text.lower() for keyword in rights_keywords): 

       rules.append({ 

           'Jurisdiction': jurisdiction, 

           'ClauseType': 'DataSubjectRights', 

           'RequiredText': 'Provide assistance to enable data subject rights requests', 

           'RiskLevel': 'MEDIUM', 

           'Regulation': f'{jurisdiction} Data Protection Law - Individual Rights' 

       }) 

   

   # Pattern 7: Audit rights 

   audit_keywords = ['audit', 'inspection', 'demonstrate compliance'] 

   if any(keyword in text.lower() for keyword in audit_keywords): 

       rules.append({ 

           'Jurisdiction': jurisdiction, 

           'ClauseType': 'AuditRights', 

           'RequiredText': 'Provide information to demonstrate compliance and allow audits', 

           'RiskLevel': 'MEDIUM', 

           'Regulation': f'{jurisdiction} Data Protection Law - Accountability' 

       }) 

   

   return rules 

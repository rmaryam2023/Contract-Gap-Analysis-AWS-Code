import json
import boto3
import os
import time
import zipfile
import xml.etree.ElementTree as ET
from io import BytesIO
from urllib.parse import unquote_plus

s3_client = boto3.client('s3')
textract_client = boto3.client('textract')

def lambda_handler(event, context):
    """
    Triggered by PDF or DOCX upload to msa-intake-2026 bucket.
    Extracts text using:
     Extracts text using Textract ASYNC API (for multi-page PDFs)
    - Textract for PDFs
    - Native extraction for Word (.docx) files
    Saves to processed-output-2026/msa-text/
    Then triggers compliance analysis
    """
    
    # Get bucket and key from S3 event
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = unquote_plus(event['Records'][0]['s3']['object']['key'])
    
    print(f"Processing MSA document: {key} from bucket: {bucket}")
    
    # Check file type
    file_lower = key.lower()
    is_pdf = file_lower.endswith('.pdf')
    is_docx = file_lower.endswith('.docx') or file_lower.endswith('.doc')
    
    if not (is_pdf or is_docx):
        print(f"Skipping unsupported file type: {key}")
        return {
            'statusCode': 200,
            'body': json.dumps('Only PDF and Word (.docx) files are supported')
        }
    
    try:
        # Check file size
        s3_response = s3_client.head_object(Bucket=bucket, Key=key)
        file_size = s3_response['ContentLength']
        file_size_mb = file_size / (1024 * 1024)
        
        print(f"File size: {file_size_mb:.2f} MB")
        print(f"File type: {'PDF' if is_pdf else 'Word'}")
        
        # Extract text based on file type
        if is_pdf:
            extracted_text = extract_text_from_pdf(bucket, key, file_size_mb)
        else:  # is_docx
            extracted_text = extract_text_from_docx(bucket, key)
        
        print(f"Extracted {len(extracted_text)} characters from {key}")
        
        # Generate output filename
        base_name = os.path.splitext(os.path.basename(key))[0]
        output_key = f"msa-text/{base_name}_msa_text.json"
        
        # Save extracted text to output bucket
        output_data = {
            'source_file': key,
            'source_bucket': bucket,
            'extracted_text': extracted_text,
            'file_size_mb': file_size_mb,
            'file_type': 'PDF' if is_pdf else 'DOCX'
        }
        
        s3_client.put_object(
            Bucket='processed-output-2026',
            Key=output_key,
            Body=json.dumps(output_data, indent=2),
            ContentType='application/json'
        )
        
        print(f"Saved extracted text to: s3://processed-output-2026/{output_key}")
        
        # Trigger compliance analysis Lambda
        lambda_client = boto3.client('lambda')
        
        invoke_response = lambda_client.invoke(
            FunctionName='AnalyzeCompliance',
            InvocationType='Event',  # Asynchronous invocation
            Payload=json.dumps({
                'msa_text_key': output_key,
                'msa_source_file': key
            })
        )
        
        print(f"Triggered AnalyzeCompliance Lambda: StatusCode={invoke_response['StatusCode']}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Text extraction successful for {key}',
                'characters_extracted': len(extracted_text),
                'output_file': output_key,
                'file_type': 'PDF' if is_pdf else 'DOCX'
            })
        }
        
    except Exception as e:
        print(f"Error processing {key}: {str(e)}")
        import traceback
        traceback.print_exc()
        raise e

def extract_text_from_pdf(bucket, key, file_size_mb):
    """
    Extract text from PDF using Textract
    Uses sync for small files, async for large files
    """
    if file_size_mb < 5:
        try:
            # Try synchronous first for small PDFs
            return extract_text_sync(bucket, key)
        except Exception as sync_error:
            print(f"Synchronous extraction failed: {str(sync_error)}")
            print("Falling back to asynchronous extraction...")
            return extract_text_async(bucket, key)
    else:
        # Use asynchronous for larger PDFs
        return extract_text_async(bucket, key)

def extract_text_from_docx(bucket, key):
    """
    Extract text from Word .docx file
    .docx is a ZIP file containing XML files
    """
    try:
        # Download the Word file from S3
        response = s3_client.get_object(Bucket=bucket, Key=key)
        docx_bytes = response['Body'].read()
        
        # Open as ZIP file
        docx_zip = zipfile.ZipFile(BytesIO(docx_bytes))
        
        # Read the main document XML (word/document.xml)
        xml_content = docx_zip.read('word/document.xml')
        
        # Parse XML
        tree = ET.XML(xml_content)
        
        # Define namespaces
        namespaces = {
            'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
        }
        
        # Extract all text from paragraphs
        paragraphs = []
        for paragraph in tree.findall('.//w:p', namespaces):
            texts = []
            for text in paragraph.findall('.//w:t', namespaces):
                if text.text:
                    texts.append(text.text)
            if texts:
                paragraphs.append(''.join(texts))
        
        # Join paragraphs with newlines
        extracted_text = '\n\n'.join(paragraphs)
        
        print(f"Extracted {len(paragraphs)} paragraphs from Word document")
        
        return extracted_text
        
    except KeyError:
        # word/document.xml not found - might be an old .doc file
        print("ERROR: File appears to be old .doc format, not .docx")
        print("Please save as .docx (Word 2007+) or convert to PDF")
        raise Exception("Unsupported Word format - please use .docx or PDF")
    except Exception as e:
        print(f"Error extracting text from Word file: {str(e)}")
        raise

def extract_text_sync(bucket, key):
    """
    Extract text using Textract synchronous API (for small PDFs)
    """
    response = textract_client.detect_document_text(
        Document={
            'S3Object': {
                'Bucket': bucket,
                'Name': key
            }
        }
    )
    
    # Extract text from response
    text_lines = []
    for block in response['Blocks']:
        if block['BlockType'] == 'LINE':
            text_lines.append(block['Text'])
    
    return '\n'.join(text_lines)

def extract_text_async(bucket, key):
    """
    Extract text using Textract asynchronous API (for multi-page PDFs)
    """
    # Start the async job
    response = textract_client.start_document_text_detection(
        DocumentLocation={
            'S3Object': {
                'Bucket': bucket,
                'Name': key
            }
        }
    )
    
    job_id = response['JobId']
    print(f"Started Textract job: {job_id}")
    
    # Poll for completion
    max_attempts = 60  # 5 minutes max
    attempt = 0
    
    while attempt < max_attempts:
        attempt += 1
        time.sleep(5)  # Wait 5 seconds between checks
        
        result = textract_client.get_document_text_detection(JobId=job_id)
        status = result['JobStatus']
        
        print(f"Attempt {attempt}: Job status = {status}")
        
        if status == 'SUCCEEDED':
            # Extract text from all pages
            text_lines = []
            
            # Get first page
            for block in result.get('Blocks', []):
                if block['BlockType'] == 'LINE':
                    text_lines.append(block['Text'])
            
            # Get additional pages if they exist
            next_token = result.get('NextToken')
            while next_token:
                result = textract_client.get_document_text_detection(
                    JobId=job_id,
                    NextToken=next_token
                )
                
                for block in result.get('Blocks', []):
                    if block['BlockType'] == 'LINE':
                        text_lines.append(block['Text'])
                
                next_token = result.get('NextToken')
            
            return '\n'.join(text_lines)
        
        elif status == 'FAILED':
            error_msg = result.get('StatusMessage', 'Unknown error')
            raise Exception(f"Textract job failed: {error_msg}")
    
    raise Exception(f"Textract job timed out after {max_attempts} attempts")
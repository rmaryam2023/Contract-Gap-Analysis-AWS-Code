import json 

import boto3 

import os 

import time 

from urllib.parse import unquote_plus 

 

s3_client = boto3.client('s3') 

textract_client = boto3.client('textract') 

 

def lambda_handler(event, context): 

   """ 

   Triggered by PDF upload to msa-intake-mr-2026 bucket. 

   Extracts text using Textract ASYNC API (for multi-page PDFs) 

   Saves to processed-output-mr-2026/msa-text/ 

   Then triggers compliance analysis 

   """ 

   

   # Get bucket and key from S3 event 

   bucket = event['Records'][0]['s3']['bucket']['name'] 

   key = unquote_plus(event['Records'][0]['s3']['object']['key']) 

   

   print(f"Processing MSA document: {key} from bucket: {bucket}") 

   

   # Only process PDF files 

   if not key.lower().endswith('.pdf'): 

       print(f"Skipping non-PDF file: {key}") 

       return { 

           'statusCode': 200, 

           'body': json.dumps('Not a PDF file, skipping') 

       } 

   

   try: 

       # Check file size to decide sync vs async 

       s3_response = s3_client.head_object(Bucket=bucket, Key=key) 

       file_size = s3_response['ContentLength'] 

       file_size_mb = file_size / (1024 * 1024) 

       

       print(f"File size: {file_size_mb:.2f} MB") 

       

       # Use synchronous API for small single-page PDFs, async for everything else 

       if file_size_mb < 5: 

           try: 

               # Try synchronous first 

               extracted_text = extract_text_sync(bucket, key) 

           except Exception as sync_error: 

               print(f"Synchronous extraction failed: {str(sync_error)}") 

               print("Falling back to asynchronous extraction...") 

               extracted_text = extract_text_async(bucket, key) 

       else: 

           # Use asynchronous for larger files 

           extracted_text = extract_text_async(bucket, key) 

       

       print(f"Extracted {len(extracted_text)} characters from {key}") 

       

       # Generate output filename 

       base_name = os.path.splitext(os.path.basename(key))[0] 

       output_key = f"msa-text/{base_name}_msa_text.json" 

       

       # Save extracted text to output bucket 

       output_data = { 

           'source_file': key, 

           'source_bucket': bucket, 

           'extracted_text': extracted_text, 

           'file_size_mb': file_size_mb 

       } 

       

       s3_client.put_object( 

           Bucket='processed-output-mr-2026', 

           Key=output_key, 

           Body=json.dumps(output_data, indent=2), 

           ContentType='application/json' 

       ) 

       

       print(f"Saved extracted text to: s3://processed-output-mr-2026/{output_key}") 

       

       # Trigger compliance analysis Lambda 

       lambda_client = boto3.client('lambda') 

       lambda_client.invoke( 

           FunctionName='AnalyzeCompliance', 

           InvocationType='Event', 

           Payload=json.dumps({ 

               'msa_text_key': output_key, 

               'msa_source_file': key 

           }) 

       ) 

       

       print("Triggered compliance analysis") 

       

       return { 

           'statusCode': 200, 

           'body': json.dumps({ 

               'message': 'Text extraction successful', 

               'output_file': output_key, 

               'text_length': len(extracted_text), 

               'extraction_method': 'async' if file_size_mb >= 5 else 'sync' 

           }) 

       } 

       

   except Exception as e: 

       print(f"Error processing {key}: {str(e)}") 

       import traceback 

       traceback.print_exc() 

       raise e 

 

def extract_text_sync(bucket, key): 

   """Extract text using synchronous Textract API (for small, single-page PDFs)""" 

   print("Using synchronous Textract API...") 

   

   response = textract_client.detect_document_text( 

       Document={ 

           'S3Object': { 

               'Bucket': bucket, 

               'Name': key 

           } 

       } 

   ) 

   

   # Extract all text from Textract response 

   extracted_text = "" 

   for block in response['Blocks']: 

       if block['BlockType'] == 'LINE': 

           extracted_text += block['Text'] + "\n" 

   

   return extracted_text 

 

def extract_text_async(bucket, key): 

   """Extract text using asynchronous Textract API (for multi-page or large PDFs)""" 

   print("Using asynchronous Textract API...") 

   

   # Start asynchronous text detection 

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

   

   # Wait for job to complete (with timeout) 

   max_wait_time = 300  # 5 minutes 

   wait_interval = 5    # Check every 5 seconds 

   elapsed_time = 0 

   

   while elapsed_time < max_wait_time: 

       time.sleep(wait_interval) 

       elapsed_time += wait_interval 

       

       result = textract_client.get_document_text_detection(JobId=job_id) 

       status = result['JobStatus'] 

       

       print(f"Job status: {status} (waited {elapsed_time}s)") 

       

       if status == 'SUCCEEDED': 

           # Extract text from all pages 

           extracted_text = "" 

           

           # Get first page of results 

           for block in result['Blocks']: 

               if block['BlockType'] == 'LINE': 

                   extracted_text += block['Text'] + "\n" 

           

           # Get remaining pages if any 

           next_token = result.get('NextToken') 

           while next_token: 

               result = textract_client.get_document_text_detection( 

                   JobId=job_id, 

                   NextToken=next_token 

               ) 

               

               for block in result['Blocks']: 

                   if block['BlockType'] == 'LINE': 

                       extracted_text += block['Text'] + "\n" 

               

               next_token = result.get('NextToken') 

           

           print(f"Successfully extracted text from all pages") 

           return extracted_text 

           

       elif status == 'FAILED': 

           error_msg = f"Textract job failed: {result.get('StatusMessage', 'Unknown error')}" 

           print(error_msg) 

           raise Exception(error_msg) 

   

   # Timeout 

   raise Exception(f"Textract job timed out after {max_wait_time} seconds") 

 

import boto3
import json

s3 = boto3.client('s3')
config = boto3.client('config')

def evaluate_and_remediate(bucket_name):
    compliance_type = "NON_COMPLIANT"
    annotation = ""

    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        flags = response['PublicAccessBlockConfiguration']

        if all(flags.values()):
            compliance_type = "COMPLIANT"
            annotation = "All BPA settings are enabled."
        else:
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            annotation = "BPA was not fully enabled. Remediation applied."

    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        annotation = "BPA was missing. Remediation applied."

    except Exception as e:
        annotation = f"Error: {str(e)}"

    return compliance_type, annotation

def lambda_handler(event, context):
    print("Received event:", json.dumps(event, indent=2))

    # Case 1: Triggered by AWS Config
    if 'invokingEvent' in event:
        invoking_event = json.loads(event['invokingEvent'])
        config_item = invoking_event['configurationItem']
        result_token = event['resultToken']
        bucket_name = config_item['resourceName']

        compliance_type, annotation = evaluate_and_remediate(bucket_name)

        config.put_evaluations(
            Evaluations=[{
                "ComplianceResourceType": config_item["resourceType"],
                "ComplianceResourceId": config_item["resourceId"],
                "ComplianceType": compliance_type,
                "Annotation": annotation,
                "OrderingTimestamp": config_item["configurationItemCaptureTime"]
            }],
            ResultToken=result_token
        )

        return {
            'compliance_type': compliance_type,
            'annotation': annotation
        }

    # Case 2: Triggered by EventBridge
    elif 'detail-type' in event and event['detail-type'] == "Config Rules Compliance Change":
        bucket_name = event['detail']['resourceId']
        compliance_type, annotation = evaluate_and_remediate(bucket_name)

        # 🟢 Force Config to re-evaluate the rule
        config.start_config_rules_evaluation(ConfigRuleNames=['s3bucketBPA'])

        return {
            'triggered_by': 'EventBridge',
            'bucket': bucket_name,
            'compliance_type': compliance_type,
            'annotation': annotation
        }

    else:
        return {
            'error': 'Unsupported event source',
            'event': event
        }

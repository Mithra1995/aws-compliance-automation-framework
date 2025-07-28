import boto3
import json

def lambda_handler(event, context):
    config = boto3.client('config')
    cloudtrail = boto3.client('cloudtrail')

    # Parse the invokingEvent
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event['configurationItem']
    trail_name = configuration_item['resourceId']
    result_token = event['resultToken']

    compliance_type = "NON_COMPLIANT"
    annotation = ""

    try:
        # Get the logging status of the trail
        response = cloudtrail.get_trail_status(Name=trail_name)

        if response.get('IsLogging', False):
            compliance_type = "COMPLIANT"
            annotation = "CloudTrail logging is enabled."
        else:
            annotation = "CloudTrail logging is disabled."

    except Exception as e:
        compliance_type = "NON_COMPLIANT"
        annotation = f"Error checking logging status: {str(e)}"

    # Send the evaluation result back to AWS Config
    config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': configuration_item['resourceType'],
                'ComplianceResourceId': configuration_item['resourceId'],
                'ComplianceType': compliance_type,
                'Annotation': annotation,
                'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
            }
        ],
        ResultToken=result_token
    )

    return {
        'statusCode': 200,
        'body': json.dumps(f"Evaluation complete: {compliance_type}")
    }

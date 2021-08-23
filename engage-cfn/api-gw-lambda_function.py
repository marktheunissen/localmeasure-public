import os, json
from datetime import datetime, timezone
import boto3

TRANSCRIPT_BUCKET = os.environ['TRANSCRIPT_BUCKET']
IDENTITY_POOL_ID = os.environ['IDENTITY_POOL_ID']
TBL_SESSION = os.environ['TBL_SESSION']
ENGAGE_ORIGIN = os.environ['ENGAGE_ORIGIN']
CI_COMMIT_SHORT_SHA = os.environ.get('CI_COMMIT_SHORT_SHA', 'none') # SHA from serverless repo
CFN_VERSION = os.environ.get('CFN_VERSION', 'none') # engage-base/VERSION file, updated manually

connect_to_boto3 = {
    # GET & PUT methods are deprecated. Use POST equivalents below.
    'put:connect/StartTaskContact': 'start_task_contact',
    'get:connect/GetContactAttributes': 'get_contact_attributes',
    'get:connect/ListQueues': 'list_queues',

    'post:connect/StartTaskContact': 'start_task_contact', # https://docs.aws.amazon.com/connect/latest/APIReference/API_StartTaskContact.html
    'post:connect/UpdateContactAttributes': 'update_contact_attributes', # https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdateContactAttributes.html
    'post:connect/GetContactAttributes': 'get_contact_attributes', # https://docs.aws.amazon.com/connect/latest/APIReference/API_GetContactAttributes.html
    'post:connect/SuspendContactRecording': 'suspend_contact_recording', # https://docs.aws.amazon.com/connect/latest/APIReference/API_SuspendContactRecording.html
    'post:connect/ResumeContactRecording': 'resume_contact_recording', # https://docs.aws.amazon.com/connect/latest/APIReference/API_ResumeContactRecording.html
    'post:connect/ListQueues': 'list_queues', # https://docs.aws.amazon.com/connect/latest/APIReference/API_ListQueues.html
    'post:connect/DescribeQueue': 'describe_queue' #https://docs.aws.amazon.com/connect/latest/APIReference/API_DescribeQueue.html
}

customerprofiles_to_boto3 = {
    # PUT method is deprecated. Use POST equivalents below.
    'put:customerprofiles/UpdateProfile': 'update_profile',
    'put:customerprofiles/PutProfileObject': 'put_profile_object',

    'post:customerprofiles/CreateProfile': 'create_profile', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_CreateProfile.html
    'post:customerprofiles/DeleteProfile': 'delete_profile', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_DeleteProfile.html
    'post:customerprofiles/SearchProfiles': 'search_profiles', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_SearchProfiles.html
    'post:customerprofiles/UpdateProfile': 'update_profile', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_UpdateProfile.html
    'post:customerprofiles/ListProfileObjects': 'list_profile_objects', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_ListProfileObjects.html
    'post:customerprofiles/DeleteProfileObject': 'delete_profile_object', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_DeleteProfileObject.html
    'post:customerprofiles/PutProfileObject': 'put_profile_object', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_PutProfileObject.html
    'post:customerprofiles/AddProfileKey': 'add_profile_key', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_AddProfileKey.html
    'post:customerprofiles/DeleteProfileKey': 'delete_profile_key' # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_DeleteProfileKey.html
}

custom = {'get:custom/transcript': 'transcript'}
ddb = boto3.resource('dynamodb')

def lambda_handler(event, context):
    print(event)
    req_method = event['requestContext']['httpMethod']
    origin = event.get('headers', {}).get('origin', '') if ENGAGE_ORIGIN == '*' else ENGAGE_ORIGIN
    origin_headers = {'access-control-allow-origin': origin, 'access-control-allow-credentials': 'true'}
    if req_method == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': {
                **origin_headers,
                'access-control-max-age': 86400,
                'access-control-allow-headers': 'content-type,authorization',
                'access-control-allow-methods': 'GET,POST,PUT,OPTIONS',
            }
        }

    if req_method == 'GET' and event['path'] == '/.well-known/lm-engage-debug':
        return success_response(origin_headers, {'lm-engage-ci-sha': CI_COMMIT_SHORT_SHA, 'lm-engage-cfn-version': CFN_VERSION})

    key = f"{str.lower(req_method)}:{event['path'][1:]}"
    method = connect_to_boto3.get(key)
    payload = event.get('queryStringParameters') if req_method == 'GET' else json.loads(event.get('body'))

    if method != None:
        connect = authed_client('connect', event)
        try:
            res = getattr(connect, method)(**payload)
            return success_response(origin_headers, res)
        except Exception as e:
            print(e)
            return error_response(origin_headers, e)
    method = customerprofiles_to_boto3.get(key)
    if method != None:
        customerprofiles = authed_client('customer-profiles', event)
        try:
            res = getattr(customerprofiles, method)(**payload)
            return success_response(origin_headers, res)
        except Exception as e:
            print(e)
            return error_response(origin_headers, e)
    method = custom.get(key)
    if method == 'transcript':
        s3 = boto3.client('s3')
        try:
            obj = s3.get_object(Bucket=TRANSCRIPT_BUCKET, Key=event['queryStringParameters'].get('Key'))
            return {'statusCode': 200, 'headers': origin_headers, 'body': obj['Body'].read().decode()}
        except Exception as e:
            print(e)
            return error_response(origin_headers, e)
    return {'statusCode': 501, 'headers': origin_headers}

def success_response(headers, response):
    response.pop('ResponseMetadata', None)
    return {'statusCode': 200, 'headers': headers, 'body': json.dumps(response)}

def error_response(headers, err):
    return {'statusCode': 500, 'headers': headers, 'body': json.dumps({'error': str(err)})}


def get_session(event):
    subject = event.get('requestContext', {}).get('authorizer', {}).get('claims', {}).get('sub')
    ci = boto3.client('cognito-identity')
    tbl = ddb.Table(TBL_SESSION)
    try:
        response = tbl.get_item(Key={'Subject': subject})
        item = response.get('Item')
        if item is not None:
            dt = item.get('ExpiredTimestamp')
            if dt is not None and dt > int(datetime.utcnow().timestamp()):
                return item
        tok = event.get('headers', {}).get('Authorization', '')
        tok_prefix = 'Bearer '
        if tok.startswith(tok_prefix):
            tok = tok[len(tok_prefix):]
        iss = event.get('requestContext', {}).get('authorizer', {}).get('claims', {}).get('iss')
        iss_prefix = 'https://'
        if iss.startswith(iss_prefix):
            iss = iss[len(iss_prefix):]
        res = ci.get_id(
            AccountId=event.get('requestContext', {}).get('accountId'),
            IdentityPoolId=IDENTITY_POOL_ID,
            Logins={iss: tok}
        )
        creds_res = ci.get_credentials_for_identity(
            IdentityId=res.get('IdentityId'),
            Logins={iss: tok}
        )
        exp = creds_res['Credentials']['Expiration']
        creds_res['ExpiredTimestamp'] = int(exp.replace(tzinfo=timezone.utc).timestamp())
        creds_res['Credentials']['Expiration'] = exp.isoformat()
        creds_res.pop('ResponseMetadata', None)
        tbl.put_item(Item={'Subject': subject, **creds_res})
        return creds_res
    except Exception as e:
        print(str(e))

def authed_client(service_name, event):
    session = get_session(event)
    return boto3.client(
        service_name,
        aws_access_key_id=session.get('Credentials', {}).get('AccessKeyId'),
        aws_secret_access_key=session.get('Credentials', {}).get('SecretKey'),
        aws_session_token=session.get('Credentials', {}).get('SessionToken'),
    )

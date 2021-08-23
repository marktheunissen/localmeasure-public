import os, json
from datetime import datetime, timezone
import boto3

TRANSCRIPT_BUCKET = os.environ['TRANSCRIPT_BUCKET']
IDENTITY_POOL_ID = os.environ['IDENTITY_POOL_ID']
TBL_SESSION = os.environ['TBL_SESSION']

connect_to_boto3 = {
    'put:connect/StartTaskContact': 'start_task_contact', # https://docs.aws.amazon.com/connect/latest/APIReference/API_StartTaskContact.html
    'post:connect/UpdateContactAttributes': 'update_contact_attributes', # https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdateContactAttributes.html
    'get:connect/GetContactAttributes': 'get_contact_attributes', # https://docs.aws.amazon.com/connect/latest/APIReference/API_GetContactAttributes.html
    'post:connect/SuspendContactRecording': 'suspend_contact_recording', # https://docs.aws.amazon.com/connect/latest/APIReference/API_SuspendContactRecording.html
    'post:connect/ResumeContactRecording': 'resume_contact_recording', # https://docs.aws.amazon.com/connect/latest/APIReference/API_ResumeContactRecording.html
    'get:connect/ListQueues': 'list_queues' # https://docs.aws.amazon.com/connect/latest/APIReference/API_ListQueues.html
}

customerprofiles_to_boto3 = {
    'post:customerprofiles/CreateProfile': 'create_profile', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_CreateProfile.html
    'post:customerprofiles/DeleteProfile': 'delete_profile', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_DeleteProfile.html
    'post:customerprofiles/SearchProfiles': 'search_profiles', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_SearchProfiles.html
    'put:customerprofiles/UpdateProfile': 'update_profile', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_UpdateProfile.html
    'post:customerprofiles/ListProfileObjects': 'list_profile_objects', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_ListProfileObjects.html
    'post:customerprofiles/DeleteProfileObject': 'delete_profile_object', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_DeleteProfileObject.html
    'put:customerprofiles/PutProfileObject': 'put_profile_object', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_PutProfileObject.html
    'post:customerprofiles/AddProfileKey': 'add_profile_key', # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_AddProfileKey.html
    'post:customerprofiles/DeleteProfileKey': 'delete_profile_key' # https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_DeleteProfileKey.html
}

custom = {'get:custom/transcript': 'transcript'}
ddb = boto3.resource('dynamodb')

def lambda_handler(event, context):
    print(event)
    req_method = event['requestContext']['http']['method']
    if req_method == 'OPTIONS':
        return {'statusCode': 200}

    key = f"{str.lower(req_method)}:{event['rawPath'][1:]}"
    method = connect_to_boto3.get(key)
    payload = event.get('queryStringParameters') if req_method == 'GET' else json.loads(event.get('body'))

    if method != None:
        connect = authed_client('connect', event)
        payload = event.get('queryStringParameters') if req_method == 'GET' else json.loads(event.get('body'))
        try:
            res = getattr(connect, method)(**payload)
            return success_response(res)
        except Exception as e:
            print(e)
            return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}
    method = customerprofiles_to_boto3.get(key)
    if method != None:
        customerprofiles = authed_client('customer-profiles', event)
        payload = event.get('queryStringParameters') if req_method == 'GET' else json.loads(event.get('body'))
        try:
            res = getattr(customerprofiles, method)(**payload)
            return success_response(res)
        except Exception as e:
            print(e)
            return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}
    method = custom.get(key)
    if method == 'transcript':
        s3 = authed_client('s3', event)
        try:
            obj = s3.get_object(Bucket=TRANSCRIPT_BUCKET, Key=event['queryStringParameters'].get('Key'))
            return {'statusCode': 200, 'body': obj['Body'].read().decode()}
        except Exception as e:
            print(e)
            return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}
    return {'statusCode': 501}

def success_response(response):
    response.pop('ResponseMetadata', None)
    return {'statusCode': 200, 'body': json.dumps(response)}

def get_session(event):
    subject = event.get('requestContext', {}).get('authorizer', {}).get('jwt', {}).get('claims', {}).get('sub')
    ci = boto3.client('cognito-identity')
    tbl = ddb.Table(TBL_SESSION)
    try:
        response = tbl.get_item(Key={'Subject': subject})
        item = response.get('Item')
        if item is not None:
            dt = item.get('ExpiredTimestamp')
            if dt is not None and dt > int(datetime.utcnow().timestamp()):
                return item
        tok = event.get('headers', {}).get('authorization', '')
        tok_prefix = 'Bearer '
        if tok.startswith(tok_prefix):
            tok = tok[len(tok_prefix):]
        iss = event.get('requestContext', {}).get('authorizer', {}).get('jwt', {}).get('claims', {}).get('iss')
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
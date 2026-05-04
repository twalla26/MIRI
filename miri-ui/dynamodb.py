import boto3
from datetime import datetime
from dotenv import load_dotenv
import os
import logging
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
AWS_PROFILE_NAME= os.getenv("AWS_PROFILE_NAME", "")
AWS_REGION = os.getenv("AWS_REGION", "")
DYNAMODB_TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME", "")

session = boto3.Session(profile_name=AWS_PROFILE_NAME)
dynamodb = session.resource('dynamodb', region_name=AWS_REGION)
table = dynamodb.Table(DYNAMODB_TABLE_NAME)

def put_user_metadata(user_id, account_id, external_id):
    try:
        table.put_item(
            Item={
                'PK': f'USER#{user_id}',
                'SK': 'METADATA',
                'AccountID': account_id,
                'ExternalID': external_id,
                'CreatedAt': datetime.now().isoformat(),
                'Status': 'ACTIVE'
            }
        )

    except ClientError as e:
        logger.error(f"[DB Error] 메타데이터 저장 실패 ({user_id}): {e.response['Error']['Message']}") # type: ignore
    
def get_latest_scan_result(user_id):
    try:
        response = table.query(
            KeyConditionExpression=Key('PK').eq(f'USER#{user_id}') & 
                                    Key('SK').begins_with('SCAN#'),
            ScanIndexForward=False,
            Limit=1
        )

        items = response.get('Items', [])
        return items[0] if items else None 
    except ClientError as e:
        logger.error(f"[DB Error] 최신 스캔 결과 조회 실패 ({user_id}): {e.response['Error']['Message']}") # type: ignore
        return None

def get_scan_result(user_id, scan_id):
    try:
        response = table.get_item(
            Key={'PK': f'USER#{user_id}', 'SK': scan_id}
        )

        return response.get('Item')
    except ClientError as e:
        logger.error(f"[DB Error] 단일 스캔 결과 조회 실패 ({scan_id}): {e.response['Error']['Message']}") # type: ignore
        return None

def get_scan_history(user_id):
    items = []
    try:
        query_kwargs = {
            'KeyConditionExpression': Key('PK').eq(f'USER#{user_id}') & 
                                        Key('SK').begins_with('SCAN#'),
            'ScanIndexForward': False
        }

        # Pagination 처리 로직
        while True:
            response = table.query(**query_kwargs)
            items.extend(response.get('Items', []))

            # LastEvaluatedKey가 존재하면 데이터가 더 있다는 뜻 --> 이어서 쿼리
            if 'LastEvaluatedKey' in response:
                query_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            else:
                break

        return items
    except ClientError as e:
        logger.error(f"[DB Error] 스캔 히스토리 조회 실패 ({user_id}): {e.response['Error']['Message']}") # type: ignore
        return items

    
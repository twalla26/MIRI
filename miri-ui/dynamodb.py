import boto3
from datetime import datetime
from dotenv import load_dotenv
import os
import logging
import hashlib
import base64
import secrets
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

def _hash_password(password: str) -> str:
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return base64.b64encode(salt + key).decode()

def _verify_password(password: str, stored: str) -> bool:
    decoded = base64.b64decode(stored.encode())
    salt, stored_key = decoded[:32], decoded[32:]
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return key == stored_key

def register_user(user_id: str, password: str, account_id: str) -> dict:
    """회원가입. External ID를 자동 생성하여 저장하고 성공 시 반환."""
    external_id = secrets.token_hex(16)
    try:
        table.put_item(
            Item={
                'PK': f'USER#{user_id}',
                'SK': 'METADATA',
                'AccountID': account_id,
                'ExternalID': external_id,
                'PasswordHash': _hash_password(password),
                'CreatedAt': datetime.now().isoformat(),
                'Status': 'ACTIVE'
            },
            ConditionExpression='attribute_not_exists(PK)'
        )
        return {'ok': True, 'external_id': external_id}
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return {'ok': False, 'error': '이미 사용 중인 아이디입니다.'}
        logger.error(f"[DB Error] 회원가입 실패 ({user_id}): {e.response['Error']['Message']}")
        return {'ok': False, 'error': '서버 오류가 발생했습니다.'}

def authenticate_user(user_id: str, password: str) -> dict:
    """로그인. 성공 시 {'ok': True, 'account_id': ...}, 실패 시 {'ok': False, 'error': '...'} 반환."""
    try:
        response = table.get_item(Key={'PK': f'USER#{user_id}', 'SK': 'METADATA'})
        item = response.get('Item')
        if not item:
            return {'ok': False, 'error': '아이디 또는 비밀번호가 올바르지 않습니다.'}
        if not _verify_password(password, item.get('PasswordHash', '')):
            return {'ok': False, 'error': '아이디 또는 비밀번호가 올바르지 않습니다.'}
        return {'ok': True, 'account_id': item.get('AccountID', '')}
    except ClientError as e:
        logger.error(f"[DB Error] 로그인 실패 ({user_id}): {e.response['Error']['Message']}")
        return {'ok': False, 'error': '서버 오류가 발생했습니다.'}

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

def pad_rule_id(rule_id):
    """'2.1.11' 형태의 ID를 '02.01.11' (Zero-Padding) 형태로 변환"""
    return ".".join([part.zfill(2) for part in str(rule_id).split('.')])

def get_guide_data_with_meta(check_id):
    """batch_get_item을 사용하여 METADATA와 특정 RULE 항목을 단일 요청으로 가져오는 함수"""
    try:
        # 1. 포맷 분해 및 패딩 처리
        parts = check_id.split('-')
        if len(parts) >= 4:
            cloud_provider = parts[1]
            version_str = parts[2]
            rule_number = parts[-1]
        else:
            cloud_provider = "AWS"
            version_str = "v7.0.0"
            rule_number = check_id
            
        padded_id = pad_rule_id(rule_number)
        pk_value = f'GUIDE#CIS#{cloud_provider}#{version_str}'
        
        # 2. batch_get_item 요청
        table_name = table.name 
        
        response = dynamodb.batch_get_item(
            RequestItems={
                table_name: {
                    'Keys': [
                        {'PK': pk_value, 'SK': 'METADATA'},
                        {'PK': pk_value, 'SK': f'RULE#{padded_id}'}
                    ]
                }
            }
        )
        
        # 3. 결과 데이터를 가공하여 추출
        items = response.get('Responses', {}).get(table_name, [])
        
        result = {"guide": None, "meta": None}
        for item in items:
            if item.get('SK') == 'METADATA':
                result["meta"] = item
            else:
                result["guide"] = item
                
        return result
        
    except Exception as e:
        print(f"Error fetching guide data with batch_get_item: {e}")
        return None